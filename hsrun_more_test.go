package kamune

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/hpke"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/engine"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

func acceptVerify(n *int, mu *sync.Mutex) verifyFunc {
	return func(context.Context, *storage.Storage, VerifyRequest) error {
		if mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}
		if n != nil {
			*n++
		}
		return nil
	}
}

func coldPair(
	t *testing.T, store *storage.Storage, clk clock.Clock,
) (*Transport, *Transport, *attest.Attest, *attest.Attest) {
	t.Helper()
	a := require.New(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", clock: clk,
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob",
		resumeEnabled: true, clock: clk,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	return gi.tr, gr.tr, ia, ra
}

func resumeBoth(
	t *testing.T,
	store *storage.Storage,
	ia, ra *attest.Attest,
	sid string,
	clk clock.Clock,
	iExtra func(*initiatorInput),
	rExtra func(*responderInput),
	iConn, rConn Conn,
) (hsResult, hsResult) {
	t.Helper()
	if iConn == nil || rConn == nil {
		iConn, rConn = pipeConns(t)
	}
	in := initiatorInput{
		attest: ia, store: store, name: "ada", clock: clk,
		resumeSID: sid, verify: acceptVerify(nil, nil),
	}
	rn := responderInput{
		attest: ra, store: store, name: "bob",
		resumeEnabled: true, clock: clk,
		verify: acceptVerify(nil, nil),
	}
	if iExtra != nil {
		iExtra(&in)
	}
	if rExtra != nil {
		rExtra(&rn)
	}
	iCh := startInitiator(iConn, in)
	rCh := startResponder(rConn, rn)
	return <-iCh, <-rCh
}

type wireConn struct {
	Conn
	mu        sync.Mutex
	wrote     [][]byte
	dropRead  int
	failWrite int
}

func (w *wireConn) WriteBytes(p []byte) error {
	w.mu.Lock()
	w.wrote = append(w.wrote, bytes.Clone(p))
	fail := w.failWrite != 0 && len(p) == w.failWrite
	w.mu.Unlock()
	if fail {
		return io.ErrClosedPipe
	}
	return w.Conn.WriteBytes(p)
}

func (w *wireConn) ReadBytes() ([]byte, error) {
	b, err := w.Conn.ReadBytes()
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	drop := w.dropRead != 0 && len(b) == w.dropRead
	w.mu.Unlock()
	if drop {
		return nil, io.EOF
	}
	return b, nil
}

func (w *wireConn) lengths() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, len(w.wrote))
	for i, p := range w.wrote {
		out[i] = len(p)
	}
	return out
}

func (w *wireConn) frames() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.wrote))
	copy(out, w.wrote)
	return out
}

type failCommand struct {
	engine.Store
	mu     sync.Mutex
	armed  bool
	n      int
	at     int
	err    error
	qArmed bool
	qN     int
	qAt    int
	qErr   error
}

func (f *failCommand) Command(fn func(engine.Namespace) error) error {
	f.mu.Lock()
	fire := false
	if f.armed {
		f.n++
		if f.n == f.at {
			fire = true
			f.armed = false
		}
	}
	want := f.err
	f.mu.Unlock()
	if fire {
		return want
	}
	return f.Store.Command(fn)
}

func (f *failCommand) arm(at int, err error) {
	f.mu.Lock()
	f.armed = true
	f.n = 0
	f.at = at
	f.err = err
	f.mu.Unlock()
}

func (f *failCommand) Query(fn func(engine.Namespace) error) error {
	f.mu.Lock()
	fire := false
	if f.qArmed {
		f.qN++
		if f.qN == f.qAt {
			fire = true
			f.qArmed = false
		}
	}
	want := f.qErr
	f.mu.Unlock()
	if fire {
		return want
	}
	return f.Store.Query(fn)
}

func (f *failCommand) failQueryAt(at int, err error) {
	f.mu.Lock()
	f.qArmed = true
	f.qN = 0
	f.qAt = at
	f.qErr = err
	f.mu.Unlock()
}

type noteConn struct {
	Conn
	once  sync.Once
	wrote chan struct{}
}

func (n *noteConn) WriteBytes(p []byte) error {
	n.once.Do(func() { close(n.wrote) })
	return n.Conn.WriteBytes(p)
}

type errConn struct{}

func (errConn) ReadBytes() ([]byte, error) { return nil, io.EOF }
func (errConn) WriteBytes([]byte) error    { return io.ErrClosedPipe }
func (errConn) Close() error               { return nil }
func (errConn) SetDeadline(time.Time) error {
	return nil
}

type deadlineConn struct {
	Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (d *deadlineConn) SetDeadline(at time.Time) error {
	d.mu.Lock()
	d.deadlines = append(d.deadlines, at)
	d.mu.Unlock()
	return d.Conn.SetDeadline(at)
}

func openFailStore(t *testing.T) (*storage.Storage, *failCommand) {
	t.Helper()
	a := require.New(t)
	db, err := engine.NewBoltDB(
		filepath.Join(t.TempDir(), "db"), []byte(""),
	)
	a.NoError(err)
	wrap := &failCommand{Store: db}
	s, err := storage.OpenStorage(
		storage.WithBackend(wrap), storage.WithNoPassphrase(),
	)
	a.NoError(err)
	t.Cleanup(func() { _ = s.Close() })
	return s, wrap
}

func TestHandshake_PinnedDialer(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	var pinned bool
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		pin: ra.MarshalPublicKey(),
		verify: func(
			_ context.Context, _ *storage.Storage, req VerifyRequest,
		) error {
			pinned = req.Pinned
			return nil
		},
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(pinned)
	a.False(gi.tr.Resumed())
}

func TestResume_Success(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	clk := clock.NewFake(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	it, rt, ia, ra := coldPair(t, store, clk)
	sid := it.SessionID()
	a.Equal(sid, rt.SessionID())
	coldI, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	coldR, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	clk.Advance(time.Hour)
	var iReq, rReq VerifyRequest
	gi, gr := resumeBoth(t, store, ia, ra, sid, clk,
		func(in *initiatorInput) {
			in.verify = func(
				_ context.Context, _ *storage.Storage, req VerifyRequest,
			) error {
				iReq = req
				return nil
			}
		},
		func(in *responderInput) {
			in.verify = func(
				_ context.Context, _ *storage.Storage, req VerifyRequest,
			) error {
				rReq = req
				return nil
			}
		}, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.True(gr.tr.Resumed())
	a.Equal(sid, gi.tr.SessionID())
	a.Equal(sid, gr.tr.SessionID())
	a.True(iReq.ResumeOffered)
	a.True(rReq.Resumed)
	nextI, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	nextR, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	a.Equal(coldI.Generation+1, nextI.Generation)
	a.Equal(coldR.Generation+1, nextR.Generation)
	a.True(nextI.RefreshedAt.After(coldI.RefreshedAt))
	a.Equal(coldI.ColdAt, nextI.ColdAt)
	a.Equal(coldR.ColdAt, nextR.ColdAt)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
}

func TestResume_Chain(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	for i := 0; i < 5; i++ {
		gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
		a.NoError(gi.err)
		a.NoError(gr.err)
		a.True(gi.tr.Resumed())
		a.Equal(sid, gi.tr.SessionID())
		a.NoError(gi.tr.CloseAbort())
		a.NoError(gr.tr.CloseAbort())
	}
	row, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(uint64(6), row.Generation)
}

func TestResume_AfterLongSession(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	clk := clock.NewFake(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	it, rt, ia, ra := coldPair(t, store, clk)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	clk.Advance(30 * time.Hour)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	gi, gr := resumeBoth(t, store, ia, ra, sid, clk, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.True(gr.tr.Resumed())
	a.Equal(sid, gi.tr.SessionID())
}

func TestResumeOnly_Success(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil,
		func(in *initiatorInput) { in.resumeOnly = true },
		nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.True(gr.tr.Resumed())
}

func TestExporter(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, _, _ := coldPair(t, store, nil)
	label := "kamune/relay-reconnect"
	left, err := it.ExportKeyingMaterial(label, []byte("ctx"), 32)
	a.NoError(err)
	right, err := rt.ExportKeyingMaterial(label, []byte("ctx"), 32)
	a.NoError(err)
	a.Equal(left, right)
	other, err := it.ExportKeyingMaterial(label+"x", []byte("ctx"), 32)
	a.NoError(err)
	a.NotEqual(left, other)
	ctx2, err := it.ExportKeyingMaterial(label, []byte("other"), 32)
	a.NoError(err)
	a.NotEqual(left, ctx2)
	nilCtx, err := it.ExportKeyingMaterial(label, nil, 32)
	a.NoError(err)
	empty, err := it.ExportKeyingMaterial(label, []byte{}, 32)
	a.NoError(err)
	a.Equal(nilCtx, empty)
	_, err = it.ExportKeyingMaterial("", nil, 32)
	a.ErrorIs(err, ErrInvalidExport)
	_, err = it.ExportKeyingMaterial(repeat(201), nil, 32)
	a.ErrorIs(err, ErrInvalidExport)
	_, err = it.ExportKeyingMaterial(label, nil, 0)
	a.ErrorIs(err, ErrInvalidExport)
	_, err = it.ExportKeyingMaterial(label, nil, 16321)
	a.ErrorIs(err, ErrInvalidExport)
	a.NoError(rt.CloseAbort())
	a.NoError(it.Close())
	_, err = it.ExportKeyingMaterial(label, nil, 32)
	a.ErrorIs(err, ErrConnClosed)

	t.Run("race", func(t *testing.T) {
		a := require.New(t)
		store := openStore(t)
		it, rt, _, _ := coldPair(t, store, nil)
		defer rt.CloseAbort()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = it.ExportKeyingMaterial(label, nil, 32)
		}()
		go func() {
			defer wg.Done()
			_ = it.Close()
		}()
		wg.Wait()
		_, err := it.ExportKeyingMaterial(label, nil, 32)
		a.ErrorIs(err, ErrConnClosed)
	})
}

func repeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestResume_RejectUniform(t *testing.T) {
	cases := []string{
		"unknown", "wrong key", "bad binder", "idle", "max age",
		"disabled", "no persistence", "initiator row only",
	}
	var sizes []int
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			store := openStore(t)
			clk := clock.NewFake(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC))
			it, rt, ia, ra := coldPair(t, store, clk)
			sid := it.SessionID()
			remember(t, store, ia)
			remember(t, store, ra)
			a.NoError(it.CloseAbort())
			a.NoError(rt.CloseAbort())
			switch name {
			case "unknown":
				sid = "ABCDEFGHIJKLMNOPQRSTUVWX"
				row, err := store.GetResumption(
					it.SessionID(), storage.ResumeRoleInitiator,
				)
				a.NoError(err)
				row.Role = storage.ResumeRoleInitiator
				a.NoError(store.SwapResumption(sid, 0, row))
			case "wrong key":
				row, err := store.GetResumption(
					sid, storage.ResumeRoleResponder,
				)
				a.NoError(err)
				other := hsIdent(t).MarshalPublicKey()
				a.NoError(store.SwapResumption(sid, row.Generation, &storage.Resumption{
					Generation: row.Generation, Current: row.Current,
					Previous: row.Previous, PeerKey: other,
					ColdAt: row.ColdAt, RefreshedAt: row.RefreshedAt,
					Role: storage.ResumeRoleResponder,
				}))
			case "bad binder":
				row, err := store.GetResumption(
					sid, storage.ResumeRoleResponder,
				)
				a.NoError(err)
				bad := bytes.Repeat([]byte{9}, 64)
				a.NoError(store.SwapResumption(sid, row.Generation, &storage.Resumption{
					Generation: row.Generation, Current: bad,
					PeerKey: row.PeerKey, ColdAt: row.ColdAt,
					RefreshedAt: row.RefreshedAt,
					Role:        storage.ResumeRoleResponder,
				}))
			case "idle":
				clk.Advance(defaultResumeIdle + time.Second)
			case "max age":
				clk.Advance(defaultResumeMaxAge + time.Second)
			case "initiator row only":
				row, err := store.GetResumption(
					sid, storage.ResumeRoleResponder,
				)
				a.NoError(err)
				a.NoError(store.DeleteResumption(
					sid, storage.ResumeRoleResponder, row.Generation,
				))
			}
			iw, rw := &wireConn{}, &wireConn{}
			li, lr := pipeConns(t)
			iw.Conn, rw.Conn = li, lr
			gi, gr := resumeBoth(t, store, ia, ra, sid, clk,
				nil,
				func(in *responderInput) {
					switch name {
					case "disabled":
						in.resumeEnabled = false
					case "no persistence":
						in.noPersistence = true
					}
				}, iw, rw)
			a.NoError(gi.err)
			a.NoError(gr.err)
			a.False(gi.tr.Resumed())
			a.NotEqual(sid, gi.tr.SessionID())
			got := append(iw.lengths(), rw.lengths()...)
			if sizes == nil {
				sizes = got
			}
			a.Equal([]int{
				clientHelloSize, initiatorAuthSize,
				serverHelloSize, responderAuthSize, confirmFrameSize,
			}, append(iw.lengths(), rw.lengths()...))
			_ = sizes
			a.NoError(gi.tr.CloseAbort())
			a.NoError(gr.tr.CloseAbort())
		})
	}
}

func TestResume_DeletedPeerFallsBackToCold(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(store.DeletePeer(ia.MarshalPublicKey()))
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.False(gi.tr.Resumed())
	a.NotEqual(sid, gi.tr.SessionID())
}

func TestResume_ExpiredPeerFallsBackToCold(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	store := openStore(t, storage.WithClock(clk), storage.WithExpiryDuration(time.Hour))
	it, rt, ia, ra := coldPair(t, store, clk)
	sid := it.SessionID()
	a.NoError(store.StorePeer(&storage.Peer{
		PublicKey: ra.MarshalPublicKey(), Name: "bob",
		AppVersion: "0.8.0",
		FirstSeen:  clk.Now().Add(3 * time.Hour), LastSeen: clk.Now(),
	}))
	a.NoError(store.StorePeer(&storage.Peer{
		PublicKey: ia.MarshalPublicKey(), Name: "ada",
		AppVersion: "0.8.0", FirstSeen: clk.Now(), LastSeen: clk.Now(),
	}))
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	clk.Advance(2 * time.Hour)
	gi, gr := resumeBoth(t, store, ia, ra, sid, clk, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.False(gi.tr.Resumed())
}

func TestResume_DialerDeletedPeer(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ra)
	a.NoError(store.DeletePeer(ra.MarshalPublicKey()))
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	ic, rc := pipeConns(t)
	gi := <-startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	_ = rc
	a.ErrorIs(gi.err, ErrNoResumptionState)
	_, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.ErrorIs(err, storage.ErrNoResumption)
}

func TestResume_LostConfirm(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	before, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	li, lr := pipeConns(t)
	iw := &wireConn{Conn: li, dropRead: confirmFrameSize}
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, iw, lr)
	a.Error(gi.err)
	a.NoError(gr.err)
	a.True(gr.tr.Resumed())
	kept, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(before.Generation, kept.Generation)
	server, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	a.Equal(before.Generation+1, server.Generation)
	a.NoError(gr.tr.CloseAbort())

	gi, gr = resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.Equal(sid, gi.tr.SessionID())
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())

	gi, gr = resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
}

func TestResume_LostConfirmTwice(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	for i := 0; i < 2; i++ {
		li, lr := pipeConns(t)
		iw := &wireConn{Conn: li, dropRead: confirmFrameSize}
		gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, iw, lr)
		a.Error(gi.err)
		a.NoError(gr.err)
		a.NoError(gr.tr.CloseAbort())
	}
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.Equal(sid, gi.tr.SessionID())
}

func TestResume_CrashAfterCommit(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	li, lr := pipeConns(t)
	rw := &wireConn{Conn: lr, failWrite: confirmFrameSize}
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, li, rw)
	a.Error(gi.err)
	a.Error(gr.err)
	gi, gr = resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
	a.Equal(sid, gi.tr.SessionID())
}

func TestResume_CommitFails(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	wrap.arm(1, errors.New("disk"))
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.False(gr.tr.Resumed())
	sid := gi.tr.SessionID()
	_, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.ErrorIs(err, storage.ErrNoResumption)
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	gi, gr = resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.False(gi.tr.Resumed())
	a.NotEqual(sid, gi.tr.SessionID())
}

func TestResume_InitiatorCASConflict(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	wrap.arm(2, storage.ErrResumptionConflict)
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	_, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.ErrorIs(err, storage.ErrNoResumption)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	ic, rc := pipeConns(t)
	miss := <-startInitiator(ic, initiatorInput{
		attest: ia, store: store, resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	_ = rc
	a.ErrorIs(miss.err, ErrNoResumptionState)
	coldI, coldR := pipeConns(t)
	okIC := startInitiator(coldI, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	okRC := startResponder(coldR, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	okI, okR := <-okIC, <-okRC
	a.NoError(okI.err)
	a.NoError(okR.err)
	a.False(okI.tr.Resumed())
}

func TestResume_ResponderCASConflict(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	wrap.arm(1, storage.ErrResumptionConflict)
	ia, ra := hsIdent(t), hsIdent(t)
	li, lr := pipeConns(t)
	rw := &wireConn{Conn: lr}
	iCh := startInitiator(li, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rw, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.Error(gi.err)
	a.ErrorIs(gr.err, storage.ErrResumptionConflict)
	for _, n := range rw.lengths() {
		a.NotEqual(confirmFrameSize, n)
	}
}

func TestResume_ConcurrentDialsLocked(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	entered := make(chan struct{})
	release := make(chan struct{})
	li, lr := pipeConns(t)
	iCh := startInitiator(li, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			close(entered)
			<-release
			return nil
		},
	})
	rCh := startResponder(lr, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	<-entered
	li2, lr2 := pipeConns(t)
	w2 := &wireConn{Conn: li2}
	second := <-startInitiator(w2, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	_ = lr2
	a.ErrorIs(second.err, ErrResumeInProgress)
	a.Empty(w2.lengths())
	close(release)
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	gi, gr = resumeBoth(t, store, ia, ra, sid, nil, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.True(gi.tr.Resumed())
}

func TestResume_VerifierRejects(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil,
		func(in *responderInput) {
			in.verify = func(
				context.Context, *storage.Storage, VerifyRequest,
			) error {
				return errors.New("no")
			}
		}, nil, nil)
	a.ErrorIs(gi.err, ErrHandshakeRejected)
	a.ErrorIs(gr.err, ErrVerificationFailed)
	_, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.ErrorIs(err, storage.ErrNoResumption)
	_, err = store.GetResumption(sid, storage.ResumeRoleResponder)
	a.ErrorIs(err, storage.ErrNoResumption)
}

func TestResume_Window(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	clk := clock.NewFake(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	it, rt, ia, ra := coldPair(t, store, clk)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	clk.Advance(defaultResumeIdle + time.Second)
	gi, gr := resumeBoth(t, store, ia, ra, sid, clk, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.False(gi.tr.Resumed())
	a.NotEqual(sid, gi.tr.SessionID())
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())

	it, rt, ia, ra = coldPair(t, store, clk)
	sid = it.SessionID()
	coldAt := clk.Now()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	for {
		clk.Advance(defaultResumeIdle - time.Hour)
		if clk.Now().Sub(coldAt) > defaultResumeMaxAge {
			break
		}
		gi, gr = resumeBoth(t, store, ia, ra, sid, clk, nil, nil, nil, nil)
		a.NoError(gi.err)
		a.True(gi.tr.Resumed())
		a.NoError(gi.tr.CloseAbort())
		a.NoError(gr.tr.CloseAbort())
	}
	gi, gr = resumeBoth(t, store, ia, ra, sid, clk, nil, nil, nil, nil)
	a.NoError(gi.err)
	a.False(gi.tr.Resumed())
}

func TestResumeOnly_Refused(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	before, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil,
		func(in *initiatorInput) { in.resumeOnly = true },
		func(in *responderInput) { in.resumeEnabled = false },
		nil, nil)
	a.ErrorIs(gi.err, ErrResumeRefused)
	a.NoError(gr.err)
	a.False(gr.tr.Resumed())
	kept, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(before.Generation, kept.Generation)
	a.Equal(before.Current, kept.Current)
}

func TestHandshake_VersionReject(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", version: "0.8.0",
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", version: "0.9.0",
		resumeEnabled: true, verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.ErrorIs(gi.err, ErrHandshakeRejected)
	a.ErrorIs(gi.err, ErrVersionMismatch)
	a.ErrorIs(gr.err, ErrVersionMismatch)
}

func TestHandshake_SelfConnection(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	id := hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: id, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: id, store: store, name: "ada", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.ErrorIs(gi.err, ErrSelfConnection)
	a.Error(gr.err)
	a.NotErrorIs(gr.err, ErrSelfConnection)
}

func TestTerminateZerosExporter(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, _, _ := coldPair(t, store, nil)
	t.Cleanup(func() { _ = it.CloseAbort() })
	held := rt.exporter
	a.NotEmpty(held)
	err := rt.terminate(ErrConnClosed, true)
	a.ErrorIs(err, ErrConnClosed)
	a.Nil(rt.exporter)
	for _, b := range held {
		a.Zero(b)
	}
	_, err = rt.ExportKeyingMaterial("kamune/relay-reconnect", nil, 32)
	a.ErrorIs(err, ErrConnClosed)
}

func TestResumeLock_DropsIdleEntry(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	unlock, ok := tryResumeLock(store, "sid")
	a.True(ok)
	_, busy := tryResumeLock(store, "sid")
	a.False(busy)
	other, ok := tryResumeLock(store, "other")
	a.True(ok)
	other()
	unlock()
	again, ok := tryResumeLock(store, "sid")
	a.True(ok)
	again()
	resumeMu.Lock()
	defer resumeMu.Unlock()
	a.Empty(resumeHolds)
}

func TestResumeLock_NoDoubleHold(t *testing.T) {
	store := openStore(t)
	var held atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 40 {
				unlock, ok := tryResumeLock(store, "sid")
				if !ok {
					continue
				}
				if held.Add(1) != 1 {
					t.Errorf("two resumes held the lock")
				}
				held.Add(-1)
				unlock()
			}
		}()
	}
	wg.Wait()
}

func TestPostVerifyDeadlineUsesConfiguredTimeout(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	dc := &deadlineConn{Conn: ic}
	limit := time.Second
	iCh := startInitiator(dc, initiatorInput{
		attest: ia, store: store, name: "ada",
		verifyTimeout: limit, verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verifyTimeout: limit, verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	dc.mu.Lock()
	got := append([]time.Time(nil), dc.deadlines...)
	dc.mu.Unlock()
	a.GreaterOrEqual(len(got), 2)
	a.True(got[len(got)-1].IsZero())
	remain := time.Until(got[len(got)-2])
	want := defaultHandshakeTimeout + limit
	a.InDelta(float64(want), float64(remain), float64(3*time.Second))
}

func TestHandshakeIOIncludesContext(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readHS(ctx, errConn{})
	a.ErrorIs(err, context.Canceled)
	a.ErrorIs(err, io.EOF)
	err = writeHS(ctx, errConn{}, []byte{1})
	a.ErrorIs(err, context.Canceled)
	a.ErrorIs(err, io.ErrClosedPipe)

	_, err = readHS(context.Background(), errConn{})
	a.NotErrorIs(err, context.Canceled)
	a.ErrorIs(err, io.EOF)
}

func TestLoadOffer_PeerLookupErrorKeepsRow(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, _, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	disk := errors.New("disk")
	wrap.failQueryAt(2, disk)
	_, err := loadOffer(initiatorInput{store: store, resumeSID: sid})
	a.ErrorIs(err, disk)
	a.NotErrorIs(err, ErrNoResumptionState)
	_, err = store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
}

func TestDecideResume_ReadErrorContinuesCold(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, ia, _ := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	disk := errors.New("disk")
	wrap.failQueryAt(1, disk)
	d, err := decideResume(responderInput{
		store: store, resumeEnabled: true,
	}, sid, nil, ia.MarshalPublicKey(), nil)
	a.NoError(err)
	a.False(d.resumed)
	_, err = store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
}

func TestDecideResume_PeerLookupError(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, ia, _ := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	disk := errors.New("disk")
	wrap.failQueryAt(2, disk)
	d, err := decideResume(responderInput{
		store: store, resumeEnabled: true,
	}, sid, nil, ia.MarshalPublicKey(), nil)
	a.ErrorIs(err, disk)
	a.False(d.resumed)
	_, err = store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
}

func TestResume_ResponderReadErrorContinuesCold(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	ic, rc := pipeConns(t)
	wrote := make(chan struct{})
	iCh := startInitiator(&noteConn{Conn: ic, wrote: wrote}, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	select {
	case <-wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("initiator did not write")
	}
	wrap.failQueryAt(1, errors.New("disk"))
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.False(gi.tr.Resumed())
	a.False(gr.tr.Resumed())
}

func TestResume_ResponderPeerLookupKeepsOffer(t *testing.T) {
	a := require.New(t)
	store, wrap := openFailStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	before, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	ic, rc := pipeConns(t)
	wrote := make(chan struct{})
	disk := errors.New("disk")
	iCh := startInitiator(&noteConn{Conn: ic, wrote: wrote}, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	select {
	case <-wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("initiator did not write")
	}
	wrap.failQueryAt(2, disk)
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.Error(gi.err)
	a.ErrorIs(gr.err, disk)
	kept, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(before.Generation, kept.Generation)
	a.Equal(before.Current, kept.Current)
}

func TestConfirm_BadMACBeforeStatus(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	th, hs := driveToConfirm(t, rc, ra)
	sendScriptConfirm(
		t, rc, &th, hs, confirmResumed, 0, "bob", AppVersion, true,
	)
	gi := <-iCh
	a.ErrorIs(gi.err, ErrVerificationFailed)
	a.NotErrorIs(gi.err, ErrInvalidHandshake)
}

func TestConfirm_ResumedWithoutOfferAfterMAC(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	th, hs := driveToConfirm(t, rc, ra)
	sendScriptConfirm(
		t, rc, &th, hs, confirmResumed, 0, "bob", AppVersion, false,
	)
	gi := <-iCh
	a.ErrorIs(gi.err, ErrInvalidHandshake)
	a.NotErrorIs(gi.err, ErrVerificationFailed)
}

func TestConfirm_BadNameAfterMAC(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	th, hs := driveToConfirm(t, rc, ra)
	sendScriptConfirm(
		t, rc, &th, hs, confirmCold, 0, "ada\n", AppVersion, false,
	)
	gi := <-iCh
	a.ErrorIs(gi.err, ErrInvalidPeerName)
	a.NotErrorIs(gi.err, ErrInvalidHandshake)
}

func TestConfirm_ResumeOnlyChecksVersionFirst(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	ic, rc := pipeConns(t)
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		resumeOnly: true, verify: acceptVerify(nil, nil),
	})
	th, hs := driveToConfirm(t, rc, ra)
	sendScriptConfirm(
		t, rc, &th, hs, confirmCold, 0, "bob", "9.0.0", false,
	)
	gi := <-iCh
	a.ErrorIs(gi.err, ErrVersionMismatch)
	a.NotErrorIs(gi.err, ErrResumeRefused)
	_, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
}

func driveToConfirm(
	t *testing.T, cn Conn, at *attest.Attest,
) (transcript, hsKeys) {
	t.Helper()
	a := require.New(t)
	ch, err := cn.ReadBytes()
	a.NoError(err)
	_, _, pk, err := parseClientHello(ch)
	a.NoError(err)
	var th transcript
	th.add(0x01, ch)
	pub, err := hpke.MLKEM768X25519().NewPublicKey(pk)
	a.NoError(err)
	enc, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	a.NoError(err)
	ss, err := sender.Export(kexExport, hashLen)
	a.NoError(err)
	nonce, _, err := randomHello()
	a.NoError(err)
	sh, err := writeServerHello(nil, nonce, enc)
	a.NoError(err)
	th.add(0x02, sh)
	hs, err := scheduleHS(ss, th.sum())
	a.NoError(err)
	local := at.MarshalPublicKey()
	th.add(0x10, local)
	sigR, err := at.Sign(
		signedTH(attest.ContextResponderHandshake, th.sum()),
	)
	a.NoError(err)
	th.add(0x11, sigR)
	finR := macSHA512(hs.rFin, th.sum())
	th.add(0x12, finR)
	ra, err := encodeResponderAuth(local, sigR, finR)
	a.NoError(err)
	sealed, err := sealHS(hs.rKey, ra, protocolVersion, frameResponderAuth)
	a.NoError(err)
	a.NoError(cn.WriteBytes(sh))
	a.NoError(cn.WriteBytes(sealed))

	ia, err := cn.ReadBytes()
	a.NoError(err)
	plain, err := openHS(hs.iKey, ia, frameInitiatorAuth)
	a.NoError(err)
	id, binder, sigI, finI, err := parseInitiatorAuth(plain)
	a.NoError(err)
	block, err := encodeIdentity(id)
	a.NoError(err)
	th.add(0x20, block)
	if len(binder) > 0 {
		th.add(0x21, binder)
	}
	ok := attest.Verify(
		id.Key,
		signedTH(attest.ContextInitiatorHandshake, th.sum()),
		sigI,
	)
	a.True(ok)
	th.add(0x22, sigI)
	a.True(hmac.Equal(finI, macSHA512(hs.iFin, th.sum())))
	th.add(0x23, finI)
	return th, hs
}

func sendScriptConfirm(
	t *testing.T, cn Conn, th *transcript, hs hsKeys,
	status, reason byte, name, version string, badMAC bool,
) {
	t.Helper()
	a := require.New(t)
	body, err := encodeConfirmBody(status, reason, name, version)
	a.NoError(err)
	th.add(0x30, body)
	master, err := masterSecret(hs.hs, pskOrZero(nil))
	a.NoError(err)
	cKey, err := confirmKey(master)
	a.NoError(err)
	fin := macSHA512(cKey, th.sum())
	if badMAC {
		fin[0] ^= 0xff
	}
	plain := make([]byte, confirmPlain)
	n := copy(plain, body)
	copy(plain[n:], fin)
	sealed, err := sealHS(hs.rKey, plain, protocolVersion, frameConfirm)
	a.NoError(err)
	a.NoError(cn.WriteBytes(sealed))
}

func TestResume_ServerCancelKeepsRows(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())

	ic, rc := pipeConns(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", resumeSID: sid,
		verify: acceptVerify(nil, nil),
	})
	rCh := make(chan hsResult, 1)
	go func() {
		tr, err := runResponder(ctx, rc, responderInput{
			attest: ra, store: store, name: "bob",
			resumeEnabled: true,
			verify: func(
				vctx context.Context, _ *storage.Storage, req VerifyRequest,
			) error {
				if req.Resumed {
					close(entered)
				}
				<-vctx.Done()
				return vctx.Err()
			},
		})
		rCh <- hsResult{tr, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("responder verifier did not run")
	}
	cancel()
	gi := <-iCh
	gr := <-rCh
	a.False(errors.Is(gi.err, ErrHandshakeRejected))
	a.ErrorIs(gr.err, ErrClosedServer)
	_, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	a.NoError(err)
	_, err = store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
}

