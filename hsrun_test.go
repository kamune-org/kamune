package kamune

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

func openStore(t *testing.T, opts ...storage.StorageOption) *storage.Storage {
	t.Helper()
	a := require.New(t)
	all := []storage.StorageOption{
		storage.WithDBPath(filepath.Join(t.TempDir(), "db")),
		storage.WithNoPassphrase(),
	}
	all = append(all, opts...)
	s, err := storage.OpenStorage(all...)
	a.NoError(err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func hsIdent(t *testing.T) *attest.Attest {
	t.Helper()
	at, err := attest.New()
	require.New(t).NoError(err)
	return at
}

func pipeConns(t *testing.T) (Conn, Conn) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return NewConn(left), NewConn(right)
}

func remember(t *testing.T, s *storage.Storage, at *attest.Attest) {
	t.Helper()
	a := require.New(t)
	now := time.Now()
	if s != nil {
		a.NoError(s.StorePeer(&storage.Peer{
			PublicKey: at.MarshalPublicKey(), Name: "peer",
			AppVersion: "0.8.0", FirstSeen: now, LastSeen: now,
		}))
	}
}

type hsResult struct {
	tr  *Transport
	err error
}

func startInitiator(cn Conn, in initiatorInput) <-chan hsResult {
	ch := make(chan hsResult, 1)
	go func() {
		tr, err := runInitiator(context.Background(), cn, in)
		ch <- hsResult{tr, err}
	}()
	return ch
}

func startResponder(cn Conn, in responderInput) <-chan hsResult {
	ch := make(chan hsResult, 1)
	go func() {
		tr, err := runResponder(context.Background(), cn, nil, in)
		ch <- hsResult{tr, err}
	}()
	return ch
}

func TestHandshake_Cold(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	var iReq, rReq VerifyRequest
	var once sync.Mutex
	iSeen, rSeen := 0, 0
	icCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: func(
			_ context.Context, _ *storage.Storage, req VerifyRequest,
		) error {
			once.Lock()
			iSeen++
			iReq = req
			once.Unlock()
			return nil
		},
	})
	rcCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: func(
			_ context.Context, _ *storage.Storage, req VerifyRequest,
		) error {
			once.Lock()
			rSeen++
			rReq = req
			once.Unlock()
			return nil
		},
	})
	gotI := <-icCh
	gotR := <-rcCh
	a.NoError(gotI.err)
	a.NoError(gotR.err)
	a.Equal(gotI.tr.SessionID(), gotR.tr.SessionID())
	a.False(gotI.tr.Resumed())
	a.False(gotR.tr.Resumed())
	a.Equal(1, iSeen)
	a.Equal(1, rSeen)
	a.Equal(RoleInitiator, iReq.Role)
	a.Equal(RoleResponder, rReq.Role)
	a.Empty(iReq.Peer.Name)
	a.Equal("bob", gotI.tr.RemotePeer().Name)
	a.Equal("ada", gotR.tr.RemotePeer().Name)
	a.Equal("0.8.0", gotI.tr.RemotePeer().AppVersion)
	a.False(iReq.Pinned)
	a.False(rReq.Pinned)
}
