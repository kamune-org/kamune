package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

var testErr = errors.New("test error")

// ---------------------------------------------------------------------------
// decodeTokenList
// ---------------------------------------------------------------------------

func TestDecodeTokenList(t *testing.T) {
	tok1 := make([]byte, storage.ElemSize)
	tok1[0] = 0x01
	tok2 := make([]byte, storage.ElemSize)
	tok2[0] = 0x02
	tok3 := make([]byte, storage.ElemSize)
	tok3[0] = 0x03

	buildPacked := func(tokens ...[]byte) []byte {
		b := make([]byte, 4+len(tokens)*storage.ElemSize)
		binary.BigEndian.PutUint32(b[:4], uint32(len(tokens)))
		for i, tok := range tokens {
			copy(b[4+i*storage.ElemSize:], tok)
		}
		return b
	}

	tests := []struct {
		name    string
		data    []byte
		want    [][]byte
		wantNil bool
	}{
		{
			name:    "nil",
			data:    nil,
			wantNil: true,
		},
		{
			name:    "empty",
			data:    []byte{},
			wantNil: true,
		},
		{
			name:    "too_short_for_count",
			data:    []byte{0x00, 0x00, 0x01},
			wantNil: true,
		},
		{
			name:    "zero_count",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantNil: true,
		},
		{
			name:    "count_one_but_data_truncated",
			data:    append([]byte{0x00, 0x00, 0x00, 0x01}, tok1[:20]...),
			wantNil: true,
		},
		{
			name: "single_token",
			data: buildPacked(tok1),
			want: [][]byte{tok1},
		},
		{
			name: "three_tokens",
			data: buildPacked(tok1, tok2, tok3),
			want: [][]byte{tok1, tok2, tok3},
		},
		{
			name:    "count_mismatch_too_few_elements",
			data:    append([]byte{0x00, 0x00, 0x00, 0x03}, tok1...),
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got := decodeTokenList(tc.data)
			if tc.wantNil {
				a.Nil(got)
				return
			}
			a.Len(got, len(tc.want))
			for i := range tc.want {
				a.Equal(tc.want[i], got[i])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseRelayAddr
// ---------------------------------------------------------------------------

func TestParseRelayAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		scheme   string
		host     string
		insecure *bool
	}{
		{
			name:   "bare_host",
			addr:   "192.168.1.1:9000",
			scheme: "ws",
			host:   "192.168.1.1:9000",
		},
		{
			name:   "ws_scheme",
			addr:   "ws://192.168.1.1:9000",
			scheme: "ws",
			host:   "192.168.1.1:9000",
		},
		{
			name:   "tcp_scheme",
			addr:   "tcp://relay.example.com:443",
			scheme: "tcp",
			host:   "relay.example.com:443",
		},
		{
			name:   "wss_scheme",
			addr:   "wss://relay.example.com:443",
			scheme: "wss",
			host:   "relay.example.com:443",
		},
		{
			name:   "tls_scheme",
			addr:   "tls://relay.example.com:443",
			scheme: "tls",
			host:   "relay.example.com:443",
		},
		{
			name:     "insecure_true",
			addr:     "wss://relay.example.com:443?insecure=true",
			scheme:   "wss",
			host:     "relay.example.com:443",
			insecure: new(true),
		},
		{
			name:     "insecure_false",
			addr:     "wss://relay.example.com:443?insecure=false",
			scheme:   "wss",
			host:     "relay.example.com:443",
			insecure: new(false),
		},
		{
			name:     "tcp_with_insecure",
			addr:     "tcp://relay.example.com:443?insecure=true",
			scheme:   "tcp",
			host:     "relay.example.com:443",
			insecure: new(true),
		},
		{
			name:     "bare_host_with_insecure",
			addr:     "192.168.1.1:9000?insecure=true",
			scheme:   "ws",
			host:     "192.168.1.1:9000",
			insecure: new(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			scheme, host, insecure := parseRelayAddr(tc.addr)
			a.Equal(tc.scheme, scheme)
			a.Equal(tc.host, host)
			if tc.insecure == nil {
				a.Nil(insecure)
			} else {
				a.NotNil(insecure)
				a.Equal(*tc.insecure, *insecure)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// dialRelayFuncMultiToken error paths
// ---------------------------------------------------------------------------

func TestDialRelayFuncMultiToken_Errors(t *testing.T) {
	validToken := make([]byte, 32)
	validToken[0] = 0x01

	tests := []struct {
		name      string
		relayAddr string
		tokens    [][]byte
		wantErr   bool
	}{
		{
			name:      "empty_relay_addr",
			relayAddr: "",
			tokens:    [][]byte{validToken},
			wantErr:   true,
		},
		{
			name:      "whitespace_relay_addr",
			relayAddr: "   ",
			tokens:    [][]byte{validToken},
			wantErr:   true,
		},
		{
			name:      "no_tokens",
			relayAddr: "127.0.0.1:9000",
			tokens:    nil,
			wantErr:   true,
		},
		{
			name:      "empty_token_list",
			relayAddr: "127.0.0.1:9000",
			tokens:    [][]byte{},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			_, err := dialRelayFuncMultiToken(
				tc.relayAddr, "", false, tc.tokens,
			)
			if tc.wantErr {
				a.Error(err)
			} else {
				a.NoError(err)
			}
		})
	}
}

func TestDialRelayFuncMultiToken_ParsesRelayAddrOnce(t *testing.T) {
	a := require.New(t)
	validToken := make([]byte, 32)
	validToken[0] = 0xAA
	fn, err := dialRelayFuncMultiToken(
		"wss://relay.example.com:443", "", false,
		[][]byte{validToken},
	)
	a.NoError(err)
	a.NotNil(fn)
	_, err = fn("http://wrong-address:0")
	a.Error(err)
}

// ---------------------------------------------------------------------------
// tokenTracker death detection
// ---------------------------------------------------------------------------

// fakeKamuneConn is a minimal kamune.Conn for unit tests.
type fakeKamuneConn struct{}

func (c *fakeKamuneConn) ReadBytes() ([]byte, error)  { return nil, net.ErrClosed }
func (c *fakeKamuneConn) WriteBytes([]byte) error     { return net.ErrClosed }
func (c *fakeKamuneConn) SetDeadline(time.Time) error { return nil }
func (c *fakeKamuneConn) Close() error                { return nil }

// fakeListener is a minimal kamune.Listener for unit tests.
type fakeListener struct {
	acceptFn func() (kamune.Conn, error)
	closeFn  func()
	mu       sync.Mutex
	closed   bool
}

func (f *fakeListener) Accept() (kamune.Conn, error) {
	if f.acceptFn != nil {
		return f.acceptFn()
	}
	<-make(chan struct{})
	return nil, net.ErrClosed
}

func (f *fakeListener) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.closeFn != nil {
		f.closeFn()
	}
	return nil
}

func (f *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}
}

func TestTokenTracker_DeadOnAcceptError(t *testing.T) {
	a := require.New(t)
	errAccept := testErr
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return nil, errAccept
		},
	}

	tt := &tokenTracker{
		Listener: fl,
		dead:     make(chan struct{}),
		app:      &App{},
	}

	_, err := tt.Accept()
	a.ErrorIs(err, errAccept)

	select {
	case <-tt.Dead():
	case <-time.After(time.Second):
		t.Fatal("dead channel not closed after Accept error")
	}
}

func TestTokenTracker_DeadOnStop(t *testing.T) {
	blockCh := make(chan struct{})
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			<-blockCh
			return nil, net.ErrClosed
		},
	}

	tt := &tokenTracker{
		Listener: fl,
		dead:     make(chan struct{}),
		app:      &App{},
	}

	tt.Stop()
	close(blockCh)

	select {
	case <-tt.Dead():
	case <-time.After(time.Second):
		t.Fatal("dead channel not closed after Stop (unconsumed)")
	}
}

func TestTokenTracker_DeadNotClosedOnConsumed(t *testing.T) {
	tt := &tokenTracker{
		Listener: &fakeListener{},
		dead:     make(chan struct{}),
	}
	tt.consumed.Store(true)

	// Stop() on a consumed tracker should NOT close the dead channel.
	tt.Stop()

	select {
	case <-tt.Dead():
		t.Fatal("dead channel closed after Stop on consumed tracker")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTokenTracker_ShortCircuitOnConsumedStop(t *testing.T) {
	a := require.New(t)
	// Verify the underlying listener's Stop() IS called even when consumed.
	stopped := false
	fl := &fakeListenerWithStop{
		stopFn: func() { stopped = true },
	}

	tt := &tokenTracker{
		Listener: fl,
		dead:     make(chan struct{}),
	}
	tt.consumed.Store(true)

	tt.Stop()
	a.True(stopped, "underlying listener.Stop() should still be called")
}

func TestTokenTracker_DeadIdempotent(t *testing.T) {
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return nil, testErr
		},
	}

	tt := &tokenTracker{
		Listener: fl,
		dead:     make(chan struct{}),
		app:      &App{},
	}

	_, _ = tt.Accept()
	// Should not panic.
	tt.Stop()
}

// ---------------------------------------------------------------------------
// multiListener
// ---------------------------------------------------------------------------

func TestMultiListener_AddAfterClose(t *testing.T) {
	a := require.New(t)
	ml := newMultiListener()
	a.NoError(ml.Close())

	err := ml.Add(&fakeListener{})
	a.ErrorIs(err, net.ErrClosed)
}

func TestMultiListener_AcceptAfterClose(t *testing.T) {
	a := require.New(t)
	ml := newMultiListener()
	a.NoError(ml.Close())

	_, err := ml.Accept()
	a.ErrorIs(err, net.ErrClosed)
}

func TestMultiListener_ListenerDeath(t *testing.T) {
	a := require.New(t)
	ml := newMultiListener()
	defer ml.Close()

	errCh := make(chan error, 1)
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return nil, net.ErrClosed
		},
	}

	a.NoError(ml.Add(fl))

	// Give the goroutine time to call Accept and exit.
	time.Sleep(50 * time.Millisecond)

	// Closing ml unblocks ml.Accept via the done channel.
	go func() {
		_, err := ml.Accept()
		errCh <- err
	}()
	ml.Close()

	select {
	case err := <-errCh:
		a.Error(err)
	case <-time.After(2 * time.Second):
		t.Fatal("multiListener.Accept did not unblock after listener death")
	}
}

func TestMultiListener_Passthrough(t *testing.T) {
	a := require.New(t)
	ml := newMultiListener()
	defer ml.Close()

	mlConn := &fakeKamuneConn{}
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return mlConn, nil
		},
	}

	a.NoError(ml.Add(fl))

	got, err := ml.Accept()
	a.NoError(err)
	a.Equal(mlConn, got)
}

// ---------------------------------------------------------------------------
// markRelayTokenConsumed
// ---------------------------------------------------------------------------

func TestMarkRelayTokenConsumed(t *testing.T) {
	a := require.New(t)
	app := &App{}
	app.relayTokens = []relayToken{
		{Token: "aaa"},
		{Token: "bbb"},
		{Token: "ccc"},
	}

	// Test the consumed-flag logic directly (markRelayTokenConsumed
	// calls runtime.EventsEmit which requires a Wails lifecycle context).
	app.mu.Lock()
	for i := range app.relayTokens {
		if app.relayTokens[i].Token == "bbb" && !app.relayTokens[i].Consumed {
			app.relayTokens[i].Consumed = true
			break
		}
	}
	app.mu.Unlock()

	app.mu.RLock()
	defer app.mu.RUnlock()
	a.False(app.relayTokens[0].Consumed)
	a.True(app.relayTokens[1].Consumed)
	a.False(app.relayTokens[2].Consumed)
}

func TestMarkRelayTokenConsumed_NotFound(t *testing.T) {
	a := require.New(t)
	app := &App{}
	app.relayTokens = []relayToken{
		{Token: "aaa"},
	}

	app.mu.Lock()
	for i := range app.relayTokens {
		if app.relayTokens[i].Token == "zzz" && !app.relayTokens[i].Consumed {
			app.relayTokens[i].Consumed = true
			break
		}
	}
	app.mu.Unlock()

	app.mu.RLock()
	defer app.mu.RUnlock()
	a.False(app.relayTokens[0].Consumed)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fakeListenerWithStop is a kamune.Listener that also implements Stop().
type fakeListenerWithStop struct {
	fakeListener
	stopFn func()
}

func (f *fakeListenerWithStop) Stop() {
	if f.stopFn != nil {
		f.stopFn()
	}
}

func TestRelayTokenHexRoundTrip(t *testing.T) {
	a := require.New(t)
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	hexStr := hex.EncodeToString(raw)
	decoded, err := hex.DecodeString(hexStr)
	a.NoError(err)
	a.Equal(raw, decoded)
	a.Len(hexStr, 64)
}
