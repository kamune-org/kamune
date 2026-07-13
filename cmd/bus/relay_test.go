package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

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
			name:    "single_token",
			data:    buildPacked(tok1),
			want:    [][]byte{tok1},
		},
		{
			name:    "three_tokens",
			data:    buildPacked(tok1, tok2, tok3),
			want:    [][]byte{tok1, tok2, tok3},
		},
		{
			name:    "count_mismatch_too_few_elements",
			data:    append([]byte{0x00, 0x00, 0x00, 0x03}, tok1...),
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeTokenList(tc.data)
			if tc.wantNil {
				assert.Nil(t, got)
				return
			}
			require.Len(t, got, len(tc.want))
			for i := range tc.want {
				assert.Equal(t, tc.want[i], got[i])
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
			insecure: boolPtr(true),
		},
		{
			name:     "insecure_false",
			addr:     "wss://relay.example.com:443?insecure=false",
			scheme:   "wss",
			host:     "relay.example.com:443",
			insecure: boolPtr(false),
		},
		{
			name:     "tcp_with_insecure",
			addr:     "tcp://relay.example.com:443?insecure=true",
			scheme:   "tcp",
			host:     "relay.example.com:443",
			insecure: boolPtr(true),
		},
		{
			name:     "bare_host_with_insecure",
			addr:     "192.168.1.1:9000?insecure=true",
			scheme:   "ws",
			host:     "192.168.1.1:9000",
			insecure: boolPtr(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme, host, insecure := parseRelayAddr(tc.addr)
			assert.Equal(t, tc.scheme, scheme)
			assert.Equal(t, tc.host, host)
			if tc.insecure == nil {
				assert.Nil(t, insecure)
			} else {
				require.NotNil(t, insecure)
				assert.Equal(t, *tc.insecure, *insecure)
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
			_, err := dialRelayFuncMultiToken(
				tc.relayAddr, "", false, tc.tokens,
			)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDialRelayFuncMultiToken_ParsesRelayAddrOnce(t *testing.T) {
	validToken := make([]byte, 32)
	validToken[0] = 0xAA
	fn, err := dialRelayFuncMultiToken(
		"wss://relay.example.com:443", "", false,
		[][]byte{validToken},
	)
	require.NoError(t, err)
	require.NotNil(t, fn)
	_, err = fn("http://wrong-address:0")
	assert.Error(t, err)
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
	errAccept := assert.AnError
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
	assert.ErrorIs(t, err, errAccept)

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
		consumed: true,
	}

	// Stop() on a consumed tracker should NOT close the dead channel.
	tt.Stop()

	select {
	case <-tt.Dead():
		t.Fatal("dead channel closed after Stop on consumed tracker")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTokenTracker_ShortCircuitOnConsumedStop(t *testing.T) {
	// Verify the underlying listener's Stop() IS called even when consumed.
	stopped := false
	fl := &fakeListenerWithStop{
		stopFn: func() { stopped = true },
	}

	tt := &tokenTracker{
		Listener: fl,
		dead:     make(chan struct{}),
		consumed: true,
	}

	tt.Stop()
	assert.True(t, stopped, "underlying listener.Stop() should still be called")
}

func TestTokenTracker_DeadIdempotent(t *testing.T) {
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return nil, assert.AnError
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
	ml := newMultiListener()
	require.NoError(t, ml.Close())

	err := ml.Add(&fakeListener{})
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestMultiListener_AcceptAfterClose(t *testing.T) {
	ml := newMultiListener()
	require.NoError(t, ml.Close())

	_, err := ml.Accept()
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestMultiListener_ListenerDeath(t *testing.T) {
	ml := newMultiListener()
	defer ml.Close()

	errCh := make(chan error, 1)
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return nil, net.ErrClosed
		},
	}

	require.NoError(t, ml.Add(fl))

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
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("multiListener.Accept did not unblock after listener death")
	}
}

func TestMultiListener_Passthrough(t *testing.T) {
	ml := newMultiListener()
	defer ml.Close()

	mlConn := &fakeKamuneConn{}
	fl := &fakeListener{
		acceptFn: func() (kamune.Conn, error) {
			return mlConn, nil
		},
	}

	require.NoError(t, ml.Add(fl))

	got, err := ml.Accept()
	require.NoError(t, err)
	assert.Equal(t, mlConn, got)
}

// ---------------------------------------------------------------------------
// markRelayTokenConsumed
// ---------------------------------------------------------------------------

func TestMarkRelayTokenConsumed(t *testing.T) {
	a := &App{}
	a.relayTokens = []relayToken{
		{Token: "aaa"},
		{Token: "bbb"},
		{Token: "ccc"},
	}

	// Test the consumed-flag logic directly (markRelayTokenConsumed
	// calls runtime.EventsEmit which requires a Wails lifecycle context).
	a.mu.Lock()
	for i := range a.relayTokens {
		if a.relayTokens[i].Token == "bbb" && !a.relayTokens[i].Consumed {
			a.relayTokens[i].Consumed = true
			break
		}
	}
	a.mu.Unlock()

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.False(t, a.relayTokens[0].Consumed)
	assert.True(t, a.relayTokens[1].Consumed)
	assert.False(t, a.relayTokens[2].Consumed)
}

func TestMarkRelayTokenConsumed_NotFound(t *testing.T) {
	a := &App{}
	a.relayTokens = []relayToken{
		{Token: "aaa"},
	}

	a.mu.Lock()
	for i := range a.relayTokens {
		if a.relayTokens[i].Token == "zzz" && !a.relayTokens[i].Consumed {
			a.relayTokens[i].Consumed = true
			break
		}
	}
	a.mu.Unlock()

	a.mu.RLock()
	defer a.mu.RUnlock()
	assert.False(t, a.relayTokens[0].Consumed)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

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
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	hexStr := hex.EncodeToString(raw)
	decoded, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	assert.Equal(t, raw, decoded)
	assert.Len(t, hexStr, 64)
}
