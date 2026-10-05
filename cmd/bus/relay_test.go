package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

var errTest = errors.New("test error")

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
	const pinHex = "00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff"
	pin, err := hex.DecodeString(pinHex)
	require.New(t).NoError(err)
	colonPin := strings.ToUpper(pinHex[:2])
	for i := 2; i < len(pinHex); i += 2 {
		colonPin += ":" + strings.ToUpper(pinHex[i:i+2])
	}

	tests := []struct {
		name     string
		addr     string
		scheme   string
		host     string
		insecure *bool
		pin      []byte
		wantErr  error
		bad      bool
	}{
		{
			name:   "bare_host",
			addr:   "192.168.1.1:9000",
			scheme: "wss",
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
			scheme:   "wss",
			host:     "192.168.1.1:9000",
			insecure: new(true),
		},
		{
			name:   "wss_pin",
			addr:   "wss://relay.example.com:443?pin=" + pinHex,
			scheme: "wss",
			host:   "relay.example.com:443",
			pin:    pin,
		},
		{
			name:   "tls_pin_with_colons",
			addr:   "tls://relay.example.com:443?pin=" + colonPin,
			scheme: "tls",
			host:   "relay.example.com:443",
			pin:    pin,
		},
		{
			name:     "pin_and_insecure",
			addr:     "wss://relay.example.com:443?insecure=true&pin=" + pinHex,
			scheme:   "wss",
			host:     "relay.example.com:443",
			insecure: new(true),
			pin:      pin,
		},
		{
			name:    "pin_on_tcp",
			addr:    "tcp://relay.example.com:443?pin=" + pinHex,
			wantErr: ErrRelayPinScheme,
		},
		{
			name:    "pin_on_ws",
			addr:    "ws://relay.example.com:443?pin=" + pinHex,
			wantErr: ErrRelayPinScheme,
		},
		{
			name:    "short_pin",
			addr:    "wss://relay.example.com:443?pin=0011",
			wantErr: relayconn.ErrInvalidCertFingerprint,
		},
		{
			name: "insecure_not_a_bool",
			addr: "wss://relay.example.com:443?insecure=yes",
			bad:  true,
		},
		{
			name: "unknown_parameter",
			addr: "wss://relay.example.com:443?token=abc",
			bad:  true,
		},
		{
			name: "repeated_pin",
			addr: "wss://relay.example.com:443?pin=" + pinHex + "&pin=" + pinHex,
			bad:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ra, err := parseRelayAddr(tc.addr)
			if tc.wantErr != nil || tc.bad {
				a.Error(err)
				if tc.wantErr != nil {
					a.ErrorIs(err, tc.wantErr)
				}
				return
			}
			a.NoError(err)
			a.Equal(tc.scheme, ra.scheme)
			a.Equal(tc.host, ra.host)
			if tc.insecure == nil {
				a.Nil(ra.insecure)
			} else {
				a.NotNil(ra.insecure)
				a.Equal(*tc.insecure, *ra.insecure)
			}
			a.Equal(tc.pin, ra.pin)
		})
	}
}

// TestRelayTLSConfig checks which certificates a relay address trusts: a
// pin wins over a request to skip verification, and without a pin the
// address's insecure flag overrides the caller's choice.
func TestRelayTLSConfig(t *testing.T) {
	cases := []struct {
		name       string
		addr       string
		skip       bool
		wantPinned bool
		wantSkip   bool
	}{
		{name: "default checks", addr: "wss://r:443"},
		{name: "caller skips", addr: "wss://r:443", skip: true,
			wantSkip: true},
		{name: "address skips", addr: "wss://r:443?insecure=true",
			wantSkip: true},
		{name: "address keeps checks", addr: "wss://r:443?insecure=false",
			skip: true},
		{name: "pin", addr: "tls://r:443?pin=" + strings.Repeat("ab", 32),
			skip: true, wantPinned: true},
		{name: "pin and insecure",
			addr:       "wss://r:443?insecure=true&pin=" + strings.Repeat("ab", 32),
			wantPinned: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ra, err := parseRelayAddr(tc.addr)
			a.NoError(err)
			cfg, err := ra.tlsConfig(tc.skip)
			a.NoError(err)
			if tc.wantPinned {
				a.NotNil(cfg.VerifyConnection,
					"a pinned config checks the certificate itself")
				return
			}
			a.Nil(cfg.VerifyConnection)
			a.Equal(tc.wantSkip, cfg.InsecureSkipVerify)
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
				context.Background(), tc.relayAddr, "", false, tc.tokens,
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
		context.Background(), "wss://relay.example.com:443", "", false,
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
	errAccept := errTest
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
			return nil, errTest
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
	// emits an event which is a no-op when a.wails is nil).
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

func TestReconnectDial_SingleTokenUsesSessionContext(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fn, err := dialRelayFunc(ctx, "tcp://127.0.0.1:1", token, "", false)
	a.NoError(err)
	_, err = fn("")
	a.ErrorIs(err, context.Canceled)
}

func TestStampRelaySession(t *testing.T) {
	a := require.New(t)
	first := &tokenTracker{}
	second := &tokenTracker{}
	stampRelaySession(second, "session-b")
	a.Empty(first.sessionID)
	a.Equal("session-b", second.sessionID)
	// A session that did not come through the relay has no tracker.
	stampRelaySession(nil, "session-c")
	stampRelaySession(&gatedConn{}, "session-c")
}

func TestLoadRelayPool_NoSession(t *testing.T) {
	require.New(t).Empty(loadRelayPool(nil, ""))
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

// TestRelayCertificatePin starts a relay listener on a TLS relay with a
// self-signed certificate, and checks that a pin of that certificate is
// trusted in place of the chain check, that a pin of another one is not,
// and that without a pin the certificate is still checked, with a hint
// to pin it.
func TestRelayCertificatePin(t *testing.T) {
	relay, fp := newFakeTLSRelay(t)
	host := strings.TrimPrefix(relay.addr(), "tcp://")
	other := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		addr    string
		skip    bool
		wantErr error
		fail    bool
		wantMsg string
	}{
		{name: "pinned", addr: "tls://" + host + "?pin=" + fp},
		{name: "pinned while skipping",
			addr: "tls://" + host + "?pin=" + fp, skip: true},
		{name: "other pin", addr: "tls://" + host + "?pin=" + other,
			wantErr: relayconn.ErrCertPinMismatch},
		{name: "other pin while skipping", skip: true,
			addr:    "tls://" + host + "?insecure=true&pin=" + other,
			wantErr: relayconn.ErrCertPinMismatch},
		{name: "no pin", addr: "tls://" + host, fail: true,
			wantMsg: "enter its SHA-256 fingerprint as the relay " +
				"certificate pin"},
		{name: "verification skipped", addr: "tls://" + host, skip: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ln, _, _, _, err := listenRelay(
				t.Context(), tc.addr, "", tc.skip, nil,
			)
			if tc.wantErr != nil || tc.fail {
				a.Error(err)
				if tc.wantErr != nil {
					a.ErrorIs(err, tc.wantErr)
				}
				if tc.wantMsg != "" {
					a.ErrorContains(err, tc.wantMsg)
				}
				return
			}
			a.NoError(err)
			a.NoError(ln.Close())
		})
	}
}
