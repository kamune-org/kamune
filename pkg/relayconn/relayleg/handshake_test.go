package relayleg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/stretchr/testify/require"
)

const pipeLimit = 4096

const roundTripRecords = 1000

func TestHPKESizes(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	enc, ssS, err := sealStatic(key.PublicKey())
	a.NoError(err)
	a.Len(enc, 32)
	a.Len(ssS, 32)
	opened, err := openStatic(key, enc)
	a.NoError(err)
	a.Equal(ssS, opened)

	eph, ephPK, err := newEphemeral()
	a.NoError(err)
	a.Len(ephPK, 1216)
	encE, ssE, err := sealEphemeral(ephPK)
	a.NoError(err)
	a.Len(encE, 1120)
	a.Len(ssE, 32)
	gotE, err := openEphemeral(eph, encE)
	a.NoError(err)
	a.Equal(ssE, gotE)

	a.Equal(encSLen, len(enc))
	a.Equal(ephPKLen, len(ephPK))
	a.Equal(encELen, len(encE))
	a.Equal(1289, sizeClientHello)
	a.Equal(1156, sizeServerHello)
	a.Equal(MaxHandshakeFrame, sizeClientHello)
	a.Equal(Version, 2)
}

func TestExtractSharedNotRelaySecret(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	st, err := prepareClient(ClientConfig{RelayKey: key.PublicKey()})
	a.NoError(err)
	encS := st.ch[encSOffset : encSOffset+encSLen]
	ss, err := openStatic(key, encS)
	a.NoError(err)
	broker, err := key.ExtractShared("kamune broker v2 dh ", encS)
	a.NoError(err)
	a.NotEqual(ss, broker)
	a.NotEqual(ss, broker[:len(ss)])
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		psk   bool
		fetch bool
	}{
		{name: "no psk", psk: false, fetch: false},
		{name: "fetch key", psk: false, fetch: true},
		{name: "psk", psk: true, fetch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			key, err := GenerateKey()
			a.NoError(err)
			var psk *PSK
			if tt.psk {
				p, err := GeneratePSK()
				a.NoError(err)
				psk = &p
			}
			clientKey := key.PublicKey()
			if tt.fetch {
				clientKey = PublicKey{}
			}
			cch, sch, _, _, cErr, sErr := dial(
				t, key, psk, psk, clientKey, tt.fetch,
			)
			a.NoError(cErr)
			a.NoError(sErr)
			a.NotNil(cch)
			a.NotNil(sch)
			a.Equal(pipeLimit-recordOverhead, cch.MaxFrameSize())
			a.Equal(cch.MaxFrameSize(), sch.MaxFrameSize())
			exchangeRecords(t, cch, sch, roundTripRecords)
			honorLimit(t, cch, sch)
		})
	}
}

func TestSeededRoundTrip(t *testing.T) {
	a := require.New(t)
	oneCH, oneSH := seededHello(t, 42)
	twoCH, twoSH := seededHello(t, 42)
	a.Equal(oneCH, twoCH)
	a.Equal(oneSH, twoSH)
	threeCH, _ := seededHello(t, 99)
	a.NotEqual(oneCH, threeCH)
}

func seededHello(t *testing.T, seed uint64) (ch, sh []byte) {
	t.Helper()
	a := require.New(t)
	cryptotest.SetGlobalRandom(t, seed)
	key, err := GenerateKey()
	a.NoError(err)
	rawC, rawS := framePair(t)
	ctap := &tap{framedConn: rawC}
	stap := &tap{framedConn: rawS}
	errc := make(chan error, 1)
	go func() {
		_, err := Accept(stap, ServerConfig{Key: key})
		errc <- err
	}()
	_, err = Initiate(ctap, ClientConfig{RelayKey: key.PublicKey()})
	a.NoError(err)
	a.NoError(<-errc)
	a.Len(ctap.writes, 1)
	a.Len(stap.writes, 1)
	return ctap.writes[0], stap.writes[0]
}

func TestSilentDelay(t *testing.T) {
	a := require.New(t)
	seen := map[time.Duration]struct{}{}
	for range 20 {
		d := SilentDelay()
		if d < 2*time.Second || d > 8*time.Second {
			t.Fatalf("delay %s outside [2s, 8s]", d)
		}
		seen[d] = struct{}{}
	}
	a.Greater(len(seen), 1)
}

func TestReadErrorMapping(t *testing.T) {
	key, err := GenerateKey()
	require.New(t).NoError(err)
	pk := key.PublicKey()
	tests := []struct {
		name string
		err  error
		want error
		not  error
	}{
		{name: "eof", err: io.EOF, want: ErrHandshakeRejected},
		{
			name: "unexpected eof",
			err:  io.ErrUnexpectedEOF,
			want: ErrHandshakeRejected,
		},
		{
			name: "closed pipe",
			err:  io.ErrClosedPipe,
			want: ErrHandshakeRejected,
		},
		{
			name: "net closed",
			err:  net.ErrClosed,
			want: ErrHandshakeRejected,
		},
		{
			name: "deadline",
			err:  os.ErrDeadlineExceeded,
			want: os.ErrDeadlineExceeded,
			not:  ErrHandshakeRejected,
		},
		{
			name: "timeout",
			err:  timeoutError{},
			want: timeoutError{},
			not:  ErrHandshakeRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			rw := &scriptRW{readErr: tt.err}
			_, err := FetchKey(rw)
			a.ErrorIs(err, tt.want)
			if tt.not != nil {
				a.NotErrorIs(err, tt.not)
			}
			assertNoRecord(t, rw.writes)
			rw = &scriptRW{readErr: tt.err}
			_, err = Initiate(rw, ClientConfig{RelayKey: pk})
			// Initiate writes ClientHello before the read, unless
			// the read error is what we asked to inject. The key
			// is valid, so the write happens and the read fails.
			a.ErrorIs(err, tt.want)
			if tt.not != nil {
				a.NotErrorIs(err, tt.not)
			}
			a.Len(rw.writes, 1)
			assertNoRecord(t, rw.writes)
		})
	}
}

func TestReadDeadline(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	rawC, rawS := framePair(t)
	go func() {
		_, _ = rawS.ReadBytes()
	}()
	a.NoError(rawC.SetReadDeadline(time.Now().Add(time.Millisecond)))
	_, err = Initiate(rawC, ClientConfig{RelayKey: key.PublicKey()})
	a.Error(err)
	a.ErrorIs(err, os.ErrDeadlineExceeded)
	a.NotErrorIs(err, ErrHandshakeRejected)
}

func TestLowOrderRelayKey(t *testing.T) {
	var low PublicKey
	raw, err := hex.DecodeString(
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	)
	require.New(t).NoError(err)
	copy(low[:], raw)
	keys := []PublicKey{{}, low}
	for _, pk := range keys {
		rw := &scriptRW{}
		_, err := Initiate(rw, ClientConfig{RelayKey: pk})
		a := require.New(t)
		a.ErrorIs(err, ErrInvalidRelayKey)
		a.Empty(rw.writes)
	}
}

func TestWrongKeyEqualHint(t *testing.T) {
	a := require.New(t)
	relay, err := GenerateKey()
	a.NoError(err)
	other, err := GenerateKey()
	a.NoError(err)
	prev := clientKeyHint
	t.Cleanup(func() { clientKeyHint = prev })
	want := KeyHint(relay.PublicKey())
	clientKeyHint = func(PublicKey) [4]byte { return want }

	_, sch, cw, sw, cErr, sErr := dial(
		t, relay, nil, nil, other.PublicKey(), false,
	)
	a.ErrorIs(cErr, ErrRelayAuthFailed)
	a.NoError(sErr)
	a.NotNil(sch)
	a.Len(cw, 1)
	assertNoRecord(t, cw)
	assertNoRecord(t, sw)
}

func TestHintMismatch(t *testing.T) {
	a := require.New(t)
	relay, err := GenerateKey()
	a.NoError(err)
	other, err := GenerateKey()
	a.NoError(err)
	_, _, cw, sw, cErr, sErr := dial(
		t, relay, nil, nil, other.PublicKey(), false,
	)
	a.ErrorIs(cErr, ErrRelayKeyNotHeld)
	a.ErrorIs(sErr, ErrRelayKeyNotHeld)
	a.Len(cw, 1)
	assertNoRecord(t, cw)
	a.Len(sw, 1)
	a.Equal(alertUnknownKey, sw[0][headerLen])
}

func TestPSKCases(t *testing.T) {
	a := require.New(t)
	relay, err := GenerateKey()
	a.NoError(err)
	pk := relay.PublicKey()
	psk, err := GeneratePSK()
	a.NoError(err)
	otherPSK, err := GeneratePSK()
	a.NoError(err)
	other, err := GenerateKey()
	a.NoError(err)

	t.Run("client psk relay none", func(t *testing.T) {
		a := require.New(t)
		_, _, cw, sw, cErr, sErr := dial(
			t, relay, nil, &psk, pk, false,
		)
		a.ErrorIs(cErr, ErrPSKUnexpected)
		a.ErrorIs(sErr, ErrPSKUnexpected)
		a.Len(cw, 1)
		assertNoRecord(t, cw)
		a.Equal(alertPSKUnexpected, sw[0][headerLen])
	})

	t.Run("relay psk client none", func(t *testing.T) {
		a := require.New(t)
		_, _, cw, sw, cErr, sErr := dial(
			t, relay, &psk, nil, pk, false,
		)
		a.ErrorIs(sErr, ErrSilentReject)
		a.Empty(sw)
		a.ErrorIs(cErr, ErrHandshakeRejected)
		a.NotErrorIs(cErr, ErrRelayAuthFailed)
		a.Len(cw, 1)
		assertNoRecord(t, cw)
	})

	t.Run("different psk", func(t *testing.T) {
		a := require.New(t)
		_, _, cw, sw, cErr, sErr := dial(
			t, relay, &psk, &otherPSK, pk, false,
		)
		a.ErrorIs(sErr, ErrSilentReject)
		a.Empty(sw)
		a.ErrorIs(cErr, ErrHandshakeRejected)
		a.NotErrorIs(cErr, ErrRelayAuthFailed)
		assertNoRecord(t, cw)
	})

	t.Run("right psk wrong key", func(t *testing.T) {
		a := require.New(t)
		_, _, cw, sw, cErr, sErr := dial(
			t, relay, &psk, &psk, other.PublicKey(), false,
		)
		clientOK := errors.Is(cErr, ErrRelayKeyNotHeld) ||
			errors.Is(cErr, ErrRelayAuthFailed)
		a.True(clientOK, "client error %v", cErr)
		a.NotErrorIs(cErr, ErrHandshakeRejected)
		a.NotErrorIs(sErr, ErrSilentReject)
		a.NotEmpty(sw)
		assertNoRecord(t, cw)
		assertNoRecord(t, sw)
	})
	_ = a
}

func TestServerHelloBitFlips(t *testing.T) {
	a := require.New(t)
	st, sh := captureFlight(t, nil)
	rw := &scriptRW{}
	ch, err := st.finish(rw, sh)
	a.NoError(err)
	a.NotNil(ch)
	for i := encEOffset; i < len(sh); i++ {
		for bit := 0; bit < 8; bit++ {
			mut := bytes.Clone(sh)
			mut[i] ^= 1 << bit
			got, err := st.finish(rw, mut)
			a.Nil(got)
			a.Error(err)
		}
	}
}

func TestBinderBitFlips(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	psk, err := GeneratePSK()
	a.NoError(err)
	st, err := prepareClient(ClientConfig{
		RelayKey: key.PublicKey(),
		PSK:      &psk,
	})
	a.NoError(err)
	cfg := ServerConfig{Key: key, PSK: &psk}
	for i := 0; i < binderLen; i++ {
		for bit := 0; bit < 8; bit++ {
			mut := bytes.Clone(st.ch)
			mut[binderOffset+i] ^= 1 << bit
			rw := &scriptRW{reads: [][]byte{mut}}
			_, err := Accept(rw, cfg)
			a.ErrorIs(err, ErrSilentReject)
			a.Zero(rw.written())
		}
	}
}

func TestSplicedServerHello(t *testing.T) {
	a := require.New(t)
	st1, sh1 := captureFlight(t, nil)
	_, sh2 := captureFlight(t, nil)
	rw := &scriptRW{}
	ch, err := st1.finish(rw, sh1)
	a.NoError(err)
	a.NotNil(ch)
	got, err := st1.finish(rw, sh2)
	a.Nil(got)
	a.ErrorIs(err, ErrRelayAuthFailed)
	a.Empty(rw.writes)
}

func TestMalformedFrames(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	psk, err := GeneratePSK()
	a.NoError(err)
	pk := key.PublicKey()
	hint := KeyHint(pk)

	enc, _, err := sealStatic(pk)
	a.NoError(err)

	base := make([]byte, sizeClientHello)
	putHeader(base, typeClientHello)
	copy(base[hintOffset:], hint[:])

	zeroEnc := bytes.Clone(base)
	badEph := bytes.Clone(base)
	copy(badEph[encSOffset:], enc)
	reserved := bytes.Clone(base)
	reserved[flagOffset] = 0x02
	nonzeroBinder := bytes.Clone(base)
	nonzeroBinder[len(nonzeroBinder)-1] = 0x01
	badMagic := []byte{'X', 'R', Version, typeKeyRequest}
	unknown := []byte{magic0, magic1, Version, 0x09}
	badVer := []byte{magic0, magic1, 0x01, typeAlert, alertBadMessage}

	cases := []struct {
		name  string
		frame []byte
	}{
		{name: "bad magic", frame: badMagic},
		{name: "unknown type", frame: unknown},
		{name: "bad version", frame: badVer},
		{name: "reserved flags", frame: reserved},
		{name: "nonzero binder", frame: nonzeroBinder},
		{name: "zero enc", frame: zeroEnc},
		{name: "bad eph", frame: badEph},
	}
	lengths := []struct {
		name string
		typ  byte
		n    int
	}{
		{name: "key request", typ: typeKeyRequest, n: sizeKeyRequest},
		{name: "key response", typ: typeKeyResponse, n: sizeKeyResponse},
		{name: "client hello", typ: typeClientHello, n: sizeClientHello},
		{name: "server hello", typ: typeServerHello, n: sizeServerHello},
		{name: "alert", typ: typeAlert, n: sizeAlert},
	}
	for _, ln := range lengths {
		for _, delta := range []int{-1, 1} {
			n := ln.n + delta
			frame := make([]byte, n)
			hdr := []byte{magic0, magic1, Version, ln.typ}
			copy(frame, hdr)
			name := ln.name + " length off"
			if delta > 0 {
				name += " plus"
			} else {
				name += " minus"
			}
			cases = append(cases, struct {
				name  string
				frame []byte
			}{name: name, frame: frame})
		}
	}

	alert := alertFrame(alertBadMessage)
	for _, tc := range cases {
		t.Run(tc.name+"/public", func(t *testing.T) {
			a := require.New(t)
			rw := &scriptRW{reads: [][]byte{tc.frame}}
			_, err := Accept(rw, ServerConfig{Key: key})
			a.ErrorIs(err, ErrBadMessage)
			a.Equal([][]byte{alert}, rw.writes)
		})
		t.Run(tc.name+"/psk", func(t *testing.T) {
			a := require.New(t)
			rw := &scriptRW{reads: [][]byte{tc.frame}}
			_, err := Accept(rw, ServerConfig{Key: key, PSK: &psk})
			a.ErrorIs(err, ErrSilentReject)
			a.Zero(rw.written())
		})
	}

	t.Run("key request twice", func(t *testing.T) {
		a := require.New(t)
		kr := keyRequestFrame()
		rw := &scriptRW{reads: [][]byte{kr, kr}}
		_, err := Accept(rw, ServerConfig{Key: key})
		a.ErrorIs(err, ErrBadMessage)
		a.Len(rw.writes, 2)
		a.True(exact(rw.writes[0], typeKeyResponse, sizeKeyResponse))
		a.Equal(alert, rw.writes[1])

		rw = &scriptRW{reads: [][]byte{kr, kr}}
		_, err = Accept(rw, ServerConfig{Key: key, PSK: &psk})
		a.ErrorIs(err, ErrSilentReject)
		a.Zero(rw.written())
	})
	_ = a
}

func TestClientHeader(t *testing.T) {
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	pk := key.PublicKey()
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{
			name:  "bad version alert",
			frame: []byte{magic0, magic1, 0x01, typeAlert, 1},
			want:  ErrUnsupportedVersion,
		},
		{
			name:  "bad version hello",
			frame: []byte{magic0, magic1, 0x09, typeServerHello},
			want:  ErrUnsupportedVersion,
		},
		{
			name:  "bad magic",
			frame: []byte{'X', 'R', Version, typeAlert, 1},
			want:  ErrBadMessage,
		},
		{
			name:  "unknown alert",
			frame: alertFrame(9),
			want:  ErrBadMessage,
		},
		{
			name:  "alert 1",
			frame: alertFrame(alertBadMessage),
			want:  ErrBadMessage,
		},
		{
			name:  "alert 2",
			frame: alertFrame(alertPSKUnexpected),
			want:  ErrPSKUnexpected,
		},
		{
			name:  "alert 3",
			frame: alertFrame(alertUnknownKey),
			want:  ErrRelayKeyNotHeld,
		},
		{
			name:  "truncated",
			frame: []byte{magic0, magic1},
			want:  ErrBadMessage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			rw := &scriptRW{reads: [][]byte{tt.frame}}
			_, err := Initiate(rw, ClientConfig{RelayKey: pk})
			a.ErrorIs(err, tt.want)
			a.Len(rw.writes, 1)
			assertNoRecord(t, rw.writes)
		})
	}

	good := make([]byte, sizeKeyResponse)
	putHeader(good, typeKeyResponse)
	copy(good[headerLen:], pk[:])
	rw := &scriptRW{reads: [][]byte{good}}
	got, err := FetchKey(rw)
	a.NoError(err)
	a.Equal(pk, got)

	zero := make([]byte, sizeKeyResponse)
	putHeader(zero, typeKeyResponse)
	rw = &scriptRW{reads: [][]byte{zero}}
	_, err = FetchKey(rw)
	a.ErrorIs(err, ErrInvalidRelayKey)

	badVer := []byte{magic0, magic1, 0x03, typeKeyResponse}
	rw = &scriptRW{reads: [][]byte{badVer}}
	_, err = FetchKey(rw)
	a.ErrorIs(err, ErrUnsupportedVersion)
	assertNoRecord(t, rw.writes)
}

func TestFetchKeyThenRecordsUseKey(t *testing.T) {
	// Covered by TestRoundTrip fetch key. This checks the key bytes.
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	rawC, rawS := framePair(t)
	errc := make(chan error, 1)
	go func() {
		_, err := Accept(rawS, ServerConfig{Key: key})
		errc <- err
	}()
	got, err := FetchKey(rawC)
	a.NoError(err)
	a.Equal(key.PublicKey(), got)
	_, err = Initiate(rawC, ClientConfig{RelayKey: got})
	a.NoError(err)
	a.NoError(<-errc)
}

func dial(
	t *testing.T,
	key *PrivateKey,
	serverPSK, clientPSK *PSK,
	clientKey PublicKey,
	fetch bool,
) (
	clientCh, serverCh *Channel,
	clientWrites, serverWrites [][]byte,
	cErr, sErr error,
) {
	t.Helper()
	rawC, rawS := framePair(t)
	dead := time.Now().Add(2 * time.Minute)
	_ = rawC.SetDeadline(dead)
	_ = rawS.SetDeadline(dead)
	ctap := &tap{framedConn: rawC}
	stap := &tap{framedConn: rawS}
	sErrc := make(chan error, 1)
	go func() {
		var err error
		serverCh, err = Accept(stap, ServerConfig{
			Key: key, PSK: serverPSK,
		})
		if err != nil {
			_ = rawS.Close()
		}
		sErrc <- err
	}()
	cfg := ClientConfig{RelayKey: clientKey, PSK: clientPSK}
	if fetch {
		var got PublicKey
		got, cErr = FetchKey(ctap)
		if cErr != nil {
			_ = rawC.Close()
			sErr = <-sErrc
			clientWrites = append([][]byte(nil), ctap.writes...)
			serverWrites = append([][]byte(nil), stap.writes...)
			return clientCh, serverCh, clientWrites, serverWrites, cErr, sErr
		}
		cfg.RelayKey = got
	}
	clientCh, cErr = Initiate(ctap, cfg)
	if cErr != nil {
		_ = rawC.Close()
	}
	sErr = <-sErrc
	clientWrites = append([][]byte(nil), ctap.writes...)
	serverWrites = append([][]byte(nil), stap.writes...)
	return clientCh, serverCh, clientWrites, serverWrites, cErr, sErr
}

func captureFlight(t *testing.T, psk *PSK) (*clientState, []byte) {
	t.Helper()
	a := require.New(t)
	key, err := GenerateKey()
	a.NoError(err)
	rawC, rawS := framePair(t)
	dead := time.Now().Add(30 * time.Second)
	_ = rawC.SetDeadline(dead)
	_ = rawS.SetDeadline(dead)
	errc := make(chan error, 1)
	go func() {
		_, err := Accept(rawS, ServerConfig{Key: key, PSK: psk})
		if err != nil {
			_ = rawS.Close()
		}
		errc <- err
	}()
	st, err := prepareClient(ClientConfig{
		RelayKey: key.PublicKey(),
		PSK:      psk,
	})
	a.NoError(err)
	a.NoError(rawC.WriteBytes(st.ch))
	sh, err := rawC.ReadBytes()
	a.NoError(err)
	a.NoError(<-errc)
	return st, sh
}

func exchangeRecords(t *testing.T, a, b *Channel, n int) {
	t.Helper()
	req := require.New(t)
	errc := make(chan error, 4)
	var once sync.Once
	shut := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	go writeRecords(errc, a, n, shut)
	go readRecords(errc, b, n, shut)
	go writeRecords(errc, b, n, shut)
	go readRecords(errc, a, n, shut)
	for range 4 {
		err := <-errc
		if err != nil {
			shut()
			req.NoError(err)
		}
	}
}

func writeRecords(
	errc chan<- error, ch *Channel, n int, shut func(),
) {
	for i := range n {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(i))
		if err := ch.WriteBytes(buf[:]); err != nil {
			shut()
			errc <- err
			return
		}
	}
	errc <- nil
}

func readRecords(
	errc chan<- error, ch *Channel, n int, shut func(),
) {
	for i := range n {
		var want [8]byte
		binary.BigEndian.PutUint64(want[:], uint64(i))
		got, err := ch.ReadBytes()
		if err != nil {
			shut()
			errc <- err
			return
		}
		if !bytes.Equal(got, want[:]) {
			shut()
			errc <- errors.New("record mismatch")
			return
		}
	}
	errc <- nil
}

func honorLimit(t *testing.T, w, r *Channel) {
	t.Helper()
	a := require.New(t)
	maxN := w.MaxFrameSize()
	a.Equal(pipeLimit-recordOverhead, maxN)
	payload := make([]byte, maxN)
	payload[0] = 0xab
	errc := make(chan error, 1)
	go func() {
		got, err := r.ReadBytes()
		if err != nil {
			errc <- err
			return
		}
		if !bytes.Equal(got, payload) {
			errc <- errors.New("max frame mismatch")
			return
		}
		errc <- nil
	}()
	a.NoError(w.WriteBytes(payload))
	a.NoError(<-errc)
	err := w.WriteBytes(make([]byte, maxN+1))
	a.ErrorIs(err, ErrFrameTooLarge)
	done := make(chan struct {
		got []byte
		err error
	}, 1)
	go func() {
		got, err := r.ReadBytes()
		done <- struct {
			got []byte
			err error
		}{got, err}
	}()
	a.NoError(w.WriteBytes([]byte("still")))
	res := <-done
	a.NoError(res.err)
	a.Equal([]byte("still"), res.got)
}
