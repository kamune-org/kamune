package kamune

import (
	"bytes"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestHandshake(t *testing.T) {
	a := require.New(t)

	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attest1, err := attest.New()
	a.NoError(err)
	attest2, err := attest.New()
	a.NoError(err)

	serde1 := newSignedSerde(attest2.MarshalPublicKey(), attest1)
	serde2 := newSignedSerde(attest1.MarshalPublicKey(), attest2)

	hndshkeOpts := handshakeOpts{
		remoteVerifier: func(*storage.Storage, *storage.Peer) error { return nil },
		timeout:        30 * time.Second,
	}

	var t1 *Transport
	var handshakeErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		t1, handshakeErr = requestHandshake(conn1, serde1, hndshkeOpts)
	}()
	t2, err := acceptHandshake(conn2, serde2, hndshkeOpts)
	a.NoError(err)
	<-done
	a.NoError(handshakeErr)
	a.NotNil(t1)
	a.NotNil(t2)

	msg1 := Bytes([]byte(rand.Text()))
	var metadata1 *Metadata
	var sendErr1 error
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		metadata1, sendErr1 = t1.Send(msg1, RouteExchangeMessages)
	}()
	receivedMsg1 := Bytes(nil)
	receivedMetadata1, err := t2.Receive(receivedMsg1)
	a.NoError(err)
	<-done1
	a.NoError(sendErr1)
	a.NotNil(metadata1)
	a.NotNil(receivedMetadata1)
	a.Equal(msg1.Value, receivedMsg1.Value)
	a.Equal(metadata1.ID(), receivedMetadata1.ID())
	a.Equal(metadata1.Timestamp(), receivedMetadata1.Timestamp())
	a.Equal(metadata1.SequenceNum(), receivedMetadata1.SequenceNum())

	msg2 := Bytes([]byte(rand.Text()))
	var metadata2 *Metadata
	var sendErr2 error
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		metadata2, sendErr2 = t2.Send(msg2, RouteExchangeMessages)
	}()
	receivedMsg2 := Bytes(nil)
	receivedMetadata2, err := t1.Receive(receivedMsg2)
	a.NoError(err)
	<-done2
	a.NoError(sendErr2)
	a.NotNil(metadata2)
	a.NotNil(receivedMetadata2)
	a.Equal(msg2.Value, receivedMsg2.Value)
	a.Equal(metadata2.ID(), receivedMetadata2.ID())
	a.Equal(metadata2.Timestamp(), receivedMetadata2.Timestamp())
	a.Equal(metadata2.SequenceNum(), receivedMetadata2.SequenceNum())
}

func BenchmarkValidateHandshakeFields_OK(b *testing.B) {
	salt := make([]byte, handshakeSaltSize)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2)

	b.ReportAllocs()
	for b.Loop() {
		if err := validateHandshakeFields(
			salt, string(sessionKey), sessionIDLength/2,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func TestValidateHandshakeFields(t *testing.T) {
	tests := []struct {
		name       string
		sessionKey string
		saltSize   int
		wantLen    int
		wantErr    bool
	}{
		{"prefix", "ABCDEFGHIJKL", handshakeSaltSize, 12, false},
		{
			"full",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:sessionIDLength],
			handshakeSaltSize, sessionIDLength, false,
		},
		{"cold rejects full", "ABCDEFGHIJKLMNOPQRSTUVWX", handshakeSaltSize, 12, true},
		{"resume rejects prefix", "ABCDEFGHIJKL", handshakeSaltSize, 24, true},
		{"short salt", "ABCDEFGHIJKL", handshakeSaltSize - 1, 12, true},
		{"short key", "ABCDEFGHIJK", handshakeSaltSize, 12, true},
		{"lowercase", "ABCDEFGHIJKa", handshakeSaltSize, 12, true},
		{"punctuation", "ABCDEFGHIJK!", handshakeSaltSize, 12, true},
		{"invalid digit", "ABCDEFGHIJK0", handshakeSaltSize, 12, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			err := validateHandshakeFields(
				make([]byte, tt.saltSize),
				tt.sessionKey,
				tt.wantLen,
			)
			if tt.wantErr {
				a.Error(err)
			} else {
				a.NoError(err)
			}
		})
	}
}

func BenchmarkValidateHandshakeFields_BadSalt(b *testing.B) {
	salt := make([]byte, handshakeSaltSize-1)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2)

	b.ReportAllocs()
	for b.Loop() {
		_ = validateHandshakeFields(
			salt, string(sessionKey), sessionIDLength/2,
		)
	}
}

func BenchmarkValidateHandshakeFields_BadSessionKey(b *testing.B) {
	salt := make([]byte, handshakeSaltSize)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2-1)

	b.ReportAllocs()
	for b.Loop() {
		_ = validateHandshakeFields(
			salt, string(sessionKey), sessionIDLength/2,
		)
	}
}

func BenchmarkHandshakeTranscriptHash_HandshakeFieldsTypical(b *testing.B) {
	// Model a typical handshake (inner pb.Handshake fields only):
	// - req.Key: initiator MLKEM public key bytes (small)
	// - resp.Key: KEM enc bytes (small/moderate)
	// - salts: 16 bytes
	// - session prefix/suffix: 10 chars each
	//
	// Note: these sizes are representative; the benchmark is about per-call
	// overhead rather than exact on-wire sizing.
	req := &pb.Handshake{
		Key:        make([]byte, 32),
		Salt:       make([]byte, handshakeSaltSize),
		SessionKey: "AAAAAAAAAA",
	}
	resp := &pb.Handshake{
		Key:        make([]byte, 32),
		Salt:       make([]byte, handshakeSaltSize),
		SessionKey: "BBBBBBBBBB",
	}

	// Bytes processed by the hasher inside handshakeTranscriptHash:
	// domain label + length prefixes + field bytes.
	totalBytes :=
		len("kamune/handshake/v1") +
			4 + len(req.GetKey()) +
			4 + len(req.GetSalt()) +
			4 + len(req.GetSessionKey()) +
			4 + len(resp.GetKey()) +
			4 + len(resp.GetSalt()) +
			4 + len(resp.GetSessionKey())

	b.ReportAllocs()
	b.SetBytes(int64(totalBytes))
	for b.Loop() {
		_ = handshakeTranscriptHash(req, resp)
	}
}

func BenchmarkDeriveChallengeInfo(b *testing.B) {
	sessionID := "12345678901234567890" // sessionIDLength
	direction := handshakeC2SInfo
	var transcriptHash [32]byte

	b.ReportAllocs()
	for b.Loop() {
		_ = deriveChallengeInfo(sessionID, direction, transcriptHash)
	}
}

// handshakeScript plays one side of a handshake against requestHandshake or
// acceptHandshake, departing from the protocol as its fields say. The zero
// value plays its side correctly.
type handshakeScript struct {
	// mutate changes the handshake message before it is signed.
	mutate func(*pb.Handshake)
	// signer signs the handshake message in place of the script's own key.
	signer *attest.Attest
	// challenge plays the challenge phase in place of the protocol.
	challenge func(*Transport) error
	// route replaces the route of the handshake message, if set.
	route Route
}

// send signs msg, as the script's fields say, and writes it to cn.
func (s handshakeScript) send(
	cn Conn, serde *signedSerde, msg *pb.Handshake, route Route,
) error {
	if s.mutate != nil {
		s.mutate(msg)
	}
	if s.route != RouteInvalid {
		route = s.route
	}
	if s.signer != nil {
		serde = newSignedSerde(serde.remote, s.signer)
	}
	b, _, err := serde.serialize(msg, route, 0)
	if err != nil {
		return err
	}
	return cn.WriteBytes(b)
}

// scriptTransport returns the transport of a scripted side, which encrypts
// with sendInfo and decrypts with recvInfo.
func scriptTransport(
	cn Conn,
	serde *signedSerde,
	secret []byte,
	sessionID string,
	sendSalt, recvSalt []byte,
	sendInfo, recvInfo string,
) (*Transport, error) {
	enc, err := enigma.NewEnigma(secret, sendSalt, []byte(sendInfo+sessionID))
	if err != nil {
		return nil, err
	}
	dec, err := enigma.NewEnigma(secret, recvSalt, []byte(recvInfo+sessionID))
	if err != nil {
		return nil, err
	}
	return newTransport(cn, serde, sessionID, enc, dec), nil
}

// respond plays the responder on cn against requestHandshake run by the
// owner of remote. sessionID is the session being resumed, or "".
func (s handshakeScript) respond(
	cn Conn, local *attest.Attest, remote []byte, sessionID string,
) error {
	serde := newSignedSerde(remote, local)
	reqBytes, err := cn.ReadBytes()
	if err != nil {
		return err
	}
	var req pb.Handshake
	if _, err := serde.deserialize(reqBytes, &req); err != nil {
		return err
	}
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return err
	}
	sessionKey := sessionID
	if sessionID == "" {
		sessionKey = enigma.Text(sessionIDLength / 2)
	}
	resp := &pb.Handshake{
		Key:        ct,
		Salt:       randomBytes(handshakeSaltSize),
		SessionKey: sessionKey,
	}
	if err := s.send(cn, serde, resp, RouteAcceptHandshake); err != nil {
		return err
	}
	if sessionID == "" {
		sessionID = req.GetSessionKey() + resp.GetSessionKey()
	}
	t, err := scriptTransport(
		cn, serde, secret, sessionID, resp.GetSalt(), req.GetSalt(),
		handshakeS2CInfo, handshakeC2SInfo,
	)
	if err != nil {
		return err
	}
	if s.challenge != nil {
		return s.challenge(t)
	}
	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return err
	}
	return sendChallenge(t, secret, deriveChallengeInfo(
		sessionID, handshakeS2CInfo, handshakeTranscriptHash(&req, resp),
	))
}

// initiate plays the initiator on cn against acceptHandshake run by the
// owner of remote. sessionID is the session being resumed, or "".
func (s handshakeScript) initiate(
	cn Conn, local *attest.Attest, remote []byte, sessionID string,
) error {
	serde := newSignedSerde(remote, local)
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return err
	}
	sessionKey := sessionID
	if sessionID == "" {
		sessionKey = enigma.Text(sessionIDLength / 2)
	}
	req := &pb.Handshake{
		Key:        ml.PublicKey.Bytes(),
		Salt:       randomBytes(handshakeSaltSize),
		SessionKey: sessionKey,
	}
	if err := s.send(cn, serde, req, RouteRequestHandshake); err != nil {
		return err
	}
	respBytes, err := cn.ReadBytes()
	if err != nil {
		return err
	}
	var resp pb.Handshake
	if _, err := serde.deserialize(respBytes, &resp); err != nil {
		return err
	}
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return err
	}
	if sessionID == "" {
		sessionID = req.GetSessionKey() + resp.GetSessionKey()
	}
	t, err := scriptTransport(
		cn, serde, secret, sessionID, req.GetSalt(), resp.GetSalt(),
		handshakeC2SInfo, handshakeS2CInfo,
	)
	if err != nil {
		return err
	}
	if s.challenge != nil {
		return s.challenge(t)
	}
	err = sendChallenge(t, secret, deriveChallengeInfo(
		sessionID, handshakeC2SInfo, handshakeTranscriptHash(req, &resp),
	))
	if err != nil {
		return err
	}
	return acceptChallenge(t, RouteSendChallenge)
}

// runScriptedHandshake runs requestHandshake, or acceptHandshake when
// dialer is false, against script playing the other side over a pipe. It
// returns the local side's transport and error, and the script's error.
func runScriptedHandshake(
	t *testing.T, script handshakeScript, dialer bool, sessionID string,
) (*Transport, error, error) {
	t.Helper()
	a := require.New(t)
	local, err := attest.New()
	a.NoError(err)
	peer, err := attest.New()
	a.NoError(err)

	c1, c2 := net.Pipe()
	localConn, peerConn := newConn(c1), newConn(c2)
	play := script.initiate
	if dialer {
		play = script.respond
	}
	scriptErr := make(chan error, 1)
	go func() {
		// The script closes its end once done, so that a local side that
		// still waits for it fails instead of waiting for the deadline.
		defer func() { _ = peerConn.Close() }()
		scriptErr <- play(peerConn, peer, local.MarshalPublicKey(), sessionID)
	}()

	serde := newSignedSerde(peer.MarshalPublicKey(), local)
	opts := handshakeOpts{timeout: 30 * time.Second, sessionID: sessionID}
	var tr *Transport
	if dialer {
		tr, err = requestHandshake(localConn, serde, opts)
	} else {
		tr, err = acceptHandshake(localConn, serde, opts)
	}
	// Closing the local end ends a script still waiting on the pipe.
	_ = localConn.Close()
	return tr, err, <-scriptErr
}

// receiveThen returns a challenge script that receives the peer's challenge
// and then runs next with it.
func receiveThen(next func(*Transport, []byte) error) func(*Transport) error {
	return func(t *Transport) error {
		challenge := Bytes(nil)
		if _, err := t.Receive(challenge); err != nil {
			return err
		}
		return next(t, challenge.GetValue())
	}
}

// answer returns a challenge step that sends value on route, or the
// received challenge when value is nil.
func answer(value []byte, route Route) func(*Transport, []byte) error {
	return func(t *Transport, challenge []byte) error {
		if value == nil {
			value = challenge
		}
		_, err := t.Send(Bytes(value), route)
		return err
	}
}

// garble writes a frame that does not decrypt under the session keys.
func garble(t *Transport) error {
	return t.conn.WriteBytes(bytes.Repeat([]byte{0x5a}, 64))
}

func TestRequestHandshakeRejectsBadResponder(t *testing.T) {
	other, err := attest.New()
	require.New(t).NoError(err)
	wrong := bytes.Repeat([]byte{0xa5}, handshakeChallengeSize)

	cases := []struct {
		want    error
		name    string
		msg     string
		script  handshakeScript
		resumes bool
	}{
		{name: "conforming responder"},
		{name: "conforming responder on resume", resumes: true},
		{
			name:   "unexpected route",
			want:   ErrUnexpectedRoute,
			script: handshakeScript{route: RouteRequestHandshake},
		},
		{
			name:   "signed by another key",
			want:   ErrInvalidSignature,
			script: handshakeScript{signer: other},
		},
		{
			name: "short salt",
			msg:  "invalid remote handshake fields",
			script: handshakeScript{mutate: func(h *pb.Handshake) {
				h.Salt = h.Salt[:handshakeSaltSize/2]
			}},
		},
		{
			name:    "other session on resume",
			msg:     "session ID mismatch",
			resumes: true,
			script: handshakeScript{mutate: func(h *pb.Handshake) {
				h.SessionKey = enigma.Text(sessionIDLength)
			}},
		},
		{
			name: "wrong challenge echo",
			want: ErrVerificationFailed,
			script: handshakeScript{
				challenge: receiveThen(answer(wrong, RouteVerifyChallenge)),
			},
		},
		{
			name: "challenge echo on wrong route",
			want: ErrUnexpectedRoute,
			script: handshakeScript{
				challenge: receiveThen(answer(nil, RouteSendChallenge)),
			},
		},
		{
			name: "own challenge on wrong route",
			want: ErrUnexpectedRoute,
			script: handshakeScript{challenge: receiveThen(
				func(t *Transport, challenge []byte) error {
					err := answer(nil, RouteVerifyChallenge)(t, challenge)
					if err != nil {
						return err
					}
					return answer(wrong, RouteVerifyChallenge)(t, nil)
				},
			)},
		},
		{
			name: "undecryptable challenge echo",
			msg:  "decrypting payload",
			script: handshakeScript{challenge: receiveThen(
				func(t *Transport, _ []byte) error { return garble(t) },
			)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var sessionID string
			if tc.resumes {
				sessionID = enigma.Text(sessionIDLength)
			}
			tr, err, scriptErr := runScriptedHandshake(
				t, tc.script, true, sessionID,
			)
			if tc.want == nil && tc.msg == "" {
				a.NoError(err)
				a.NoError(scriptErr)
				a.True(tr.established)
				return
			}
			a.Error(err)
			a.Nil(tr)
			if tc.want != nil {
				a.ErrorIs(err, tc.want)
			}
			a.ErrorContains(err, tc.msg)
		})
	}
}

func TestAcceptHandshakeRejectsBadInitiator(t *testing.T) {
	other, err := attest.New()
	require.New(t).NoError(err)
	wrong := bytes.Repeat([]byte{0xa5}, handshakeChallengeSize)

	cases := []struct {
		want    error
		name    string
		msg     string
		script  handshakeScript
		resumes bool
	}{
		{name: "conforming initiator"},
		{name: "conforming initiator on resume", resumes: true},
		{
			name:   "unexpected route",
			want:   ErrUnexpectedRoute,
			script: handshakeScript{route: RouteAcceptHandshake},
		},
		{
			name:   "signed by another key",
			want:   ErrInvalidSignature,
			script: handshakeScript{signer: other},
		},
		{
			name: "invalid session key",
			msg:  "invalid remote handshake fields",
			script: handshakeScript{mutate: func(h *pb.Handshake) {
				h.SessionKey = strings.ToLower(h.SessionKey)
			}},
		},
		{
			name:    "other session on resume",
			msg:     "session ID mismatch",
			resumes: true,
			script: handshakeScript{mutate: func(h *pb.Handshake) {
				h.SessionKey = enigma.Text(sessionIDLength)
			}},
		},
		{
			name: "challenge on wrong route",
			want: ErrUnexpectedRoute,
			script: handshakeScript{challenge: func(t *Transport) error {
				return answer(wrong, RouteVerifyChallenge)(t, nil)
			}},
		},
		{
			name: "wrong challenge echo",
			want: ErrVerificationFailed,
			script: handshakeScript{challenge: func(t *Transport) error {
				err := answer(wrong, RouteSendChallenge)(t, nil)
				if err != nil {
					return err
				}
				if _, err := t.Receive(Bytes(nil)); err != nil {
					return err
				}
				return receiveThen(answer(wrong, RouteVerifyChallenge))(t)
			}},
		},
		{
			name:   "undecryptable challenge",
			msg:    "decrypting payload",
			script: handshakeScript{challenge: garble},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var sessionID string
			if tc.resumes {
				sessionID = enigma.Text(sessionIDLength)
			}
			tr, err, scriptErr := runScriptedHandshake(
				t, tc.script, false, sessionID,
			)
			if tc.want == nil && tc.msg == "" {
				a.NoError(err)
				a.NoError(scriptErr)
				a.True(tr.established)
				return
			}
			a.Error(err)
			a.Nil(tr)
			if tc.want != nil {
				a.ErrorIs(err, tc.want)
			}
			a.ErrorContains(err, tc.msg)
		})
	}
}
