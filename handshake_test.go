package kamune

import (
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestHandshake(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune")
	a.NoError(err)
	a.NoError(f.Close())
	defer a.NoError(os.Remove(f.Name()))
	store, err := storage.OpenStorage(
		storage.StorageWithDBPath(f.Name()),
		storage.StorageWithAlgorithm(attest.Ed25519Algorithm),
		storage.StorageWithNoPassphrase(),
	)
	a.NoError(err)
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	a.NoError(err)
	conn2, err := newConn(c2)
	a.NoError(err)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attester1, err := attest.NewAttester(store.Algorithm())
	a.NoError(err)
	attester2, err := attest.NewAttester(store.Algorithm())
	a.NoError(err)

	pt1 := newUnderlyingTransport(
		conn1, conn1, attester2.PublicKey(), attester1, store,
	)
	pt2 := newUnderlyingTransport(
		conn2, conn2, attester1.PublicKey(), attester2, store,
	)

	hndshkeOpts := handshakeOpts{
		remoteVerifier: defaultRemoteVerifier,
		timeout:        30 * time.Second,
	}

	var t1 *Transport
	var handshakeErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		t1, handshakeErr = requestHandshake(pt1, hndshkeOpts)
	}()
	t2, err := acceptHandshake(pt2, hndshkeOpts)
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
	salt := make([]byte, saltSize)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2)

	b.ReportAllocs()
	for b.Loop() {
		if err := validateHandshakeFields(salt, string(sessionKey)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateHandshakeFields_BadSalt(b *testing.B) {
	salt := make([]byte, saltSize-1)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2)

	b.ReportAllocs()
	for b.Loop() {
		_ = validateHandshakeFields(salt, string(sessionKey))
	}
}

func BenchmarkValidateHandshakeFields_BadSessionKey(b *testing.B) {
	salt := make([]byte, saltSize)
	sessionKey := bytes.Repeat([]byte{'A'}, sessionIDLength/2-1)

	b.ReportAllocs()
	for b.Loop() {
		_ = validateHandshakeFields(salt, string(sessionKey))
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
		Key:        make([]byte, 64),
		Salt:       make([]byte, saltSize),
		SessionKey: "AAAAAAAAAA",
	}
	resp := &pb.Handshake{
		Key:        make([]byte, 128),
		Salt:       make([]byte, saltSize),
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

func BenchmarkHandshakeTranscriptHash_LargeKeyMaterial(b *testing.B) {
	// Stress case: larger KEM/enc blobs (still hashing only inner fields).
	req := &pb.Handshake{
		Key:        make([]byte, 2048),
		Salt:       make([]byte, saltSize),
		SessionKey: "AAAAAAAAAA",
	}
	resp := &pb.Handshake{
		Key:        make([]byte, 2048),
		Salt:       make([]byte, saltSize),
		SessionKey: "BBBBBBBBBB",
	}

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
