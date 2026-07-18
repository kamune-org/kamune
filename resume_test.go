package kamune

import (
	"crypto/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestStore(
	t *testing.T, opts ...storage.StorageOption,
) (*storage.Storage, func()) {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-resume-test-*.db")
	a.NoError(err)
	a.NoError(f.Close())

	s, err := storage.OpenStorage(
		append(
			[]storage.StorageOption{
				storage.WithDBPath(f.Name()),
				storage.WithNoPassphrase(),
			},
			opts...,
		)...,
	)
	a.NoError(err)

	cleanup := func() {
		s.Close()
		os.Remove(f.Name())
	}
	return s, cleanup
}

func setupExchange(
	t *testing.T, conn1, conn2 Conn,
) (*exchange.Channel, *exchange.Channel) {
	t.Helper()
	a := require.New(t)

	var ec1, ec2 *exchange.Channel
	var err1, err2 error
	done := make(chan struct{})
	go func() {
		defer close(done)
		ec1, err1 = exchange.Initiate(conn1)
	}()
	ec2, err2 = exchange.Accept(conn2)
	<-done
	a.NoError(err1)
	a.NoError(err2)
	return ec1, ec2
}

type resumptionTestContext struct {
	attest1   *attest.Attest
	attest2   *attest.Attest
	storage1  *storage.Storage
	storage2  *storage.Storage
	cleanup   func()
	sessionID string
}

// setupResumptionTest performs a cold handshake and stores resumption tokens in
// both client and server storage, returning everything needed for resume tests.
// Optional storage options are applied to the server-side storage only.
func setupResumptionTest(
	t *testing.T, serverStoreOpts ...storage.StorageOption,
) *resumptionTestContext {
	t.Helper()
	a := require.New(t)

	att1, err := attest.New()
	a.NoError(err)
	att2, err := attest.New()
	a.NoError(err)

	store1, cleanup1 := newTestStore(t)
	store2, cleanup2 := newTestStore(t, serverStoreOpts...)

	// Store each peer in the other's storage.
	a.NoError(store1.StorePeer(&storage.Peer{
		Name:      "server",
		PublicKey: att2.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(store2.StorePeer(&storage.Peer{
		Name:      "client",
		PublicKey: att1.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	// Cold handshake over fresh pipes.
	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)

	ec1, ec2 := setupExchange(t, conn1, conn2)

	// Client sends introduction.
	var introErr error
	introDone := make(chan struct{})
	go func() {
		defer close(introDone)
		introErr = sendIntroduction(ec1, att1, "client", AppVersion)
	}()
	st, err := readSignedTransport(ec2)
	a.NoError(err)
	<-introDone
	a.NoError(introErr)

	peer, _, err := receiveIntroduction(st)
	a.NoError(err)
	a.Equal(att1.MarshalPublicKey(), peer.PublicKey)

	// Server sends introduction.
	var sendIntroErr error
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		sendIntroErr = sendIntroduction(ec2, att2, "server", AppVersion)
	}()
	stClient, err := readSignedTransport(ec1)
	a.NoError(err)
	<-sendDone
	a.NoError(sendIntroErr)

	peer2, _, err := receiveIntroduction(stClient)
	a.NoError(err)
	a.Equal(att2.MarshalPublicKey(), peer2.PublicKey)

	// Handshake.
	serde1 := newSignedSerde(att2.MarshalPublicKey(), att1)
	serde2 := newSignedSerde(att1.MarshalPublicKey(), att2)

	opts := handshakeOpts{
		remoteVerifier: defaultRemoteVerifier,
		timeout:        30 * time.Second,
	}

	var t1 *Transport
	var hskErr error
	hskDone := make(chan struct{})
	go func() {
		defer close(hskDone)
		t1, hskErr = requestHandshake(ec1, serde1, opts)
	}()
	t2, err := acceptHandshake(ec2, serde2, opts)
	a.NoError(err)
	<-hskDone
	a.NoError(hskErr)
	a.NotNil(t1)
	a.NotNil(t2)

	sessionID := t1.SessionID()
	a.Equal(sessionID, t2.SessionID())

	// Create session records in both storages (required by GetSession).
	// Each storage references the remote peer's public key.
	a.NoError(store1.CreateSession(sessionID, att2.MarshalPublicKey()))
	a.NoError(store2.CreateSession(sessionID, att1.MarshalPublicKey()))

	// Store resumption tokens in both storages.
	a.NoError(store1.SetMeta(sessionID, storage.NewByteSlicesMeta(storage.ResumptionTokensKey, t1.deriveResumptionTokens())))
	a.NoError(store2.SetMeta(sessionID, storage.NewByteSlicesMeta(storage.ResumptionTokensKey, t2.deriveResumptionTokens())))

	cleanup := func() {
		conn1.Close()
		conn2.Close()
		cleanup1()
		cleanup2()
	}

	return &resumptionTestContext{
		attest1:   att1,
		attest2:   att2,
		storage1:  store1,
		storage2:  store2,
		sessionID: sessionID,
		cleanup:   cleanup,
	}
}

// ---------------------------------------------------------------------------
// Wire protocol roundtrip tests
// ---------------------------------------------------------------------------

func TestResumeRequest_Roundtrip(t *testing.T) {
	a := require.New(t)

	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()

	ec1, ec2 := setupExchange(t, conn1, conn2)

	att, err := attest.New()
	a.NoError(err)

	sessionID := "test-session-123456789012"
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i)
	}

	// Client sends ResumeRequest.
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = sendResumeRequest(ec1, att, sessionID, token)
	}()

	// Server reads the SignedTransport.
	st, err := readSignedTransport(ec2)
	a.NoError(err)
	<-done
	a.NoError(sendErr)

	// Verify route.
	route, err := routeFromST(st)
	a.NoError(err)
	a.Equal(RouteResumeRequest, route)

	// Unmarshal and verify fields.
	var req pb.ResumeRequest
	a.NoError(proto.Unmarshal(st.GetData(), &req))
	a.Equal(sessionID, req.GetSessionID())
	a.Equal(token, req.GetToken())

	// Verify signature.
	a.True(attest.Verify(att.MarshalPublicKey(), signingInput(st.GetMetadata(), st.GetData()), st.GetSignature()))
}

func TestResumeAccept_Roundtrip_Accepted(t *testing.T) {
	a := require.New(t)

	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()

	ec1, ec2 := setupExchange(t, conn1, conn2)

	att, err := attest.New()
	a.NoError(err)

	// Server sends accepted.
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = sendResumeAccept(ec2, att, true)
	}()

	// Client receives and verifies.
	accepted, reason, err := receiveResumeAccept(ec1, att.MarshalPublicKey())
	<-done
	a.NoError(sendErr)
	a.NoError(err)
	a.True(accepted)
	a.Empty(reason)
}

func TestResumeAccept_Roundtrip_Rejected(t *testing.T) {
	a := require.New(t)

	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()

	ec1, ec2 := setupExchange(t, conn1, conn2)

	att, err := attest.New()
	a.NoError(err)

	// Server sends rejected.
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendErr = sendResumeAccept(ec2, att, false)
	}()

	// Client receives and verifies.
	accepted, reason, err := receiveResumeAccept(ec1, att.MarshalPublicKey())
	<-done
	a.NoError(sendErr)
	a.NoError(err)
	a.False(accepted)
	a.Equal("resumption not available", reason)
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

func TestResume_HappyPath(t *testing.T) {
	a := require.New(t)
	ctx := setupResumptionTest(t)
	defer ctx.cleanup()

	// Phase B: resume over fresh pipes.
	c3, c4 := net.Pipe()
	conn3 := newConn(c3)
	conn4 := newConn(c4)
	defer conn3.Close()
	defer conn4.Close()

	ec3, ec4 := setupExchange(t, conn3, conn4)

	// Client: get token and send ResumeRequest.
	token, err := ctx.storage1.PopList(ctx.sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	a.NotNil(token)

	var reqErr error
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = sendResumeRequest(ec3, ctx.attest1, ctx.sessionID, token)
	}()

	// Server: read and validate.
	st, err := readSignedTransport(ec4)
	a.NoError(err)
	<-reqDone
	a.NoError(reqErr)

	r, err := routeFromST(st)
	a.NoError(err)
	a.Equal(RouteResumeRequest, r)

	var req pb.ResumeRequest
	a.NoError(proto.Unmarshal(st.GetData(), &req))
	a.Equal(ctx.sessionID, req.GetSessionID())

	err = ctx.storage2.RemoveListItem(
		req.GetSessionID(), storage.ResumptionTokensKey, req.GetToken(),
	)
	a.NoError(err)

	peer, err := ctx.storage2.GetPeer(req.GetSessionID())
	a.NoError(err)
	establishedAt, err := ctx.storage2.GetEstablishedAt(req.GetSessionID())
	a.NoError(err)

	a.True(attest.Verify(peer.PublicKey, signingInput(st.GetMetadata(), st.GetData()), st.GetSignature()))
	a.False(time.Since(establishedAt) > resumptionGracePeriod)

	// Server: accept (must goroutine — pipe is synchronous).
	var acceptErr error
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		acceptErr = sendResumeAccept(ec4, ctx.attest2, true)
	}()

	// Client: receive accept.
	accepted, reason, err := receiveResumeAccept(ec3, ctx.attest2.MarshalPublicKey())
	<-acceptDone
	a.NoError(acceptErr)
	a.NoError(err)
	a.True(accepted)
	a.Empty(reason)

	// Both: handshake with predetermined session ID.
	serde3 := newSignedSerde(ctx.attest2.MarshalPublicKey(), ctx.attest1)
	serde4 := newSignedSerde(ctx.attest1.MarshalPublicKey(), ctx.attest2)

	opts := handshakeOpts{
		remoteVerifier: defaultRemoteVerifier,
		timeout:        30 * time.Second,
		sessionID:      ctx.sessionID,
	}

	var t3 *Transport
	var hskErr error
	hskDone := make(chan struct{})
	go func() {
		defer close(hskDone)
		t3, hskErr = requestHandshake(ec3, serde3, opts)
	}()
	t4, err := acceptHandshake(ec4, serde4, opts)
	a.NoError(err)
	<-hskDone
	a.NoError(hskErr)
	a.NotNil(t3)
	a.NotNil(t4)

	a.Equal(ctx.sessionID, t3.SessionID())
	a.Equal(ctx.sessionID, t4.SessionID())

	// Verify bidirectional message exchange.
	msg := Bytes([]byte(rand.Text()))
	var md *Metadata
	var sendErr error
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		md, sendErr = t3.Send(msg, RouteExchangeMessages)
	}()
	received := Bytes(nil)
	recvMd, err := t4.Receive(received)
	a.NoError(err)
	<-sendDone
	a.NoError(sendErr)
	a.Equal(msg.Value, received.Value)
	a.Equal(md.ID(), recvMd.ID())
}

func TestResumeRejected_InvalidToken(t *testing.T) {
	a := require.New(t)
	ctx := setupResumptionTest(t)
	defer ctx.cleanup()

	c3, c4 := net.Pipe()
	conn3 := newConn(c3)
	conn4 := newConn(c4)
	defer conn3.Close()
	defer conn4.Close()

	ec3, ec4 := setupExchange(t, conn3, conn4)

	// Client: send ResumeRequest with random (invalid) token.
	badToken := make([]byte, 32)
	_, _ = rand.Read(badToken)

	var reqErr error
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = sendResumeRequest(ec3, ctx.attest1, ctx.sessionID, badToken)
	}()

	// Server: read and attempt validation.
	st, err := readSignedTransport(ec4)
	a.NoError(err)
	<-reqDone
	a.NoError(reqErr)

	var req pb.ResumeRequest
	a.NoError(proto.Unmarshal(st.GetData(), &req))

	// RemoveSessionToken should fail (token not found).
	err = ctx.storage2.RemoveListItem(
		req.GetSessionID(), storage.ResumptionTokensKey, req.GetToken(),
	)
	a.Error(err)

	// Server rejects.
	var rejectErr error
	rejectDone := make(chan struct{})
	go func() {
		defer close(rejectDone)
		rejectErr = sendResumeAccept(ec4, ctx.attest2, false)
	}()

	// Client receives rejection.
	accepted, reason, err := receiveResumeAccept(ec3, ctx.attest2.MarshalPublicKey())
	<-rejectDone
	a.NoError(rejectErr)
	a.NoError(err)
	a.False(accepted)
	a.Equal("resumption not available", reason)
}

func TestResumeRejected_ExpiredSession(t *testing.T) {
	a := require.New(t)

	fakeClock := clock.NewFake(time.Now().Add(-25 * time.Hour))
	ctx := setupResumptionTest(t, storage.WithClock(fakeClock))

	c3, c4 := net.Pipe()
	conn3 := newConn(c3)
	conn4 := newConn(c4)
	defer conn3.Close()
	defer conn4.Close()

	ec3, ec4 := setupExchange(t, conn3, conn4)

	// Client: get token and send ResumeRequest.
	token, err := ctx.storage1.PopList(ctx.sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	a.NotNil(token)

	var reqErr error
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = sendResumeRequest(ec3, ctx.attest1, ctx.sessionID, token)
	}()

	// Server: read and validate.
	st, err := readSignedTransport(ec4)
	a.NoError(err)
	<-reqDone
	a.NoError(reqErr)

	var req pb.ResumeRequest
	a.NoError(proto.Unmarshal(st.GetData(), &req))

	err = ctx.storage2.RemoveListItem(
		req.GetSessionID(), storage.ResumptionTokensKey, req.GetToken(),
	)
	a.NoError(err)

	peer, err := ctx.storage2.GetPeer(req.GetSessionID())
	a.NoError(err)
	establishedAt, err := ctx.storage2.GetEstablishedAt(req.GetSessionID())
	a.NoError(err)

	// Verify signature passes...
	a.True(attest.Verify(peer.PublicKey, signingInput(st.GetMetadata(), st.GetData()), st.GetSignature()))

	// ...but expiry check fails.
	a.True(time.Since(establishedAt) > resumptionGracePeriod)

	// Server rejects.
	var rejectErr2 error
	rejectDone2 := make(chan struct{})
	go func() {
		defer close(rejectDone2)
		rejectErr2 = sendResumeAccept(ec4, ctx.attest2, false)
	}()

	// Client receives rejection.
	accepted, reason, err := receiveResumeAccept(ec3, ctx.attest2.MarshalPublicKey())
	<-rejectDone2
	a.NoError(rejectErr2)
	a.NoError(err)
	a.False(accepted)
	a.Equal("resumption not available", reason)
}

func TestResumeRejected_SignatureMismatch(t *testing.T) {
	a := require.New(t)
	ctx := setupResumptionTest(t)
	defer ctx.cleanup()

	// Third attestation keypair signs the request (wrong key).
	attWrong, err := attest.New()
	a.NoError(err)

	c3, c4 := net.Pipe()
	conn3 := newConn(c3)
	conn4 := newConn(c4)
	defer conn3.Close()
	defer conn4.Close()

	ec3, ec4 := setupExchange(t, conn3, conn4)

	// Client: get token and send ResumeRequest signed by wrong key.
	token, err := ctx.storage1.PopList(ctx.sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	a.NotNil(token)

	var reqErr error
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = sendResumeRequest(ec3, attWrong, ctx.sessionID, token)
	}()

	// Server: read and validate.
	st, err := readSignedTransport(ec4)
	a.NoError(err)
	<-reqDone
	a.NoError(reqErr)

	var req pb.ResumeRequest
	a.NoError(proto.Unmarshal(st.GetData(), &req))

	err = ctx.storage2.RemoveListItem(
		req.GetSessionID(), storage.ResumptionTokensKey, req.GetToken(),
	)
	a.NoError(err)

	peer, err := ctx.storage2.GetPeer(req.GetSessionID())
	a.NoError(err)

	// Token is valid but signature is wrong.
	a.False(attest.Verify(peer.PublicKey, signingInput(st.GetMetadata(), st.GetData()), st.GetSignature()))

	// Server rejects.
	var rejectErr3 error
	rejectDone3 := make(chan struct{})
	go func() {
		defer close(rejectDone3)
		rejectErr3 = sendResumeAccept(ec4, ctx.attest2, false)
	}()

	// Client receives rejection.
	accepted, reason, err := receiveResumeAccept(ec3, ctx.attest2.MarshalPublicKey())
	<-rejectDone3
	a.NoError(rejectErr3)
	a.NoError(err)
	a.False(accepted)
	a.Equal("resumption not available", reason)
}

func TestResumeRejected_Disabled(t *testing.T) {
	a := require.New(t)
	ctx := setupResumptionTest(t)
	defer ctx.cleanup()

	c3, c4 := net.Pipe()
	conn3 := newConn(c3)
	conn4 := newConn(c4)
	defer conn3.Close()
	defer conn4.Close()

	ec3, ec4 := setupExchange(t, conn3, conn4)

	// Client sends ResumeRequest.
	token, err := ctx.storage1.PopList(ctx.sessionID, storage.ResumptionTokensKey)
	a.NoError(err)

	var reqErr error
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = sendResumeRequest(ec3, ctx.attest1, ctx.sessionID, token)
	}()

	// Server reads and checks route — simulating resumeEnabled: false.
	st, err := readSignedTransport(ec4)
	a.NoError(err)
	<-reqDone
	a.NoError(reqErr)

	route, err := routeFromST(st)
	a.NoError(err)
	a.Equal(RouteResumeRequest, route)
}
