package kamune

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestStore(
	t testing.TB, opts ...storage.StorageOption,
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
// Resume requests served by Server.serve
// ---------------------------------------------------------------------------

// resumeEnv is a session that a client and a server both stored after a cold
// handshake. token is one of the session's unused tokens, taken from the
// client's storage as a dialer would take it.
type resumeEnv struct {
	serverStore *storage.Storage
	client      *attest.Attest
	clock       *clock.Fake
	sessionID   string
	token       []byte
}

func newResumeEnv(t *testing.T) *resumeEnv {
	t.Helper()
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)

	sessionID := coldDial(t, clientStore, serverStore)
	client, err := clientStore.Attester()
	a.NoError(err)
	token, err := clientStore.PopList(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	return &resumeEnv{
		serverStore: serverStore,
		client:      client,
		clock:       clock.NewFake(time.Now()),
		sessionID:   sessionID,
		token:       token,
	}
}

// storedTokens returns the server's packed list of the session's tokens.
func (e *resumeEnv) storedTokens(a *require.Assertions) []byte {
	m, err := e.serverStore.GetMeta(e.sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	return m.Value()
}

// tokenCount returns the number of tokens in a packed list of tokens.
func tokenCount(list []byte) int {
	if len(list) < 4 {
		return 0
	}
	return int(binary.BigEndian.Uint32(list))
}

// resumeRequest returns a marshalled ResumeRequest.
func resumeRequest(sessionID string, token []byte) []byte {
	b, err := proto.Marshal(&pb.ResumeRequest{
		SessionID: sessionID,
		Token:     token,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// writeResumeRequest writes data, signed by at, to conn as the message of a
// resume request, as sendResumeRequest does with a marshalled request.
func writeResumeRequest(conn Conn, at *attest.Attest, data []byte) error {
	md, err := proto.Marshal(&pb.Metadata{Route: RouteResumeRequest.ToProto()})
	if err != nil {
		return err
	}
	sig, err := at.Sign(signingInput(md, data))
	if err != nil {
		return err
	}
	payload, err := padSignedTransport(&pb.SignedTransport{
		Data:      data,
		Signature: sig,
		Metadata:  md,
	})
	if err != nil {
		return err
	}
	return conn.WriteBytes(payload)
}

// resumeAnswer is how a server answered a resume request.
type resumeAnswer struct {
	// serveErr is what Server.serve returned.
	serveErr error
	// readErr is the error reading the server's ResumeAccept, if any.
	readErr  error
	reason   string
	accepted bool
}

// requestResume sends data, signed by signer, as a resume request to a
// server on e's server storage, which uses e's clock. It reads the server's
// answer and then closes the connection without a handshake.
func (e *resumeEnv) requestResume(
	t *testing.T, signer *attest.Attest, data []byte, opts ...ServerOptions,
) resumeAnswer {
	t.Helper()
	a := require.New(t)
	clientNet, serverNet := net.Pipe()
	clientConn, serverConn := newConn(clientNet), newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	server, err := NewServer(
		"",
		func(*Transport) error { return errors.New("handler must not run") },
		e.serverStore,
		func(*storage.Storage, *storage.Peer) error {
			return errors.New("verifier must not run")
		},
		append([]ServerOptions{ServeWithClock(e.clock)}, opts...)...,
	)
	a.NoError(err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	ec, err := exchange.Initiate(clientConn)
	a.NoError(err)
	a.NoError(writeResumeRequest(ec, signer, data))
	var ans resumeAnswer
	ans.accepted, ans.reason, ans.readErr = receiveResumeAccept(
		ec, server.PublicKey(),
	)
	_ = clientConn.Close()
	ans.serveErr = <-serveErr
	return ans
}

// TestHandleResumeRejects sends resume requests that the server must refuse
// through Server.serve, and checks that the server answers with a generic
// rejection, also when resumption is off, and that no token is consumed.
func TestHandleResumeRejects(t *testing.T) {
	other, err := attest.New()
	require.New(t).NoError(err)
	signedBy := func(
		signer func(*resumeEnv) *attest.Attest,
		data func(*resumeEnv) []byte,
	) func(*resumeEnv) (*attest.Attest, []byte) {
		return func(e *resumeEnv) (*attest.Attest, []byte) {
			return signer(e), data(e)
		}
	}
	byClient := func(e *resumeEnv) *attest.Attest { return e.client }
	byOther := func(*resumeEnv) *attest.Attest { return other }
	validRequest := func(e *resumeEnv) []byte {
		return resumeRequest(e.sessionID, e.token)
	}

	cases := []struct {
		// setup changes the stored session before the request is sent.
		setup func(*testing.T, *resumeEnv)
		// request returns the signer and message of the request. Nil
		// sends a valid request signed by the client.
		request func(*resumeEnv) (*attest.Attest, []byte)
		name    string
		// reason is the reason that serve gives for the rejection.
		reason string
		opts   []ServerOptions
	}{
		{
			name:   "resumption disabled",
			reason: "resumption not available",
			opts:   []ServerOptions{ServeWithResumeEnabled(false)},
		},
		{
			name:   "malformed request",
			reason: "malformed request",
			request: signedBy(byClient, func(*resumeEnv) []byte {
				return []byte{0xff}
			}),
		},
		{
			name:   "short token",
			reason: "token invalid",
			request: signedBy(byClient, func(e *resumeEnv) []byte {
				return resumeRequest(e.sessionID, e.token[:3])
			}),
		},
		{
			name:   "unknown session",
			reason: "unknown session",
			request: signedBy(byClient, func(e *resumeEnv) []byte {
				return resumeRequest(enigma.Text(sessionIDLength), e.token)
			}),
		},
		{
			name:   "peer deleted",
			reason: "unknown session",
			setup: func(t *testing.T, e *resumeEnv) {
				require.New(t).NoError(
					e.serverStore.DeletePeer(e.client.MarshalPublicKey()),
				)
			},
		},
		{
			name:   "session never established",
			reason: "unknown session",
			setup: func(t *testing.T, e *resumeEnv) {
				require.New(t).NoError(e.serverStore.DeleteMeta(
					e.sessionID, storage.EstablishedAtKey,
				))
			},
		},
		{
			name:    "signed by another key",
			reason:  "invalid signature",
			request: signedBy(byOther, validRequest),
		},
		{
			name:   "session expired",
			reason: "session expired",
			setup: func(_ *testing.T, e *resumeEnv) {
				e.clock.Advance(resumptionGracePeriod + time.Minute)
			},
		},
		{
			name:   "token not issued",
			reason: "token invalid",
			request: signedBy(byClient, func(e *resumeEnv) []byte {
				return resumeRequest(
					e.sessionID, bytes.Repeat([]byte{0x24}, len(e.token)),
				)
			}),
		},
		{
			// An accepted request uses up its token even when the resumed
			// handshake never happens, so the token cannot be replayed.
			name:   "token replayed",
			reason: "token invalid",
			setup: func(t *testing.T, e *resumeEnv) {
				a := require.New(t)
				before := tokenCount(e.storedTokens(a))
				ans := e.requestResume(t, e.client, validRequest(e))
				a.NoError(ans.readErr)
				a.True(ans.accepted)
				a.Equal(before-1, tokenCount(e.storedTokens(a)))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			e := newResumeEnv(t)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			request := tc.request
			if request == nil {
				request = signedBy(byClient, validRequest)
			}
			signer, data := request(e)
			before := e.storedTokens(a)

			ans := e.requestResume(t, signer, data, tc.opts...)
			a.False(ans.accepted)
			a.NoError(ans.readErr)
			// The dialer learns nothing about which check failed.
			a.Equal("resumption not available", ans.reason)
			a.ErrorContains(ans.serveErr, "resume rejected: "+tc.reason)
			a.Equal(before, e.storedTokens(a), "a token was consumed")
		})
	}
}
