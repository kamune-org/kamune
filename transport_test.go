package kamune

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	relaypb "github.com/kamune-org/kamune/pkg/relayconn/pb"
	"github.com/kamune-org/kamune/pkg/storage"
)

type queuedConn struct {
	closed bool
	frames [][]byte
	err    error
}

func (c *queuedConn) ReadBytes() ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	if len(c.frames) == 0 {
		return nil, io.EOF
	}
	frame := c.frames[0]
	c.frames = c.frames[1:]
	return frame, nil
}

func (*queuedConn) WriteBytes([]byte) error     { return nil }
func (*queuedConn) SetDeadline(time.Time) error { return nil }
func (c *queuedConn) Close() error {
	c.closed = true
	return nil
}

func incomingTransport(
	t *testing.T, route Route, sequence uint64, message Transferable,
) *Transport {
	t.Helper()
	a := require.New(t)

	att, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)
	cipher, err := enigma.NewEnigma(
		[]byte("transport test secret"),
		[]byte("transport salt"),
		[]byte("transport info"),
	)
	a.NoError(err)
	payload, _, err := serde.serialize(message, route, sequence)
	a.NoError(err)

	conn := &queuedConn{frames: [][]byte{cipher.Encrypt(payload)}}
	tr := newTransport(conn, serde, "test-session", cipher, cipher)
	tr.established = true
	return tr
}

func TestReceivePayload_RoundTrip(t *testing.T) {
	a := require.New(t)
	want := []byte("hello")
	tr := incomingTransport(t, RouteExchangeMessages, 1, Bytes(want))

	md, raw, err := tr.ReceivePayload()
	a.NoError(err)
	a.Equal(RouteExchangeMessages, md.Route())
	var got wrapperspb.BytesValue
	a.NoError(proto.Unmarshal(raw, &got))
	a.Equal(want, got.GetValue())
}

func TestReceive_ErrClosedPipeIsConnClosed(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteSessionData, 1, Bytes([]byte("x")))
	qc := tr.conn.(*queuedConn)
	qc.frames = nil
	qc.err = io.ErrClosedPipe

	_, err := tr.Receive(Bytes(nil))
	a.ErrorIs(err, ErrConnClosed)
}

func TestReceive_WrappedErrClosedPipeIsConnClosed(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteSessionData, 1, Bytes([]byte("x")))
	qc := tr.conn.(*queuedConn)
	qc.frames = nil
	qc.err = fmt.Errorf("reading message: %w", io.ErrClosedPipe)

	_, err := tr.Receive(Bytes(nil))
	a.ErrorIs(err, ErrConnClosed)
}

func TestReceive_ConnDropIsConnClosed(t *testing.T) {
	cases := []struct {
		err  error
		name string
	}{
		{
			name: "connection reset",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: os.NewSyscallError("read", syscall.ECONNRESET),
			},
		},
		{
			name: "connection aborted",
			err:  fmt.Errorf("reading: %w", syscall.ECONNABORTED),
		},
		{
			name: "broken pipe",
			err:  fmt.Errorf("reading: %w", syscall.EPIPE),
		},
		{
			name: "truncated frame",
			err:  fmt.Errorf("reading message: %w", io.ErrUnexpectedEOF),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			tr := incomingTransport(t, RouteSessionData, 1, Bytes(nil))
			qc := tr.conn.(*queuedConn)
			qc.frames = nil
			qc.err = tc.err

			_, err := tr.Receive(Bytes(nil))
			a.ErrorIs(err, ErrConnClosed)
		})
	}
}

// TestReceive_TCPResetIsConnClosed has the peer abort a real TCP connection
// with a reset.
func TestReceive_TCPResetIsConnClosed(t *testing.T) {
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = ln.Close() })

	dialed := make(chan struct{})
	reset := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			reset <- err
			return
		}
		// Reset only after Dial has returned, or Dial itself may fail.
		<-dialed
		tc := c.(*net.TCPConn)
		if err := tc.SetLinger(0); err != nil {
			reset <- err
			return
		}
		reset <- tc.Close()
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	close(dialed)
	a.NoError(err)
	t.Cleanup(func() { _ = c.Close() })
	a.NoError(<-reset)

	tr := newTransport(newConn(c), nil, "test-session", nil, nil)
	_, _, err = tr.ReceivePayload()
	a.ErrorIs(err, ErrConnClosed)
}

// TestReceive_FatalFrameTerminatesTransport checks that a frame that fails
// decryption or verification, or a RouteCloseTransport frame, closes the
// connection and that no frame queued behind it is processed.
func TestReceive_FatalFrameTerminatesTransport(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	other, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)
	forger := newSignedSerde(att.MarshalPublicKey(), other)
	cipher, err := enigma.NewEnigma(
		[]byte("terminate secret"),
		[]byte("terminate salt"),
		[]byte("terminate info"),
	)
	a.NoError(err)
	frame := func(s *signedSerde, route Route, seq uint64) []byte {
		payload, _, err := s.serialize(Bytes([]byte("data")), route, seq)
		a.NoError(err)
		return cipher.Encrypt(payload)
	}

	cases := []struct {
		want  error
		name  string
		first []byte
		next  []byte
	}{
		{
			name:  "decryption failure",
			first: bytes.Repeat([]byte{0x5a}, 64),
			next:  frame(serde, RouteExchangeMessages, 1),
		},
		{
			name:  "invalid signature",
			want:  ErrInvalidSignature,
			first: frame(forger, RouteExchangeMessages, 1),
			next:  frame(serde, RouteExchangeMessages, 1),
		},
		{
			name:  "out of sequence",
			want:  ErrOutOfSync,
			first: frame(serde, RouteExchangeMessages, 2),
			next:  frame(serde, RouteExchangeMessages, 1),
		},
		{
			name:  "unexpected route",
			want:  ErrUnexpectedRoute,
			first: frame(serde, RouteSendChallenge, 1),
			next:  frame(serde, RouteExchangeMessages, 2),
		},
		{
			name:  "peer close",
			want:  ErrPeerDisconnected,
			first: frame(serde, RouteCloseTransport, 1),
			next:  frame(serde, RouteExchangeMessages, 2),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			conn := &queuedConn{frames: [][]byte{tc.first, tc.next}}
			tr := newTransport(conn, serde, "test-session", cipher, cipher)
			tr.established = true
			store := newTransportTestStorage(t)
			tr.storage = store
			a.NoError(store.PutSessionResumption(
				tr.sessionID, nil, [][]byte{bytes.Repeat([]byte{7}, 32)}, false,
			))

			_, err := tr.Receive(Bytes(nil))
			a.Error(err)
			if tc.want != nil {
				a.ErrorIs(err, tc.want)
			}
			a.True(conn.closed)
			_, popErr := store.PopList(
				tr.sessionID, storage.ResumptionTokensKey,
			)
			a.ErrorIs(popErr, storage.ErrNotFound, "session stays resumable")

			_, again := tr.Receive(Bytes(nil))
			a.Equal(err, again)
			a.Len(conn.frames, 1, "queued frame must not be read")

			_, err = tr.Send(Bytes(nil), RouteExchangeMessages)
			a.ErrorIs(err, ErrConnClosed)
			a.NoError(tr.Close())
		})
	}
}

// handoffConn hands queued frames to concurrent readers. The reader that
// takes the first frame does not return it until a second ReadBytes call has
// taken the next one, so that without receive serialization the second frame
// reaches the sequence check first.
type handoffConn struct {
	taken  chan struct{}
	second chan struct{}
	frames [][]byte
	next   int
	mu     sync.Mutex
}

func (c *handoffConn) ReadBytes() ([]byte, error) {
	c.mu.Lock()
	if c.next >= len(c.frames) {
		c.mu.Unlock()
		return nil, io.EOF
	}
	i := c.next
	c.next++
	frame := c.frames[i]
	c.mu.Unlock()

	switch i {
	case 0:
		close(c.taken)
		select {
		case <-c.second:
			time.Sleep(50 * time.Millisecond)
		case <-time.After(200 * time.Millisecond):
		}
	case 1:
		close(c.second)
	}
	return frame, nil
}

func (*handoffConn) WriteBytes([]byte) error     { return nil }
func (*handoffConn) SetDeadline(time.Time) error { return nil }
func (*handoffConn) Close() error                { return nil }

func TestReceive_ConcurrentCallersKeepSequence(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)
	cipher, err := enigma.NewEnigma(
		[]byte("concurrent secret"),
		[]byte("concurrent salt"),
		[]byte("concurrent info"),
	)
	a.NoError(err)

	conn := &handoffConn{
		taken:  make(chan struct{}),
		second: make(chan struct{}),
	}
	for seq := uint64(1); seq <= 2; seq++ {
		msg := Bytes([]byte{byte(seq)})
		payload, _, err := serde.serialize(msg, RouteExchangeMessages, seq)
		a.NoError(err)
		conn.frames = append(conn.frames, cipher.Encrypt(payload))
	}
	tr := newTransport(conn, serde, "test-session", cipher, cipher)
	tr.established = true

	type result struct {
		err error
		seq uint64
	}
	receive := func(out chan<- result) {
		md, err := tr.Receive(Bytes(nil))
		if err != nil {
			out <- result{err: err}
			return
		}
		out <- result{seq: md.SequenceNum()}
	}
	first := make(chan result, 1)
	second := make(chan result, 1)
	go receive(first)
	<-conn.taken
	go receive(second)

	r1, r2 := <-first, <-second
	a.NoError(r1.err)
	a.NoError(r2.err)
	a.Equal(uint64(1), r1.seq)
	a.Equal(uint64(2), r2.seq)
}

func TestTransportReceiveValidatesSequenceBeforeClose(t *testing.T) {
	a := require.New(t)
	transport := incomingTransport(t, RouteCloseTransport, 2, Bytes(nil))

	_, err := transport.Receive(Bytes(nil))
	a.ErrorIs(err, ErrOutOfSync)
	a.Equal(uint64(0), transport.recvSequence)
	a.True(transport.conn.(*queuedConn).closed)
}

func TestTransportReceiveAdvancesSequenceForClose(t *testing.T) {
	a := require.New(t)
	transport := incomingTransport(t, RouteCloseTransport, 1, Bytes(nil))

	_, err := transport.Receive(Bytes(nil))
	a.ErrorIs(err, ErrPeerDisconnected)
	a.Equal(uint64(1), transport.recvSequence)
}

func TestTransportReceiveRejectsInvalidRouteBeforeMutatingMessage(
	t *testing.T,
) {
	a := require.New(t)
	transport := incomingTransport(t, RouteInvalid, 1, Bytes([]byte("replacement")))
	dst := Bytes([]byte("original"))

	_, err := transport.Receive(dst)
	a.ErrorIs(err, ErrInvalidRoute)
	a.Equal([]byte("original"), dst.GetValue())
	a.Equal(uint64(1), transport.recvSequence)
}

func FuzzTransportReceiveEnvelope(f *testing.F) {
	att, err := attest.New()
	if err != nil {
		f.Fatal(err)
	}
	serde := newSignedSerde(att.MarshalPublicKey(), att)
	cipher, err := enigma.NewEnigma(
		[]byte("transport fuzz secret"),
		[]byte("transport fuzz salt"),
		[]byte("transport fuzz info"),
	)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(int32(RouteExchangeMessages), uint64(1), []byte("message"))
	f.Add(int32(RouteCloseTransport), uint64(1), []byte{})
	f.Add(int32(RouteInvalid), uint64(1), []byte("invalid route"))
	f.Add(int32(RoutePing), uint64(1), []byte{})
	f.Add(int32(RoutePing), uint64(2), []byte("wrong sequence"))
	f.Add(int32(RouteSessionData+1), uint64(1), []byte("unknown route"))

	f.Fuzz(func(t *testing.T, routeValue int32, sequence uint64, data []byte) {
		if len(data) > 4*1024 {
			t.Skip()
		}
		a := require.New(t)
		route := Route(routeValue)
		payload, _, err := serde.serialize(Bytes(data), route, sequence)
		a.NoError(err)

		conn := &queuedConn{frames: [][]byte{cipher.Encrypt(payload)}}
		transport := newTransport(
			conn, serde, "fuzz-session", cipher, cipher,
		)
		transport.established = true
		original := []byte("original")
		dst := Bytes(bytes.Clone(original))

		metadata, receiveErr := transport.Receive(dst)
		switch {
		case sequence != 1:
			a.ErrorIs(receiveErr, ErrOutOfSync)
			a.Nil(metadata)
			a.Equal(uint64(0), transport.recvSequence)
			a.Equal(original, dst.GetValue())
			a.True(conn.closed)
		case !route.IsValid():
			a.ErrorIs(receiveErr, ErrInvalidRoute)
			a.Nil(metadata)
			a.Equal(uint64(1), transport.recvSequence)
			a.Equal(original, dst.GetValue())
		case !route.isSessionRoute():
			a.ErrorIs(receiveErr, ErrUnexpectedRoute)
			a.Nil(metadata)
			a.Equal(uint64(1), transport.recvSequence)
			a.Equal(original, dst.GetValue())
			a.True(conn.closed)
		case route == RouteCloseTransport:
			a.ErrorIs(receiveErr, ErrPeerDisconnected)
			a.Nil(metadata)
			a.Equal(uint64(1), transport.recvSequence)
			a.Equal(original, dst.GetValue())
		default:
			a.NoError(receiveErr)
			a.NotNil(metadata)
			a.Equal(uint64(1), transport.recvSequence)
			a.True(bytes.Equal(data, dst.GetValue()))
		}
	})
}

// TestTransport_PadToBucket asserts that serialize produces payloads
// that land on a bucket boundary and never exceed frameTargetSize.
func TestTransport_PadToBucket(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)

	cases := []struct {
		msg  proto.Message
		name string
	}{
		{&pb.Handshake{SessionKey: "x"}, "tiny"},
		{
			&pb.Handshake{
				Key:        make([]byte, 1024),
				Salt:       make([]byte, handshakeSaltSize),
				SessionKey: "0123456789",
			},
			"small",
		},
		{
			&pb.Handshake{
				Key:        make([]byte, 16*1024),
				Salt:       make([]byte, handshakeSaltSize),
				SessionKey: "0123456789",
			},
			"medium",
		},
		{
			&pb.Handshake{
				Key:        make([]byte, int(maxTransportSize)-64),
				Salt:       make([]byte, handshakeSaltSize),
				SessionKey: "0123456789",
			},
			"near_max",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			payload, _, err := serde.serialize(tc.msg, RouteExchangeMessages, 1)
			a.NoError(err)
			a.LessOrEqual(
				len(payload), frameTargetSize,
				"payload (%d bytes) must fit frameTargetSize (%d)",
				len(payload), frameTargetSize,
			)
			a.Contains(paddingBuckets, len(payload),
				"payload size must land on a bucket boundary")
		})
	}
}

// TestTransport_FrameBudget asserts that the largest bucket plus encryption
// overhead equals maxFrameSize and leaves transportReserve bytes of headroom
// below math.MaxUint16.
func TestTransport_FrameBudget(t *testing.T) {
	a := require.New(t)
	a.Equal(
		frameTargetSize, paddingBuckets[len(paddingBuckets)-1],
		"sanity: last bucket must be frameTargetSize",
	)
	a.Equal(
		maxFrameSize, frameTargetSize+encryptionOverhead,
		"last bucket + AEAD must equal maxFrameSize",
	)
	a.Equal(
		math.MaxUint16, maxFrameSize+transportReserve,
		"maxFrameSize must leave transportReserve below math.MaxUint16",
	)
	a.Less(maxTransportSize, frameTargetSize)
}

// TestTransport_LargestFrameFitsRelayWrapping sends the largest padded
// session frame through the wrapping the relay transport applies (a relay
// Frame envelope sealed by an HPKE channel) over a 2-byte length-prefixed
// conn and checks that it arrives intact.
func TestTransport_LargestFrameFitsRelayWrapping(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)
	cipher, err := enigma.NewEnigma(
		[]byte("relay budget secret"),
		[]byte("relay budget salt"),
		[]byte("relay budget info"),
	)
	a.NoError(err)

	// A message near the user cap always lands on the last bucket.
	msg := Bytes(make([]byte, maxTransportSize-64))
	payload, _, err := serde.serialize(msg, RouteExchangeMessages, 1)
	a.NoError(err)
	a.Len(payload, frameTargetSize)
	frame := cipher.Encrypt(payload)
	a.Len(frame, maxFrameSize)

	wrapped, err := proto.Marshal(&relaypb.Frame{
		Kind: &relaypb.Frame_Msg{Msg: &relaypb.Message{Data: frame}},
	})
	a.NoError(err)

	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	type result struct {
		ch  *exchange.Channel
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		ch, err := exchange.Accept(newConn(right))
		accepted <- result{ch, err}
	}()
	sender, err := exchange.Initiate(newConn(left))
	a.NoError(err)
	res := <-accepted
	a.NoError(res.err)

	type readResult struct {
		err  error
		data []byte
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := res.ch.ReadBytes()
		read <- readResult{err, data}
	}()
	a.NoError(sender.WriteBytes(wrapped))
	got := <-read
	a.NoError(got.err)

	var out relaypb.Frame
	a.NoError(proto.Unmarshal(got.data, &out))
	a.Equal(frame, out.GetMsg().GetData())
}

func TestTransportReceiveRejectsHandshakeRoute(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteIdentity, 1, Bytes(nil))

	_, err := tr.Receive(Bytes(nil))
	a.ErrorIs(err, ErrUnexpectedRoute)
	a.True(tr.conn.(*queuedConn).closed)
}

func TestTransportSendRejectsHandshakeRoute(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteExchangeMessages, 1, Bytes(nil))

	_, err := tr.Send(Bytes(nil), RouteSendChallenge)
	a.ErrorIs(err, ErrUnexpectedRoute)
}

func TestTransportChallengeRoutesBeforeEstablished(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteSendChallenge, 1, Bytes([]byte("c")))
	tr.established = false

	_, err := tr.Receive(Bytes(nil))
	a.NoError(err)

	_, err = tr.Send(Bytes([]byte("c")), RouteVerifyChallenge)
	a.NoError(err)

	_, err = tr.Send(Bytes(nil), RouteExchangeMessages)
	a.ErrorIs(err, ErrUnexpectedRoute)
}

func TestTransportSessionRoutesRejectedBeforeEstablished(t *testing.T) {
	a := require.New(t)
	tr := incomingTransport(t, RouteExchangeMessages, 1, Bytes(nil))
	tr.established = false

	_, err := tr.Receive(Bytes(nil))
	a.ErrorIs(err, ErrUnexpectedRoute)
	a.True(tr.conn.(*queuedConn).closed)
}

func TestTransportCloseClearsResumptionTokens(t *testing.T) {
	a := require.New(t)
	store := newTransportTestStorage(t)
	tr := incomingTransport(t, RouteExchangeMessages, 1, Bytes(nil))
	tr.storage = store
	tok := bytes.Repeat([]byte{0x11}, 32)
	a.NoError(store.PutSessionResumption(
		tr.sessionID, nil, [][]byte{tok}, false,
	))

	a.NoError(tr.Close())
	_, err := store.PopList(tr.sessionID, storage.ResumptionTokensKey)
	a.ErrorIs(err, storage.ErrNotFound)
}

func TestTransportReceiveCloseClearsResumptionTokens(t *testing.T) {
	a := require.New(t)
	store := newTransportTestStorage(t)
	tr := incomingTransport(t, RouteCloseTransport, 1, Bytes(nil))
	tr.storage = store
	tok := bytes.Repeat([]byte{0x22}, 32)
	a.NoError(store.PutSessionResumption(
		tr.sessionID, nil, [][]byte{tok}, false,
	))

	_, err := tr.Receive(Bytes(nil))
	a.ErrorIs(err, ErrPeerDisconnected)
	_, err = store.PopList(tr.sessionID, storage.ResumptionTokensKey)
	a.ErrorIs(err, storage.ErrNotFound)
}

func newTransportTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-transport-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	store, err := storage.OpenStorage(
		storage.WithDBPath(f.Name()),
		storage.WithNoPassphrase(),
	)
	a.NoError(err)
	t.Cleanup(func() {
		_ = store.Close()
		_ = os.Remove(f.Name())
	})
	return store
}
