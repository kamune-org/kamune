package kamune

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
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

// TestTransport_EncryptFitsUint16 asserts that the largest bucket
// plus encryption overhead equals math.MaxUint16.
func TestTransport_EncryptFitsUint16(t *testing.T) {
	a := require.New(t)
	a.Equal(
		math.MaxUint16-encryptionOverhead, frameTargetSize,
		"sanity: frameTargetSize + encryptionOverhead == math.MaxUint16",
	)
	a.Equal(
		frameTargetSize, paddingBuckets[len(paddingBuckets)-1],
		"sanity: last bucket must be frameTargetSize",
	)
	a.LessOrEqual(
		frameTargetSize+encryptionOverhead, math.MaxUint16,
		"last bucket + AEAD must fit math.MaxUint16",
	)
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
