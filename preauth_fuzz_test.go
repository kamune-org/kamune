package kamune

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

func FuzzPreAuthEnvelopeValidation(f *testing.F) {
	at, err := attest.New()
	if err != nil {
		f.Fatal(err)
	}

	f.Add(true, int32(RouteIdentity), []byte("alice"), false, false, false)
	f.Add(false, int32(RouteResumeAccept), []byte("accepted"), false, false, false)
	f.Add(true, int32(RouteResumeRequest), []byte("wrong route"), false, false, false)
	f.Add(false, int32(RouteResumeAccept), []byte("tampered"), true, false, false)
	f.Add(true, int32(RouteIdentity), []byte{0xff}, false, true, false)
	f.Add(true, int32(RouteIdentity), []byte("malformed"), true, true, false)
	f.Add(false, int32(RouteResumeAccept), []byte{0xff}, false, false, true)

	f.Fuzz(func(
		t *testing.T,
		introduction bool,
		routeValue int32,
		body []byte,
		tamperSignature, rawMessage, rawMetadata bool,
	) {
		if len(body) > 4*1024 {
			t.Skip()
		}
		a := require.New(t)
		route := Route(routeValue)
		text := string(bytes.ToValidUTF8(body, []byte("?")))

		metadata := body
		if !rawMetadata {
			marshaled, marshalErr := proto.Marshal(&pb.Metadata{Route: route.ToProto()})
			a.NoError(marshalErr)
			metadata = marshaled
		}

		message := body
		if !rawMessage {
			var marshalErr error
			if introduction {
				message, marshalErr = proto.Marshal(&pb.Introduce{
					Name:       text,
					PublicKey:  at.MarshalPublicKey(),
					AppVersion: "fuzz",
				})
			} else {
				message, marshalErr = proto.Marshal(&pb.ResumeAccept{
					Accepted: len(body)%2 == 0,
					Reason:   text,
				})
			}
			a.NoError(marshalErr)
		}

		signature, err := at.Sign(signingInput(metadata, message))
		a.NoError(err)
		if tamperSignature {
			signature = append([]byte{}, signature...)
			signature[0] ^= 0xff
		}
		st := &pb.SignedTransport{
			Data:      message,
			Signature: signature,
			Metadata:  metadata,
		}

		effectiveRoute := RouteFromProto(route.ToProto())
		if introduction {
			peer, version, receiveErr := receiveIntroduction(st)
			switch {
			case rawMetadata:
				return
			case effectiveRoute != RouteIdentity:
				a.ErrorIs(receiveErr, ErrUnexpectedRoute)
			case rawMessage:
				return
			case tamperSignature:
				a.ErrorIs(receiveErr, ErrInvalidSignature)
			default:
				a.NoError(receiveErr)
				a.NotNil(peer)
				a.Equal(text, peer.Name)
				a.Equal(at.MarshalPublicKey(), peer.PublicKey)
				a.Equal("fuzz", version)
			}
			return
		}

		accepted, reason, receiveErr := parseResumeAccept(st, at.MarshalPublicKey())
		switch {
		case rawMetadata:
			return
		case effectiveRoute != RouteResumeAccept:
			a.ErrorIs(receiveErr, ErrUnexpectedRoute)
		case tamperSignature:
			a.ErrorIs(receiveErr, ErrInvalidSignature)
		case rawMessage:
			return
		default:
			a.NoError(receiveErr)
			a.Equal(len(body)%2 == 0, accepted)
			a.Equal(text, reason)
		}
	})
}
