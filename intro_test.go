package kamune

import (
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestIntroduce(t *testing.T) {
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

	var sendErr1 error
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		sendErr1 = sendIntroduction(conn1, attest1, rand.Text(), "1.0.0")
	}()
	st2, err := readSignedTransport(conn2)
	a.NoError(err)
	<-done1
	a.NoError(sendErr1)
	route2, err := routeFromST(st2)
	a.NoError(err)
	a.Equal(route2, RouteIdentity)
	peer, version, err := receiveIntroduction(st2)
	a.NoError(err)
	a.Equal(attest1.MarshalPublicKey(), peer.PublicKey)
	a.Equal("1.0.0", version)

	var sendErr2 error
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		sendErr2 = sendIntroduction(conn2, attest2, rand.Text(), "1.0.0")
	}()
	st1, err := readSignedTransport(conn1)
	a.NoError(err)
	<-done2
	a.NoError(sendErr2)
	route1, err := routeFromST(st1)
	a.NoError(err)
	a.True(route1 == RouteIdentity || route1 == RouteInvalid)
	peer, version, err = receiveIntroduction(st1)
	a.NoError(err)
	a.Equal(attest2.MarshalPublicKey(), peer.PublicKey)
	a.Equal("1.0.0", version)
}

func TestValidatePeerName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"empty", "", true},
		{"ascii", "alice", true},
		{"default fingerprint", strings.Repeat("A", 43), true},
		{"at the limit", strings.Repeat("a", MaxPeerNameLength), true},
		{"persian with zwnj", "علی\u200Cرضا", true},
		{"emoji with zwj", "👩\u200D💻 dev", true},
		{"emoji with variation selector", "❤\uFE0F bob", true},
		{"over the limit", strings.Repeat("a", MaxPeerNameLength+1), false},
		{"multi-byte over the limit", strings.Repeat("é", 33), false},
		{"invalid utf-8", "bob\xff", false},
		{"newline", "bob\nalice", false},
		{"tab", "bob\talice", false},
		{"nul", "bob\x00", false},
		{"ansi escape", "\x1b[31mbob", false},
		{"del", "bob\x7f", false},
		{"c1 control", "bob\u009b", false},
		{"right-to-left override", "bob\u202Egnp.exe", false},
		{"right-to-left isolate", "bob\u2067", false},
		{"pop directional isolate", "bob\u2069", false},
		{"left-to-right mark", "bob\u200E", false},
		{"arabic letter mark", "bob\u061C", false},
		{"zero-width space", "b\u200Bob", false},
		{"word joiner", "b\u2060ob", false},
		{"byte order mark", "\uFEFFbob", false},
		{"soft hyphen", "bo\u00ADb", false},
		{"tag character", "bob\U000e0041", false},
		{"line separator", "bob\u2028alice", false},
		{"paragraph separator", "bob\u2029alice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			err := ValidatePeerName(tt.input)
			if tt.valid {
				a.NoError(err)
				return
			}
			a.ErrorIs(err, ErrInvalidPeerName)
		})
	}
}

// signedIntroduction builds the signed introduction that sendIntroduction
// would send, with the given name.
func signedIntroduction(
	t *testing.T, at *attest.Attest, name string,
) *pb.SignedTransport {
	t.Helper()
	a := require.New(t)
	msg, err := proto.Marshal(&pb.Introduce{
		Name:       name,
		PublicKey:  at.MarshalPublicKey(),
		AppVersion: AppVersion,
	})
	a.NoError(err)
	md, err := proto.Marshal(&pb.Metadata{Route: RouteIdentity.ToProto()})
	a.NoError(err)
	sig, err := at.Sign(signingInput(md, msg))
	a.NoError(err)
	return &pb.SignedTransport{Data: msg, Signature: sig, Metadata: md}
}

func TestReceiveIntroductionRejectsInvalidName(t *testing.T) {
	at, err := attest.New()
	require.New(t).NoError(err)

	tests := []struct {
		name  string
		input string
	}{
		{"oversized", strings.Repeat("x", 60*1024)},
		{"right-to-left override", "Bob\u202E"},
		{"terminal escape", "\x1b]0;pwned\x07Bob"},
		{"newline", "Bob\nverified: yes"},
		{"zero-width space", "B\u200Bob"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			st := signedIntroduction(t, at, tt.input)
			peer, _, err := receiveIntroduction(st)
			a.ErrorIs(err, ErrInvalidPeerName)
			a.Nil(peer)
		})
	}

	t.Run("valid name", func(t *testing.T) {
		a := require.New(t)
		st := signedIntroduction(t, at, "Bob")
		peer, version, err := receiveIntroduction(st)
		a.NoError(err)
		a.Equal("Bob", peer.Name)
		a.Equal(AppVersion, version)
	})
}

func TestNameOptionsRejectInvalidName(t *testing.T) {
	a := require.New(t)
	store := newTransportTestStorage(t)
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	bad := "Bob\u202E"

	_, err := NewDialer("", store, accept, DialWithClientName(bad))
	a.ErrorIs(err, ErrInvalidPeerName)
	_, err = NewServer(
		"", nil, store, accept,
		ServeWithServerName(bad),
		ServeWithListener(newTestListener(nil)),
	)
	a.ErrorIs(err, ErrInvalidPeerName)

	d, err := NewDialer("", store, accept, DialWithClientName("Bob"))
	a.NoError(err)
	a.Equal("Bob", d.clientName)
}
