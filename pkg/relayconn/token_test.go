package relayconn

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"os"
	"testing"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestTokenFromKeys_Deterministic(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	t1, err := TokenFromKeys(x, y)
	a.NoError(err)
	t2, err := TokenFromKeys(x, y)
	a.NoError(err)

	a.True(bytes.Equal(t1, t2), "TokenFromKeys must be deterministic for the same input pair")
}

func TestTokenFromKeys_OrderIndependent(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	t1, err := TokenFromKeys(x, y)
	a.NoError(err)
	t2, err := TokenFromKeys(y, x)
	a.NoError(err)

	a.True(bytes.Equal(t1, t2), "TokenFromKeys(A, B) must equal TokenFromKeys(B, A)")
}

func TestTokenFromKeys_DistinctPairs(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	z, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	tab, err := TokenFromKeys(x, y)
	a.NoError(err)
	tac, err := TokenFromKeys(x, z)
	a.NoError(err)

	a.False(bytes.Equal(tab, tac), "distinct peer pairs must produce distinct tokens")
}

func TestTokenFromKeys_Length32(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	tok, err := TokenFromKeys(x, y)
	a.NoError(err)
	a.Len(tok, 32, "token must be exactly 32 bytes")
}

func TestTokenFromKeys_WrongSizeRejected(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	_, err = TokenFromKeys(x[:0], y)
	a.ErrorIs(err, ErrInvalidKeySize)

	_, err = TokenFromKeys(x, y[:10])
	a.ErrorIs(err, ErrInvalidKeySize)

	_, err = TokenFromKeys(x, append(y, 0x00))
	a.ErrorIs(err, ErrInvalidKeySize)
}

func TestValidateUserToken_RejectsTooShort(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(nil), ErrTokenTooShort)
	a.ErrorIs(ValidateUserToken(make([]byte, 15)), ErrTokenTooShort)
	a.ErrorIs(ValidateUserToken(make([]byte, 33)), ErrTokenTooShort)
}

func TestValidateUserToken_RejectsAllZeros(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(make([]byte, 32)), ErrTokenInsufficientEntropy)
}

func TestValidateUserToken_RejectsConstantByte(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(bytes.Repeat([]byte{0xAA}, 32)), ErrTokenInsufficientEntropy)
}

func TestValidateUserToken_AcceptsHighEntropy(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	tok, err := TokenFromKeys(x, y)
	a.NoError(err)
	a.NoError(ValidateUserToken(tok))
}

type localListener struct{ net.Listener }

func (l localListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(c), nil
}

func dialEstablished(
	t *testing.T, handler kamune.HandlerFunc,
) *kamune.Transport {
	t.Helper()
	a := require.New(t)
	open := func() *storage.Storage {
		t.Helper()
		f, err := os.CreateTemp("", "kamune-token-*.db")
		a.NoError(err)
		a.NoError(f.Close())
		s, err := storage.OpenStorage(
			storage.WithDBPath(f.Name()),
			storage.WithNoPassphrase(),
		)
		a.NoError(err)
		t.Cleanup(func() {
			_ = s.Close()
			_ = os.Remove(f.Name())
		})
		return s
	}
	verify := func(st *storage.Storage, peer *storage.Peer) error {
		return st.StorePeer(peer)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	srv, err := kamune.NewServer(
		"",
		handler,
		open(),
		verify,
		kamune.ServeWithListener(localListener{Listener: ln}),
	)
	a.NoError(err)
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ListenAndServe() }()

	dialer, err := kamune.NewDialer(
		ln.Addr().String(),
		open(),
		verify,
		kamune.DialWithTCP(),
	)
	a.NoError(err)
	tr, err := dialer.Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestBeginRelayTokenExchange_LeavesTheNextFrame(t *testing.T) {
	a := require.New(t)
	tr := dialEstablished(t, func(peer *kamune.Transport) error {
		_, err := peer.Send(
			kamune.Bytes([]byte("hello")),
			kamune.RouteExchangeMessages,
		)
		if err != nil {
			return err
		}
		var ignore pb.SessionData
		_, _ = peer.Receive(&ignore)
		return nil
	})

	_, err := BeginRelayTokenExchange(tr)
	a.NoError(err)
	msg := kamune.Bytes(nil)
	_, err = tr.Receive(msg)
	a.NoError(err)
	a.Equal([]byte("hello"), msg.GetValue())
}

func TestRelayTokenPending_BothSidesMatch(t *testing.T) {
	a := require.New(t)
	type result struct {
		tokens [tokenPoolSize][32]byte
		err    error
	}
	serverRes := make(chan result, 1)
	tr := dialEstablished(t, func(peer *kamune.Transport) error {
		pending, err := BeginRelayTokenExchange(peer)
		if err != nil {
			serverRes <- result{err: err}
			return err
		}
		var msg pb.SessionData
		if _, err = peer.Receive(&msg); err != nil {
			serverRes <- result{err: err}
			return err
		}
		key, ok := SessionDataPeerKey(&msg)
		if !ok {
			err = ErrECDHPeerKeyMissing
			serverRes <- result{err: err}
			return err
		}
		tokens, err := pending.Complete(key)
		serverRes <- result{tokens: tokens, err: err}
		return err
	})

	pending, err := BeginRelayTokenExchange(tr)
	a.NoError(err)
	md, raw, err := tr.ReceivePayload()
	a.NoError(err)
	a.Equal(kamune.RouteSessionData, md.Route())
	local, err := CompleteRelayTokenPayload(pending, raw)
	a.NoError(err)

	remote := <-serverRes
	a.NoError(remote.err)
	a.Equal(remote.tokens, local)
	var zero [tokenPoolSize][32]byte
	a.NotEqual(zero, local)
}

// TestDeriveRelayTokens checks that both peers derive the same pool and
// that a frame on another route is reported by route instead of being
// parsed as the peer's SessionData.
func TestDeriveRelayTokens(t *testing.T) {
	type result struct {
		err    error
		tokens [tokenPoolSize][32]byte
	}
	tests := []struct {
		peer    func(*kamune.Transport) result
		wantErr error
		name    string
		errText string
	}{
		{
			name: "both sides",
			peer: func(tr *kamune.Transport) result {
				tokens, err := DeriveRelayTokens(tr)
				return result{tokens: tokens, err: err}
			},
		},
		{
			name: "chat first",
			peer: func(tr *kamune.Transport) result {
				_, err := tr.Send(
					kamune.Bytes([]byte("hello")),
					kamune.RouteExchangeMessages,
				)
				var ignore pb.SessionData
				_, _ = tr.Receive(&ignore)
				return result{err: err}
			},
			wantErr: kamune.ErrUnexpectedRoute,
			errText: kamune.RouteExchangeMessages.String(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			peerRes := make(chan result, 1)
			tr := dialEstablished(t, func(peer *kamune.Transport) error {
				res := tc.peer(peer)
				peerRes <- res
				return res.err
			})

			local, err := DeriveRelayTokens(tr)
			remote := <-peerRes
			a.NoError(remote.err)
			if tc.wantErr != nil {
				a.ErrorIs(err, tc.wantErr)
				a.ErrorContains(err, tc.errText)
				return
			}
			a.NoError(err)
			a.Equal(remote.tokens, local)
			var zero [tokenPoolSize][32]byte
			a.NotEqual(zero, local)
		})
	}
}
