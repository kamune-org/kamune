package kamune

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/store"
)

type Peer struct {
	FirstSeen time.Time
	PublicKey PublicKey
	Name      string
	Algorithm attest.Algorithm
}

var (
	ErrPeerExpired = errors.New("peer has been expired")

	peersBucket = []byte(store.PeersBucket)
)

func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	var (
		key  = sha3.Sum512(claim)
		data []byte
	)
	err := s.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(peersBucket, key[:])
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("getting peer from storage: %w", err)
	}
	var p pb.Peer
	err = proto.Unmarshal(data, &p)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling peer: %w", err)
	}

	if p.FirstSeen.AsTime().Add(s.expiryDuration).Before(time.Now()) {
		err = s.store.Command(func(c store.Command) error {
			return c.Delete(peersBucket, key[:])
		})
		if err != nil {
			slog.Warn(
				"failed to remove expired peer",
				slog.String("peer_name", p.GetName()),
				slog.Any("error", err),
			)
		}
		return nil, ErrPeerExpired
	}

	var a attest.Algorithm
	if err = a.UnmarshalText([]byte(p.Algorithm.String())); err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	pubKey, err := a.Identitfier().ParsePublicKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &Peer{
		Name:      p.Name,
		PublicKey: pubKey,
		Algorithm: a,
		FirstSeen: p.FirstSeen.AsTime(),
	}, nil
}

func (s *Storage) StorePeer(peer *Peer) error {
	pubKey := peer.PublicKey.Marshal()
	p := &pb.Peer{
		Name:      peer.Name,
		Algorithm: pb.Algorithm(peer.Algorithm),
		PublicKey: pubKey,
		FirstSeen: timestamppb.New(peer.FirstSeen),
	}
	data, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	key := sha3.Sum512(pubKey)
	err = s.store.Command(func(c store.Command) error {
		return c.AddEncrypted(peersBucket, key[:], data)
	})
	if err != nil {
		return fmt.Errorf("adding peer to storage: %w", err)
	}

	return nil
}
