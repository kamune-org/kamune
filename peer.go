package kamune

import (
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/pkg/attest"
)

type Peer struct {
	Title     string
	PublicKey PublicKey
	Identity  attest.Identity
	FirstSeen time.Time
}

func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	key := sha3.Sum512(claim)
	data, err := s.store.GetEncrypted(key[:])
	if err != nil {
		return nil, fmt.Errorf("getting peer from storage: %w", err)
	}
	var p pb.Peer
	err = proto.Unmarshal(data, &p)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling peer: %w", err)
	}
	identity, err := attest.ParseIdentity(p.Identity)
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	pubKey, err := identity.ParsePublicKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &Peer{
		Title:     p.Title,
		PublicKey: pubKey,
		Identity:  identity,
		FirstSeen: p.FirstSeen.AsTime(),
	}, nil
}

func (s *Storage) TrustPeer(peer *Peer) error {
	pubKey := peer.PublicKey.Marshal()
	p := &pb.Peer{
		Title:     peer.Title,
		Identity:  peer.Identity.String(),
		PublicKey: pubKey,
		FirstSeen: timestamppb.New(peer.FirstSeen),
	}
	data, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	key := sha3.Sum512(pubKey)
	err = s.store.AddEncrypted(key[:], data)
	if err != nil {
		return fmt.Errorf("adding peer to storage: %w", err)
	}

	return nil
}
