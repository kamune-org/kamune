package kamune

import (
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

type Peer struct {
	Name      string
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
	var identity attest.Identity
	if err = identity.UnmarshalText([]byte(p.Identity.String())); err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	pubKey, err := identity.ParsePublicKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &Peer{
		Name:      p.Name,
		PublicKey: pubKey,
		Identity:  identity,
		FirstSeen: p.FirstSeen.AsTime(),
	}, nil
}

func (s *Storage) TrustPeer(peer *Peer) error {
	pubKey := peer.PublicKey.Marshal()
	p := &pb.Peer{
		Name:      peer.Name,
		Identity:  pb.Identity(peer.Identity),
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
