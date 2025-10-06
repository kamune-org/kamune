package kamune

import (
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/store"
)

type Peer struct {
	Name      string
	PublicKey PublicKey
	Algorithm attest.Algorithm
	FirstSeen time.Time
}

func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	var (
		key  = sha3.Sum512(claim)
		data []byte
	)
	err := s.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(key[:])
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
		return c.AddEncrypted(key[:], data)
	})
	if err != nil {
		return fmt.Errorf("adding peer to storage: %w", err)
	}

	return nil
}
