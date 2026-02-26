package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/hossein1376/grape/errs"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/box/pb"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
	"github.com/kamune-org/kamune/relay/pkg/span"
)

var (
	ErrPeerNotFound = errors.New("peer not found")
)

// RefreshPeer renews the TTL on an existing peer registration. The peer is
// looked up by its public key. If found, the entry's TTL is reset to the
// configured register_ttl and the updated peer information is returned.
//
// Optionally, the caller may provide new addresses to replace the stored
// ones. If newAddr is nil or empty the existing addresses are preserved.
func (s *Service) RefreshPeer(
	pubKey []byte, newAddr []string,
) (*model.Peer, error) {
	ttl := s.cfg.Storage.RegisterTTL

	var result *model.Peer
	err := s.store.Command(func(c model.Command) error {
		data, err := c.Get(peersNS, pubKey)
		if err != nil {
			if errors.Is(err, storage.ErrMissing) {
				return errs.NotFound(errs.WithErr(ErrPeerNotFound))
			}
			return fmt.Errorf("getting peer: %w", err)
		}

		var p pb.Peer
		if err := proto.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("unmarshalling peer: %w", err)
		}

		// Update addresses if new ones are provided.
		if len(newAddr) > 0 {
			p.Address = newAddr
		}

		// Update the registration timestamp to now.
		p.RegisteredAt = timestamppb.New(time.Now())

		updated, err := proto.Marshal(&p)
		if err != nil {
			return fmt.Errorf("marshalling peer: %w", err)
		}

		// Re-store with a fresh TTL.
		if err := c.SetTTL(peersNS, pubKey, updated, ttl); err != nil {
			return fmt.Errorf("refreshing peer TTL: %w", err)
		}

		var id model.PeerID
		if err := id.UnmarshalBinary(p.ID); err != nil {
			return fmt.Errorf("parsing peer ID: %w", err)
		}

		result = &model.Peer{
			ID:           id,
			Identity:     attest.Algorithm(p.Identity),
			Address:      p.Address,
			RegisteredAt: p.RegisteredAt.AsTime(),
			ExpiresIn:    span.New(ttl),
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
