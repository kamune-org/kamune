package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hossein1376/grape/errs"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/box/pb"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
	"github.com/kamune-org/kamune/relay/pkg/span"
)

const (
	peers = "peers"
)

var (
	ErrExistingPeer = errors.New("peer already exists")

	peersNS = model.NewNameSpace(peers)
)

func (s *Service) RegisterPeer(
	pubKey []byte, identity attest.Identity, addr string,
) (*model.Peer, error) {
	ttl := s.cfg.RegisterTTL
	peerID := model.PeerID(uuid.New())
	peerIDBytes, _ := peerID.MarshalBinary()
	p := pb.Peer{
		ID:           peerIDBytes,
		PublicKey:    pubKey,
		Identity:     pb.DSA(identity),
		Address:      addr,
		RegisteredAt: timestamppb.New(time.Now()),
	}
	peerBytes, err := proto.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("marshalling peer: %w", err)
	}
	err = s.store.Command(func(c model.Command) error {
		data, err := c.Get(peersNS, pubKey)
		switch {
		case err == nil:
			if err := proto.Unmarshal(data, &p); err != nil {
				return fmt.Errorf("unmarshalling peer: %w", err)
			}
			ttl = 0
			return errs.Conflict(ErrExistingPeer)
		case errors.Is(err, storage.ErrMissing):
			// continue
		default:
			return fmt.Errorf("checking peer's exists: %w", err)
		}
		err = c.SetTTL(peersNS, pubKey, peerBytes, ttl)
		if err != nil {
			return fmt.Errorf("inserting peer to storage: %w", err)
		}
		return nil
	})
	return &model.Peer{
		ID:           model.PeerID(p.ID),
		Address:      p.Address,
		Identity:     attest.Identity(p.Identity),
		RegisteredAt: p.RegisteredAt.AsTime(),
		ExpiresIn:    span.New(ttl),
	}, err
}

func (s *Service) InquiryPeer(pubKey []byte) (*model.Peer, error) {
	var p pb.Peer
	var ttl time.Duration
	err := s.store.Query(func(c model.Query) error {
		peerData, err := c.Get(peersNS, pubKey)
		if err != nil {
			if errors.Is(err, storage.ErrMissing) {
				return errs.NotFound(err)
			}
			return fmt.Errorf("getting peer: %w", err)
		}
		err = proto.Unmarshal(peerData, &p)
		if err != nil {
			return fmt.Errorf("unmarshalling peer: %w", err)
		}
		ttl, err = c.TTL(peersNS, pubKey)
		if err != nil {
			return fmt.Errorf("getting peer's TTL: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var id model.PeerID
	if err = id.UnmarshalBinary(p.ID); err != nil {
		return nil, fmt.Errorf("parsing peer ID: %w", err)
	}
	return &model.Peer{
		ID:           id,
		Identity:     attest.Identity(p.Identity),
		Address:      p.Address,
		RegisteredAt: p.RegisteredAt.AsTime(),
		ExpiresIn:    span.New(ttl),
	}, nil
}

func (s *Service) DeletePeer(pubKey []byte) error {
	return s.store.Command(func(c model.Command) error {
		return c.Delete(peersNS, pubKey)
	})
}
