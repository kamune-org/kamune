package storage

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/store"
	"github.com/kamune-org/kamune/pkg/attest"
)

type Peer struct {
	FirstSeen time.Time
	LastSeen  time.Time
	PublicKey attest.PublicKey
	Name      string
	Algorithm attest.Algorithm
}

var (
	ErrPeerExpired = errors.New("peer has been expired")

	peersBucket = []byte(store.PeersBucket)
)

// peerKey returns the storage key for a peer identified by the given claim
// (typically the marshalled public key). The key is the SHA3-512 hash of the
// claim.
func peerKey(claim []byte) []byte {
	h := sha3.Sum512(claim)
	return h[:]
}

func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	key := peerKey(claim)

	var data []byte
	err := s.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(peersBucket, key)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("getting peer from storage: %w", err)
	}

	var p pb.Peer
	if err = proto.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshaling peer: %w", err)
	}

	if p.FirstSeen.AsTime().Add(s.expiryDuration).Before(time.Now()) {
		err = s.store.Command(func(c store.Command) error {
			return c.Delete(peersBucket, key)
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

	var lastSeen time.Time
	if p.LastSeen != nil {
		lastSeen = p.LastSeen.AsTime()
	}

	return &Peer{
		Name:      p.Name,
		PublicKey: pubKey,
		Algorithm: a,
		FirstSeen: p.FirstSeen.AsTime(),
		LastSeen:  lastSeen,
	}, nil
}

func (s *Storage) StorePeer(peer *Peer) error {
	pubKey := peer.PublicKey.Marshal()

	now := time.Now()
	firstSeen := peer.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	lastSeen := peer.LastSeen
	if lastSeen.IsZero() {
		lastSeen = now
	}

	p := &pb.Peer{
		Name:      peer.Name,
		Algorithm: pb.Algorithm(peer.Algorithm),
		PublicKey: pubKey,
		FirstSeen: timestamppb.New(firstSeen),
		LastSeen:  timestamppb.New(lastSeen),
	}
	data, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	key := peerKey(pubKey)
	err = s.store.Command(func(c store.Command) error {
		return c.AddEncrypted(peersBucket, key, data)
	})
	if err != nil {
		return fmt.Errorf("adding peer to storage: %w", err)
	}

	return nil
}

// UpdatePeerLastSeen updates the LastSeen timestamp for a peer identified by
// its public key claim. If the peer does not exist, the call is a no-op and
// returns nil.
func (s *Storage) UpdatePeerLastSeen(claim []byte, t time.Time) error {
	key := peerKey(claim)

	var data []byte
	err := s.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(peersBucket, key)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrMissingItem) || errors.Is(err, store.ErrMissingBucket) {
			return nil
		}
		return fmt.Errorf("reading peer for LastSeen update: %w", err)
	}

	var p pb.Peer
	if err = proto.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshaling peer: %w", err)
	}

	if t.IsZero() {
		t = time.Now()
	}
	p.LastSeen = timestamppb.New(t)

	updated, err := proto.Marshal(&p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}

	err = s.store.Command(func(c store.Command) error {
		return c.AddEncrypted(peersBucket, key, updated)
	})
	if err != nil {
		return fmt.Errorf("persisting LastSeen update: %w", err)
	}

	return nil
}

// ListPeers returns all non-expired peers stored in the database.
// Expired peers are silently removed during iteration.
func (s *Storage) ListPeers() ([]*Peer, error) {
	var peers []*Peer
	var expiredKeys [][]byte

	err := s.store.Query(func(q store.Query) error {
		for key, value := range q.IterateEncrypted(peersBucket) {
			var p pb.Peer
			if err := proto.Unmarshal(value, &p); err != nil {
				slog.Warn(
					"skipping malformed peer entry",
					slog.Any("error", err),
				)
				continue
			}

			if p.FirstSeen.AsTime().Add(s.expiryDuration).Before(time.Now()) {
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				expiredKeys = append(expiredKeys, keyCopy)
				continue
			}

			var a attest.Algorithm
			if err := a.UnmarshalText([]byte(p.Algorithm.String())); err != nil {
				slog.Warn(
					"skipping peer with unknown algorithm",
					slog.String("peer_name", p.GetName()),
					slog.Any("error", err),
				)
				continue
			}

			pubKey, err := a.Identitfier().ParsePublicKey(p.PublicKey)
			if err != nil {
				slog.Warn(
					"skipping peer with unparseable public key",
					slog.String("peer_name", p.GetName()),
					slog.Any("error", err),
				)
				continue
			}

			var lastSeen time.Time
			if p.LastSeen != nil {
				lastSeen = p.LastSeen.AsTime()
			}

			peers = append(peers, &Peer{
				Name:      p.Name,
				PublicKey: pubKey,
				Algorithm: a,
				FirstSeen: p.FirstSeen.AsTime(),
				LastSeen:  lastSeen,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("iterating peers: %w", err)
	}

	// Clean up expired entries outside the read transaction.
	for _, key := range expiredKeys {
		if err := s.store.Command(func(c store.Command) error {
			return c.Delete(peersBucket, key)
		}); err != nil {
			slog.Warn("failed to remove expired peer", slog.Any("error", err))
		}
	}

	return peers, nil
}

// DeletePeer removes a peer from storage by its public key claim.
func (s *Storage) DeletePeer(claim []byte) error {
	key := peerKey(claim)
	return s.store.Command(func(c store.Command) error {
		return c.Delete(peersBucket, key)
	})
}
