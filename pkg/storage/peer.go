package storage

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/engine"
)

type Peer struct {
	FirstSeen  time.Time
	LastSeen   time.Time
	Name       string
	AppVersion string
	PublicKey  []byte
}

var (
	ErrPeerExpired      = errors.New("peer has been expired")
	ErrInvalidPublicKey = errors.New("public key must be PKIX-marshaled")
	// ErrPeerMismatch is returned when a stored peer record holds a public
	// key other than the one it is stored under, which means the database
	// was tampered with. The record is not trusted.
	ErrPeerMismatch = errors.New("stored peer does not match its key")
)

// peerKey returns the storage key for a peer identified by the given claim
// (typically the marshaled public key). The key is the SHA3-512 hash of the
// claim.
func peerKey(claim []byte) []byte {
	h := sha3.Sum512(claim)
	return h[:]
}

// FindPeer returns the stored peer whose public key is claim. An expired
// peer is removed and [ErrPeerExpired] returned. A record stored under
// claim that holds another public key gives [ErrPeerMismatch].
func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	key := peerKey(claim)
	var peer *Peer
	err := s.engine.Query(func(b engine.Namespace) error {
		var err error
		peer, err = s.findPeer(b, key)
		return err
	})
	if errors.Is(err, ErrPeerExpired) {
		s.removeExpiredPeer(key)
		return nil, ErrPeerExpired
	}
	return peer, err
}

// findPeer reads the peer stored under key, the [peerKey] of its public
// key. A record whose public key does not hash to key is rejected with
// [ErrPeerMismatch].
func (s *Storage) findPeer(b engine.Namespace, key []byte) (*Peer, error) {
	peers := b.Sub([]byte(engine.PeersNamespace))
	data, err := peers.GetEncrypted(key)
	if err != nil {
		return nil, fmt.Errorf("getting peer: %w", err)
	}

	var p pb.Peer
	if err = proto.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshaling peer: %w", err)
	}
	if !matchesKey(&p, key) {
		return nil, ErrPeerMismatch
	}

	if p.FirstSeen.AsTime().Add(s.expiryDuration).Before(s.clock.Now()) {
		return nil, ErrPeerExpired
	}

	var lastSeen time.Time
	if p.LastSeen != nil {
		lastSeen = p.LastSeen.AsTime()
	}

	return &Peer{
		Name:       p.Name,
		PublicKey:  p.PublicKey,
		FirstSeen:  p.FirstSeen.AsTime(),
		LastSeen:   lastSeen,
		AppVersion: p.AppVersion,
	}, nil
}

// matchesKey reports whether p is the peer whose records are stored under
// key.
func matchesKey(p *pb.Peer, key []byte) bool {
	return bytes.Equal(peerKey(p.GetPublicKey()), key)
}

func (s *Storage) removeExpiredPeer(key []byte) {
	err := s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		return peers.Delete(key)
	})
	if err != nil {
		slog.Warn("failed to remove expired peer", slog.Any("error", err))
	}
}

func (s *Storage) StorePeer(peer *Peer) error {
	pubKey := peer.PublicKey
	if len(pubKey) != 44 {
		return fmt.Errorf(
			"%w (expected 44, got %d bytes)", ErrInvalidPublicKey, len(pubKey),
		)
	}

	now := s.clock.Now()
	firstSeen := peer.FirstSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	lastSeen := peer.LastSeen
	if lastSeen.IsZero() {
		lastSeen = now
	}

	p := &pb.Peer{
		Name:       peer.Name,
		PublicKey:  pubKey,
		FirstSeen:  timestamppb.New(firstSeen),
		LastSeen:   timestamppb.New(lastSeen),
		AppVersion: peer.AppVersion,
	}
	data, err := proto.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	key := peerKey(pubKey)
	err = s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		return peers.PutEncrypted(key, data)
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
	err := s.engine.Query(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		var err error
		data, err = peers.GetEncrypted(key)
		return err
	})
	if err != nil {
		if isMissing(err) {
			return nil
		}
		return fmt.Errorf("reading peer for LastSeen update: %w", err)
	}

	var p pb.Peer
	if err = proto.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshaling peer: %w", err)
	}

	if t.IsZero() {
		t = s.clock.Now()
	}
	p.LastSeen = timestamppb.New(t)

	updated, err := proto.Marshal(&p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}

	err = s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		return peers.PutEncrypted(key, updated)
	})
	if err != nil {
		return fmt.Errorf("persisting LastSeen update: %w", err)
	}

	return nil
}

// setPeerLastSeen sets the LastSeen of the peer stored under key to t, in
// the transaction of b. It does nothing when no peer is stored under key.
func setPeerLastSeen(b engine.Namespace, key []byte, t time.Time) error {
	peers := b.Sub([]byte(engine.PeersNamespace))
	data, err := peers.GetEncrypted(key)
	if err != nil {
		if isMissing(err) {
			return nil
		}
		return fmt.Errorf("reading peer: %w", err)
	}

	var p pb.Peer
	if err = proto.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshaling peer: %w", err)
	}
	if !matchesKey(&p, key) {
		return ErrPeerMismatch
	}
	p.LastSeen = timestamppb.New(t)

	updated, err := proto.Marshal(&p)
	if err != nil {
		return fmt.Errorf("marshaling peer: %w", err)
	}
	return peers.PutEncrypted(key, updated)
}

// ListPeers returns all non-expired peers stored in the database.
// Expired peers are silently removed during iteration.
func (s *Storage) ListPeers() ([]*Peer, error) {
	var peers []*Peer
	var expiredKeys [][]byte

	err := s.engine.Query(func(b engine.Namespace) error {
		ns := b.Sub([]byte(engine.PeersNamespace))
		for key, value := range ns.IterateEncrypted() {
			var p pb.Peer
			if err := proto.Unmarshal(value, &p); err != nil {
				slog.Warn(
					"skipping malformed peer entry", slog.Any("error", err),
				)
				continue
			}
			if !matchesKey(&p, key) {
				slog.Warn(
					"skipping peer entry stored under another key",
					slog.String("name", p.GetName()),
				)
				continue
			}

			if p.FirstSeen.AsTime().Add(s.expiryDuration).Before(s.clock.Now()) {
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				expiredKeys = append(expiredKeys, keyCopy)
				continue
			}

			var lastSeen time.Time
			if p.LastSeen != nil {
				lastSeen = p.LastSeen.AsTime()
			}

			peers = append(peers, &Peer{
				Name:       p.Name,
				PublicKey:  p.PublicKey,
				FirstSeen:  p.FirstSeen.AsTime(),
				LastSeen:   lastSeen,
				AppVersion: p.AppVersion,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("iterating peers: %w", err)
	}

	// Clean up expired entries outside the read transaction.
	for _, key := range expiredKeys {
		if err := s.engine.Command(func(b engine.Namespace) error {
			peers := b.Sub([]byte(engine.PeersNamespace))
			return peers.Delete(key)
		}); err != nil {
			slog.Warn("failed to remove expired peer", slog.Any("error", err))
		}
	}

	return peers, nil
}

// DeletePeer removes a peer from storage by its public key claim.
func (s *Storage) DeletePeer(claim []byte) error {
	key := peerKey(claim)
	return s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		return peers.Delete(key)
	})
}
