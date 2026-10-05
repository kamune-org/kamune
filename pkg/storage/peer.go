package storage

import (
	"crypto/hmac"
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

// FindPeer returns the stored peer whose public key is claim. An expired
// peer is removed and [ErrPeerExpired] returned. A record stored under
// claim that holds another public key gives [ErrPeerMismatch].
func (s *Storage) FindPeer(claim []byte) (*Peer, error) {
	key := s.peerKey(claim)
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

// findPeer reads the peer stored under key, the [Storage.peerKey] of its
// public key. A record whose public key does not give key is rejected with
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
	if !s.matchesKey(&p, key) {
		return nil, ErrPeerMismatch
	}

	if s.expired(&p) {
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
func (s *Storage) matchesKey(p *pb.Peer, key []byte) bool {
	return hmac.Equal(s.peerKey(p.GetPublicKey()), key)
}

// removeExpiredPeer deletes the peer stored under key if it is still
// expired. The record is read again in the transaction that deletes it,
// so a peer stored again since it was found expired is kept.
func (s *Storage) removeExpiredPeer(key []byte) {
	err := s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		data, err := peers.GetEncrypted(key)
		if err != nil {
			if isMissing(err) {
				return nil
			}
			return err
		}
		var p pb.Peer
		if err := proto.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("unmarshaling peer: %w", err)
		}
		if !s.expired(&p) {
			return nil
		}
		return peers.Delete(key)
	})
	if err != nil {
		slog.Warn("failed to remove expired peer", slog.Any("error", err))
	}
}

// expired reports whether p was first seen longer than the expiry
// duration ago.
func (s *Storage) expired(p *pb.Peer) bool {
	return p.GetFirstSeen().AsTime().Add(s.expiryDuration).
		Before(s.clock.Now())
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
	key := s.peerKey(pubKey)
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
// its public key claim; a zero t means now. If the peer does not exist, the
// call is a no-op and returns nil. The record is read and written in one
// transaction, so a peer deleted concurrently stays deleted.
func (s *Storage) UpdatePeerLastSeen(claim []byte, t time.Time) error {
	if t.IsZero() {
		t = s.clock.Now()
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		return s.setPeerLastSeen(b, s.peerKey(claim), t)
	})
	if err != nil {
		return fmt.Errorf("updating peer LastSeen: %w", err)
	}
	return nil
}

// setPeerLastSeen sets the LastSeen of the peer stored under key to t, in
// the transaction of b. It does nothing when no peer is stored under key.
func (s *Storage) setPeerLastSeen(
	b engine.Namespace, key []byte, t time.Time,
) error {
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
	if !s.matchesKey(&p, key) {
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
			if !s.matchesKey(&p, key) {
				slog.Warn(
					"skipping peer entry stored under another key",
					slog.String("name", p.GetName()),
				)
				continue
			}

			if s.expired(&p) {
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
		s.removeExpiredPeer(key)
	}

	return peers, nil
}

// DeletePeer removes a peer from storage by its public key claim. The
// database is then compacted with [Storage.Compact], so that the record
// does not stay in the file. If that fails the peer is deleted all the
// same, the error wraps [ErrCompactFailed], and the next [OpenStorage]
// compacts the database. The sessions with the peer are kept.
func (s *Storage) DeletePeer(claim []byte) error {
	key := s.peerKey(claim)
	err := s.engine.Command(func(b engine.Namespace) error {
		peers := b.Sub([]byte(engine.PeersNamespace))
		if err := peers.Delete(key); err != nil {
			return err
		}
		return markCompactPending(b)
	})
	if err != nil {
		return err
	}
	if err := s.Compact(); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	return nil
}
