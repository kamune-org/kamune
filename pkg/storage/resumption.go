package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/engine"
)

const (
	resumptionInitiatorKey = "resumption_i"
	resumptionResponderKey = "resumption_r"
	resumptionSecretLen    = 64
)

var (
	// ErrNoResumption is returned when a session has no resumption row
	// for the requested role.
	ErrNoResumption = errors.New("no resumption state")
	// ErrResumptionConflict is returned when a resumption write lost a
	// compare-and-swap on the stored generation.
	ErrResumptionConflict = errors.New(
		"resumption state changed concurrently",
	)
)

// ResumeRole is the side of a session that owns a resumption row.
type ResumeRole uint8

const (
	ResumeRoleInitiator ResumeRole = iota + 1
	ResumeRoleResponder
)

// Resumption is one role's resumption secret and the times that bound it.
type Resumption struct {
	Generation  uint64
	Current     []byte
	Previous    []byte
	PeerKey     []byte
	ColdAt      time.Time
	RefreshedAt time.Time
	Role        ResumeRole
}

// GetResumption returns the row of sessionID for role, or ErrNoResumption.
func (s *Storage) GetResumption(
	sessionID string, role ResumeRole,
) (*Resumption, error) {
	if _, err := resumptionMetaKey(role); err != nil {
		return nil, err
	}
	var row *Resumption
	err := s.engine.Query(func(b engine.Namespace) error {
		var err error
		row, err = readResumption(s.sessionMeta(b, sessionID), role)
		return err
	})
	if errors.Is(err, ErrNoResumption) {
		return nil, ErrNoResumption
	}
	if err != nil {
		return nil, fmt.Errorf("get resumption %s: %w", sessionID, err)
	}
	return row, nil
}

// SwapResumption replaces the row of sessionID for next.Role with next if
// the stored generation equals oldGen. oldGen 0 means no row may exist.
// Otherwise it returns ErrResumptionConflict and writes nothing.
func (s *Storage) SwapResumption(
	sessionID string, oldGen uint64, next *Resumption,
) error {
	if err := validateResumption(next); err != nil {
		return err
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
		current, err := readResumption(meta, next.Role)
		switch {
		case err != nil && !errors.Is(err, ErrNoResumption):
			return err
		case oldGen == 0 && err == nil:
			return ErrResumptionConflict
		case oldGen == 0:
			session, err := s.ensureSession(b, sessionID)
			if err != nil {
				return err
			}
			meta = session.Ensure([]byte("meta"))
		case err != nil || current.Generation != oldGen:
			return ErrResumptionConflict
		}
		if err := s.noteResumptionPeer(
			b, meta, sessionID, next,
		); err != nil {
			return err
		}
		return putResumption(meta, next)
	})
	if err != nil {
		return fmt.Errorf("swap resumption %s: %w", sessionID, err)
	}
	return nil
}

// DeleteResumption deletes the row of sessionID for role if its generation
// is gen. gen must be at least 1. A missing session or row is not an
// error, and the session namespace is never created.
func (s *Storage) DeleteResumption(
	sessionID string, role ResumeRole, gen uint64,
) error {
	if gen == 0 {
		return fmt.Errorf("resumption generation must be at least 1")
	}
	if _, err := resumptionMetaKey(role); err != nil {
		return err
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
		row, err := readResumption(meta, role)
		if errors.Is(err, ErrNoResumption) {
			return nil
		}
		if err != nil {
			return err
		}
		if row.Generation != gen {
			return ErrResumptionConflict
		}
		key, err := resumptionMetaKey(role)
		if err != nil {
			return err
		}
		return meta.Delete([]byte(key))
	})
	if err != nil {
		return fmt.Errorf("delete resumption %s: %w", sessionID, err)
	}
	return nil
}

// DeleteResumptionAll deletes both rows of sessionID, whatever their
// generation, without creating the namespace.
func (s *Storage) DeleteResumptionAll(sessionID string) error {
	err := s.engine.Command(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
		for _, role := range []ResumeRole{
			ResumeRoleInitiator, ResumeRoleResponder,
		} {
			key, err := resumptionMetaKey(role)
			if err != nil {
				return err
			}
			if _, err = meta.GetEncrypted([]byte(key)); err != nil {
				if isMissing(err) {
					continue
				}
				return err
			}
			if err = meta.Delete([]byte(key)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete resumption %s: %w", sessionID, err)
	}
	return nil
}

// TouchResumption sets RefreshedAt of the row to at if its generation is
// gen and at is later. It never creates a namespace or a row.
func (s *Storage) TouchResumption(
	sessionID string, role ResumeRole, gen uint64, at time.Time,
) error {
	if _, err := resumptionMetaKey(role); err != nil {
		return err
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
		row, err := readResumption(meta, role)
		if errors.Is(err, ErrNoResumption) {
			return ErrNoResumption
		}
		if err != nil {
			return err
		}
		if row.Generation != gen {
			return ErrResumptionConflict
		}
		if !at.After(row.RefreshedAt) {
			return nil
		}
		row.RefreshedAt = at
		return putResumption(meta, row)
	})
	if errors.Is(err, ErrNoResumption) ||
		errors.Is(err, ErrResumptionConflict) {
		return err
	}
	if err != nil {
		return fmt.Errorf("touch resumption %s: %w", sessionID, err)
	}
	return nil
}

// HoldResumption keeps sessionID out of [SweepSessions] until the
// matching [ReleaseResumption]. A live transport holds its row so the
// idle window starts when the connection ends, not when it began.
// Extra releases are ignored.
func (s *Storage) HoldResumption(sessionID string) {
	if s == nil || sessionID == "" {
		return
	}
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live == nil {
		s.live = make(map[string]int)
	}
	s.live[sessionID]++
}

// ReleaseResumption drops one hold from [HoldResumption].
func (s *Storage) ReleaseResumption(sessionID string) {
	if s == nil || sessionID == "" {
		return
	}
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	n := s.live[sessionID]
	if n <= 1 {
		delete(s.live, sessionID)
		return
	}
	s.live[sessionID] = n - 1
}

// heldSessions returns the namespace names of sessions a live transport
// still holds. The caller must not use the map after the next hold change.
func (s *Storage) heldSessions() map[string]struct{} {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	held := make(map[string]struct{}, len(s.live))
	for id := range s.live {
		held[string(s.sessionName(id))] = struct{}{}
	}
	return held
}

// SweepSessions deletes expired resumption rows and the idle unnamed
// sessions they leave behind. A session held by [HoldResumption] is left
// in place, including one past the idle window or the maximum age. It
// returns how many sessions were deleted.
func (s *Storage) SweepSessions(
	now time.Time, idle, maxAge time.Duration,
) (int, error) {
	held := s.heldSessions()
	deleted := 0
	err := s.engine.Command(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace))
		for _, name := range sessions.ListSubNamespaces() {
			if _, ok := held[string(name)]; ok {
				continue
			}
			meta := sessions.Sub([]byte(name)).Sub([]byte("meta"))
			if err := expireResumption(
				meta, now, idle, maxAge,
			); err != nil {
				return err
			}
		}
		for _, name := range sessions.ListSubNamespaces() {
			session := sessions.Sub([]byte(name))
			if !idleUnnamedSession(session, now, maxAge) {
				continue
			}
			if err := sessions.DeleteNamespace([]byte(name)); err != nil {
				return fmt.Errorf("delete idle session: %w", err)
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sweep sessions: %w", err)
	}
	return deleted, nil
}

func (s *Storage) noteResumptionPeer(
	b engine.Namespace, meta engine.Namespace,
	sessionID string, row *Resumption,
) error {
	if len(row.PeerKey) == 0 {
		return nil
	}
	err := meta.PutEncrypted([]byte(PeerKey), row.PeerKey)
	if err != nil {
		return fmt.Errorf("store peer key: %w", err)
	}
	err = s.setPeerLastSeen(b, s.peerKey(row.PeerKey), s.clock.Now())
	if err != nil {
		slog.Warn(
			"could not update peer last seen",
			slog.String("session_id", sessionID),
			slog.Any("error", err),
		)
	}
	if row.Generation != 1 {
		return nil
	}
	existing, err := meta.GetEncrypted([]byte(EstablishedAtKey))
	if err != nil && !isMissing(err) {
		return fmt.Errorf("read established_at: %w", err)
	}
	if len(existing) < 8 {
		var tsBuf [8]byte
		binary.BigEndian.PutUint64(
			tsBuf[:], uint64(s.clock.Now().UnixNano()),
		)
		err = meta.PutEncrypted([]byte(EstablishedAtKey), tsBuf[:])
		if err != nil {
			return fmt.Errorf("store established_at: %w", err)
		}
	}
	return s.pruneIdleSessions(b, row.PeerKey, sessionID)
}

func expireResumption(
	meta engine.Namespace, now time.Time, idle, maxAge time.Duration,
) error {
	for _, role := range []ResumeRole{
		ResumeRoleInitiator, ResumeRoleResponder,
	} {
		row, err := readResumption(meta, role)
		if errors.Is(err, ErrNoResumption) {
			continue
		}
		if err != nil {
			return err
		}
		aged := now.Sub(row.RefreshedAt) > idle ||
			now.Sub(row.ColdAt) > maxAge
		if !aged {
			continue
		}
		key, err := resumptionMetaKey(role)
		if err != nil {
			return err
		}
		if err = meta.Delete([]byte(key)); err != nil {
			return err
		}
	}
	return nil
}

func idleUnnamedSession(
	session engine.Namespace, now time.Time, maxAge time.Duration,
) bool {
	meta := session.Sub([]byte("meta"))
	if hasResumption(meta) {
		return false
	}
	if session.Sub([]byte("chat")).FirstKey() != nil {
		return false
	}
	if _, err := meta.GetEncrypted(sessionMetaKey); err == nil {
		return false
	}
	ts, err := meta.GetEncrypted([]byte(EstablishedAtKey))
	if err == nil && len(ts) >= 8 {
		at := time.Unix(0, int64(binary.BigEndian.Uint64(ts[:8])))
		if now.Sub(at) <= maxAge {
			return false
		}
	}
	return true
}

func hasResumption(meta engine.Namespace) bool {
	for _, key := range []string{
		resumptionInitiatorKey, resumptionResponderKey,
	} {
		_, err := meta.GetEncrypted([]byte(key))
		if err == nil {
			return true
		}
	}
	return false
}

func readResumption(
	meta engine.Namespace, role ResumeRole,
) (*Resumption, error) {
	key, err := resumptionMetaKey(role)
	if err != nil {
		return nil, err
	}
	data, err := meta.GetEncrypted([]byte(key))
	if err != nil {
		if isMissing(err) {
			return nil, ErrNoResumption
		}
		return nil, err
	}
	return unmarshalResumption(data, role)
}

func putResumption(meta engine.Namespace, row *Resumption) error {
	key, err := resumptionMetaKey(row.Role)
	if err != nil {
		return err
	}
	blob, err := marshalResumption(row)
	if err != nil {
		return err
	}
	if err = meta.PutEncrypted([]byte(key), blob); err != nil {
		return fmt.Errorf("store resumption: %w", err)
	}
	return nil
}

func resumptionMetaKey(role ResumeRole) (string, error) {
	switch role {
	case ResumeRoleInitiator:
		return resumptionInitiatorKey, nil
	case ResumeRoleResponder:
		return resumptionResponderKey, nil
	default:
		return "", fmt.Errorf("invalid resume role")
	}
}

func validateResumption(row *Resumption) error {
	if row == nil {
		return fmt.Errorf("nil resumption")
	}
	if _, err := resumptionMetaKey(row.Role); err != nil {
		return err
	}
	if row.Generation < 1 {
		return fmt.Errorf("resumption generation must be at least 1")
	}
	if len(row.Current) != resumptionSecretLen {
		return fmt.Errorf("resumption secret must be 64 bytes")
	}
	if n := len(row.Previous); n != 0 && n != resumptionSecretLen {
		return fmt.Errorf(
			"previous resumption secret must be empty or 64 bytes",
		)
	}
	if row.Role == ResumeRoleInitiator && len(row.Previous) != 0 {
		return fmt.Errorf("initiator resumption must not store previous")
	}
	if len(row.PeerKey) != 44 {
		return fmt.Errorf("peer public key must be 44 bytes")
	}
	if row.ColdAt.IsZero() || row.RefreshedAt.IsZero() {
		return fmt.Errorf("resumption timestamps must be set")
	}
	return nil
}

func marshalResumption(row *Resumption) ([]byte, error) {
	blob, err := proto.Marshal(&pb.ResumptionState{
		Generation:          row.Generation,
		Current:             row.Current,
		Previous:            row.Previous,
		PeerPublicKey:       row.PeerKey,
		ColdAtUnixNano:      row.ColdAt.UnixNano(),
		RefreshedAtUnixNano: row.RefreshedAt.UnixNano(),
		Role:                pb.ResumeRole(row.Role),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal resumption: %w", err)
	}
	return blob, nil
}

func unmarshalResumption(data []byte, role ResumeRole) (*Resumption, error) {
	var st pb.ResumptionState
	if err := proto.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("unmarshal resumption: %w", err)
	}
	if ResumeRole(st.GetRole()) != role {
		return nil, fmt.Errorf("resumption role mismatch")
	}
	return &Resumption{
		Generation:  st.GetGeneration(),
		Current:     bytes.Clone(st.GetCurrent()),
		Previous:    bytes.Clone(st.GetPrevious()),
		PeerKey:     bytes.Clone(st.GetPeerPublicKey()),
		ColdAt:      time.Unix(0, st.GetColdAtUnixNano()),
		RefreshedAt: time.Unix(0, st.GetRefreshedAtUnixNano()),
		Role:        role,
	}, nil
}
