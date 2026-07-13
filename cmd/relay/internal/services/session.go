package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn"
)

var (
	ErrSessionFull    = errors.New("max concurrent sessions reached")
	ErrTokenNotFound  = errors.New("token not found")
	ErrTokenConsumed  = errors.New("token already consumed")
	ErrPeerNotFound   = errors.New("peer not found in session")
	ErrSessionExpired = errors.New("session expired")
	ErrTokenInUse     = errors.New("token already in use")
)

type session struct {
	listener      *exchange.Channel
	dialer        *exchange.Channel
	expiry        time.Time
	sessionExpiry time.Time
}

type SessionManager struct {
	mu         sync.Mutex
	sessions   map[string]*session
	ttl        time.Duration
	sessionTTL time.Duration
	maxConns   int
}

func NewSessionManager(
	ttl time.Duration, maxConns int, sessionTTL time.Duration,
) *SessionManager {
	return &SessionManager{
		sessions:   make(map[string]*session),
		ttl:        ttl,
		sessionTTL: sessionTTL,
		maxConns:   maxConns,
	}
}

func (sm *SessionManager) Create(listener *exchange.Channel) ([]byte, error) {
	sm.purgeExpired()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= sm.maxConns {
		return nil, ErrSessionFull
	}

	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	sm.sessions[fmt.Sprintf("%x", token[:])] = &session{
		listener: listener,
		expiry:   time.Now().Add(sm.ttl),
	}

	return token[:], nil
}

// CreateWith registers a session under a caller-provided token. Used for
// static-token mode and ECDH-derived tokens where both peers use the same
// token. The token must be exactly 32 bytes and pass entropy validation.
// Capacity is checked before token uniqueness so a full server always
// reports ErrSessionFull regardless of which token is offered.
func (sm *SessionManager) CreateWith(
	listener *exchange.Channel, token []byte,
) error {
	if err := relayconn.ValidateUserToken(token); err != nil {
		return err
	}

	sm.purgeExpired()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= sm.maxConns {
		return ErrSessionFull
	}

	key := fmt.Sprintf("%x", token)
	if _, exists := sm.sessions[key]; exists {
		return ErrTokenInUse
	}

	sm.sessions[key] = &session{
		listener: listener,
		expiry:   time.Now().Add(sm.ttl),
	}
	return nil
}

func (sm *SessionManager) Join(token []byte, dialer *exchange.Channel) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := fmt.Sprintf("%x", token)
	sess, ok := sm.sessions[key]
	if !ok {
		return ErrTokenNotFound
	}

	if time.Now().After(sess.expiry) {
		delete(sm.sessions, key)
		return ErrSessionExpired
	}

	if sess.dialer != nil {
		return ErrTokenConsumed
	}

	sess.dialer = dialer
	if sm.sessionTTL > 0 {
		sess.sessionExpiry = time.Now().Add(sm.sessionTTL)
	}
	return nil
}

func (sm *SessionManager) Recipient(
	token []byte, sender *exchange.Channel,
) (*exchange.Channel, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[fmt.Sprintf("%x", token)]

	if !ok {
		return nil, ErrTokenNotFound
	}

	switch sender {
	case sess.listener:
		if sess.dialer == nil {
			return nil, ErrPeerNotFound
		}
		return sess.dialer, nil
	case sess.dialer:
		return sess.listener, nil
	default:
		return nil, ErrPeerNotFound
	}
}

// ClosePeerChannel closes the exchange channel of the peer that is NOT the
// given closed channel. When one peer disconnects, this ensures the other
// peer's read pump exits rather than blocking forever.
func (sm *SessionManager) ClosePeerChannel(
	token []byte, closed *exchange.Channel,
) {
	sm.mu.Lock()
	sess, ok := sm.sessions[fmt.Sprintf("%x", token)]
	if !ok {
		sm.mu.Unlock()
		return
	}
	var peer *exchange.Channel
	switch closed {
	case sess.listener:
		peer = sess.dialer
	case sess.dialer:
		peer = sess.listener
	}
	sm.mu.Unlock()

	if peer != nil {
		peer.Close()
	}
}

func (sm *SessionManager) Remove(token []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, fmt.Sprintf("%x", token))
}

func (sm *SessionManager) Len() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.sessions)
}

func (sm *SessionManager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.purgeExpired()
		case <-ctx.Done():
			return
		}
	}
}

func (sm *SessionManager) purgeExpired() {
	sm.mu.Lock()

	var wg sync.WaitGroup
	now := time.Now()
	for key, sess := range sm.sessions {
		switch {
		case sess.dialer == nil && now.After(sess.expiry):
			delete(sm.sessions, key)
			wg.Go(func() {
				if err := sess.listener.Close(); err != nil {
					slog.Debug("session: close listener", slog.Any("error", err))
				}
			})

		case sess.dialer != nil &&
			!sess.sessionExpiry.IsZero() &&
			now.After(sess.sessionExpiry):
			delete(sm.sessions, key)
			wg.Go(func() {
				if err := sess.listener.Close(); err != nil {
					slog.Debug("session: close listener", slog.Any("error", err))
				}
				if err := sess.dialer.Close(); err != nil {
					slog.Debug("session: close dialer", slog.Any("error", err))
				}
			})
		}
	}
	sm.mu.Unlock()
	wg.Wait()
}

func (sm *SessionManager) TTL() time.Duration {
	return sm.ttl
}

func (sm *SessionManager) SessionTTL() time.Duration {
	return sm.sessionTTL
}
