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
	sm.mu.Lock()
	toClose := sm.takeExpiredLocked()
	defer closeChannels(toClose)
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

	sm.mu.Lock()
	toClose := sm.takeExpiredLocked()
	defer closeChannels(toClose)
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

	key := fmt.Sprintf("%x", token)
	sess, ok := sm.sessions[key]
	if !ok {
		sm.mu.Unlock()
		return ErrTokenNotFound
	}

	if sess.dialer != nil {
		sm.mu.Unlock()
		return ErrTokenConsumed
	}

	if time.Now().After(sess.expiry) {
		delete(sm.sessions, key)
		listener := sess.listener
		sm.mu.Unlock()
		if err := listener.Close(); err != nil {
			slog.Debug("session: close expired listener", slog.Any("error", err))
		}
		return ErrSessionExpired
	}

	sess.dialer = dialer
	if sm.sessionTTL > 0 {
		sess.sessionExpiry = time.Now().Add(sm.sessionTTL)
	}
	sm.mu.Unlock()
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

// Leave removes the session under token when ch is its listener or dialer,
// and closes the other peer's channel. The lookup and the removal share one
// lock, so a concurrent Join either pairs first, and its dialer is closed
// here, or finds no session. Without that, a dialer could join a listener
// that is already gone and wait with no session to time it out. A ch that
// does not own the session changes nothing.
func (sm *SessionManager) Leave(token []byte, ch *exchange.Channel) {
	if ch == nil {
		return
	}
	sm.mu.Lock()
	key := fmt.Sprintf("%x", token)
	sess, ok := sm.sessions[key]
	if !ok || (ch != sess.listener && ch != sess.dialer) {
		sm.mu.Unlock()
		return
	}
	delete(sm.sessions, key)
	peer := sess.dialer
	if ch == sess.dialer {
		peer = sess.listener
	}
	sm.mu.Unlock()

	if peer == nil {
		return
	}
	if err := peer.Close(); err != nil {
		slog.Debug("session: close peer", slog.Any("error", err))
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
	toClose := sm.takeExpiredLocked()
	sm.mu.Unlock()
	closeChannels(toClose)
}

func (sm *SessionManager) takeExpiredLocked() []*exchange.Channel {
	now := time.Now()
	var toClose []*exchange.Channel
	for key, sess := range sm.sessions {
		switch {
		case sess.dialer == nil && now.After(sess.expiry):
			delete(sm.sessions, key)
			toClose = append(toClose, sess.listener)
		case sess.dialer != nil &&
			!sess.sessionExpiry.IsZero() &&
			now.After(sess.sessionExpiry):
			delete(sm.sessions, key)
			toClose = append(toClose, sess.listener, sess.dialer)
		}
	}
	return toClose
}

func closeChannels(chs []*exchange.Channel) {
	var wg sync.WaitGroup
	for _, ch := range chs {
		wg.Go(func() {
			if err := ch.Close(); err != nil {
				slog.Debug("session: close channel", slog.Any("error", err))
			}
		})
	}
	wg.Wait()
}

func (sm *SessionManager) TTL() time.Duration {
	return sm.ttl
}

func (sm *SessionManager) SessionTTL() time.Duration {
	return sm.sessionTTL
}
