package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
)

var (
	ErrSessionFull    = errors.New("max concurrent sessions reached")
	ErrTokenNotFound  = errors.New("token not found")
	ErrTokenConsumed  = errors.New("token already consumed")
	ErrPeerNotFound   = errors.New("peer not found in session")
	ErrSessionExpired = errors.New("session expired")
)

type session struct {
	token    [16]byte
	listener *exchange.Channel
	dialer   *exchange.Channel
	expiry   time.Time
}

type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*session
	ttl      time.Duration
	maxConns int
}

func NewSessionManager(ttl time.Duration, maxConns int) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*session),
		ttl:      ttl,
		maxConns: maxConns,
	}
}

func (sm *SessionManager) Create(listener *exchange.Channel) ([]byte, error) {
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
		token:    token,
		listener: listener,
		expiry:   time.Now().Add(sm.ttl),
	}

	return token[:], nil
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
	return nil
}

func (sm *SessionManager) Recipient(token []byte, sender *exchange.Channel) (*exchange.Channel, error) {
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
func (sm *SessionManager) ClosePeerChannel(token []byte, closed *exchange.Channel) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sess, ok := sm.sessions[fmt.Sprintf("%x", token)]
	if !ok {
		return
	}
	switch closed {
	case sess.listener:
		if sess.dialer != nil {
			sess.dialer.Close()
		}
	case sess.dialer:
		if sess.listener != nil {
			sess.listener.Close()
		}
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
	defer sm.mu.Unlock()

	now := time.Now()
	for key, sess := range sm.sessions {
		if now.After(sess.expiry) && sess.dialer == nil {
			sess.listener.Close()
			delete(sm.sessions, key)
		}
	}
}

func (sm *SessionManager) TTL() time.Duration {
	return sm.ttl
}
