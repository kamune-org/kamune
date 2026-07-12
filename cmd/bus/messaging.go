package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) SendMessage(sessionID string, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	a.mu.RLock()
	var session *liveSession
	for _, s := range a.sessions {
		if s.ID == sessionID {
			session = s
			break
		}
	}
	a.mu.RUnlock()

	if session == nil {
		return errors.New("session not found: " + sessionID)
	}

	metadata, err := session.Transport.Send(
		kamune.Bytes([]byte(text)),
		kamune.RouteExchangeMessages,
	)
	if err != nil {
		return err
	}

	msg := MessageInfo{
		Text:      text,
		Timestamp: metadata.Timestamp(),
		IsLocal:   true,
	}

	a.mu.Lock()
	session.Messages = append(session.Messages, msg)
	session.LastActivity = time.Now()
	a.mu.Unlock()

	if store := a.store(); store != nil && !a.incognito {
		store.AddChatEntry(
			sessionID, []byte(text), metadata.Timestamp(), storage.SenderLocal,
		)
	}

	runtime.EventsEmit(a.ctx, "message-sent", sessionID, msg)
	runtime.EventsEmit(a.ctx, "session-updated", sessionID)
	a.addLogEntry("DEBUG", "Sent message | session_id="+sessionID+" msg_id="+metadata.ID())
	return nil
}

// receiveMessages runs the receive loop for a session. On involuntary
// disconnect (ErrConnClosed) it attempts transparent resumption when
// reconnectFn is available. When the loop exits, it cleans up the session and
// emits session-closed.
func (a *App) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)

	for {
		b := kamune.Bytes(nil)
		metadata, err := session.Transport.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				a.addLogEntry("INFO", "Peer disconnected: "+session.ID)
			case errors.Is(err, kamune.ErrConnClosed):
				a.addLogEntry("INFO", "Connection closed: "+session.ID)
				if session.reconnectFn != nil &&
					a.reconnectSession(session) {
					continue
				}
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				a.addLogEntry("ERROR", "Receive error: "+err.Error())
			}
			break
		}

		// Handle protocol-level routes before treating as chat.
		switch metadata.Route() {
		case kamune.RoutePing:
			if _, err := session.Transport.Send(
				kamune.Bytes(b.GetValue()), kamune.RoutePong,
			); err != nil {
				a.addLogEntry("WARN", "Failed to send pong: "+err.Error())
			}
			continue
		case kamune.RoutePong:
			select {
			case session.pongCh <- b.GetValue():
			default:
			}
			continue
		}

		msgText := string(b.GetValue())
		msg := MessageInfo{
			Text:      msgText,
			Timestamp: metadata.Timestamp(),
			IsLocal:   false,
		}

		a.mu.Lock()
		session.Messages = append(session.Messages, msg)
		session.LastActivity = time.Now()
		isActive := a.activeSessionID == session.ID
		a.mu.Unlock()

		if store := a.store(); store != nil && !a.incognito {
			store.AddChatEntry(
				session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
			)
		}

		if !isActive {
			preview := msgText
			if len(preview) > 50 {
				preview = preview[:50] + "..."
			}
			a.SendNotification("New Message", preview)
		}

		runtime.EventsEmit(a.ctx, "message-received", session.ID, msg)
		runtime.EventsEmit(a.ctx, "session-updated", session.ID)
		a.addLogEntry("DEBUG", "Received message | session_id="+session.ID+" msg_id="+metadata.ID())
	}

	sessionsRemaining := a.removeSession(session.ID)

	if store := a.store(); store != nil {
		a.loadHistorySessions(store)
	}

	runtime.EventsEmit(a.ctx, "session-closed", session.ID)

	if sessionsRemaining == 0 {
		a.setStatus(StatusDisconnected, "Not connected")
		a.addLogEntry("INFO", "All sessions disconnected")
	}
}

// keepAliveLoop sends periodic pings to detect dead connections. After 3
// consecutive ping failures, the session is closed.
func (a *App) keepAliveLoop(session *liveSession) {
	const pingTimeout = 10 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-session.ReceiveDone:
			return
		case <-session.keepAliveDone:
			return
		case <-ticker.C:
			a.addLogEntry("DEBUG", "keepalive: pinging peer | session_id="+session.ID+" failures="+
				strconv.Itoa(session.pingFailures))
			if err := sendPing(session.Transport, session.pongCh, pingTimeout); err != nil {
				session.pingFailures++
				a.addLogEntry("DEBUG", "keepalive: ping failed | session_id="+session.ID+" error="+err.Error()+
					" failures="+strconv.Itoa(session.pingFailures))
				if session.pingFailures >= 3 {
					a.addLogEntry("WARN", "Peer unresponsive: "+session.PeerName)
					_ = session.Transport.Close()
					return
				}
			} else {
				session.pingFailures = 0
				session.lastPongAt = time.Now()
				a.addLogEntry("DEBUG", "keepalive: pong received | session_id="+session.ID)
			}
		}
	}
}

// sendPing sends a RoutePing and waits for a matching RoutePong within
// timeout. The token-based verification ensures the pong corresponds to
// this specific ping.
func sendPing(t *kamune.Transport, pongCh <-chan []byte, timeout time.Duration) error {
	const pingDataSize = 8
	tok := make([]byte, pingDataSize)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	if _, err := t.Send(kamune.Bytes(tok), kamune.RoutePing); err != nil {
		return err
	}
	// Drain any stale pong from a previous (timed-out) ping.
	select {
	case <-pongCh:
	default:
	}
	select {
	case data := <-pongCh:
		if string(data) != string(tok) {
			return kamune.ErrVerificationFailed
		}
		return nil
	case <-time.After(timeout):
		return kamune.ErrReceiveTimeout
	}
}

// reconnectSession attempts to re-establish a session after an involuntary
// disconnect using resumption tokens. It retries with exponential backoff up to
// maxAttempts times. Returns true if reconnection succeeded (caller should
// restart the receive loop).
func (a *App) reconnectSession(session *liveSession) bool {
	const (
		maxAttempts = 10
		baseDelay   = 1 * time.Second
		maxDelay    = 30 * time.Second
	)

	for attempt := range maxAttempts {
		delay := min(baseDelay*time.Duration(1<<attempt), maxDelay)

		a.addLogEntry(
			"INFO", fmt.Sprintf("Reconnecting session %s (attempt %d/%d)", session.ID, attempt+1, maxAttempts),
		)
		runtime.EventsEmit(a.ctx, "session-reconnecting", session.ID, attempt+1, maxAttempts)

		select {
		case <-time.After(delay):
		case <-session.reconnectCtx.Done():
			return false
		}

		t, err := session.reconnectFn(session.ID)
		if err != nil {
			a.addLogEntry("WARN", "Reconnect failed: "+err.Error())
			continue
		}

		a.mu.Lock()
		session.Transport = t
		session.pingFailures = 0
		session.pongCh = make(chan []byte, 1)
		close(session.keepAliveDone)
		session.keepAliveDone = make(chan struct{})
		a.mu.Unlock()

		a.addLogEntry("INFO", "Reconnected session "+session.ID)
		runtime.EventsEmit(a.ctx, "session-reconnected", session.ID)
		go a.keepAliveLoop(session)
		return true
	}

	a.addLogEntry("WARN", "Reconnect failed after "+strconv.Itoa(maxAttempts)+" attempts: "+session.ID)
	return false
}
