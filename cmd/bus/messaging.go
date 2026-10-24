package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
	"google.golang.org/protobuf/proto"
)

// ErrMessageNotSent reports a message that SendMessage could not send
// because the session's connection was gone. The message is not sent
// again on its own; the user may send it once the session reconnects.
var ErrMessageNotSent = errors.New(
	"message not sent: the connection was lost",
)

// SendMessage sends text to the session sessionID. When the connection
// is gone (see sendLost), possibly with part of the message written, the
// error wraps ErrMessageNotSent: the message is never sent again on that
// connection, which the session's receive loop replaces by resuming the
// session when it can. Any other error leaves the connection usable.
//
// The message joins the session, and the history, only once it has been
// sent, after any message that arrived meanwhile; see
// MessageInfo.Timestamp. Holding the receive loop back for the send
// could stall both peers when each waits to send to the other, and the
// history keeps its entries in the order they were stored.
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
	session.mu.Lock()
	transport := session.Transport
	session.mu.Unlock()

	metadata, err := transport.Send(
		kamune.Bytes([]byte(text)),
		kamune.RouteExchangeMessages,
	)
	if sendLost(err) {
		a.addLogEntry("WARN",
			"Message not sent, connection lost | session_id="+sessionID)
		return fmt.Errorf("%w: %w", ErrMessageNotSent, err)
	}
	if err != nil {
		return err
	}

	msg := MessageInfo{
		Text:      text,
		Timestamp: a.now(),
		SentAt:    metadata.Timestamp(),
		IsLocal:   true,
	}

	a.mu.Lock()
	session.addMessage(msg)
	session.LastActivity = time.Now()
	a.mu.Unlock()

	if store := a.store(); store != nil && !a.sessionIncognito(session) {
		if err := store.AddChatEntry(
			sessionID, []byte(text), metadata.Timestamp(), storage.SenderLocal,
		); err != nil {
			a.addLogEntry("WARN", "Failed to save sent message: "+err.Error())
			a.emitEvent("history-save-failed", sessionID)
		}
	}

	a.emitEvent("message-sent", sessionID, msg)
	a.emitEvent("session-updated", sessionID)
	a.addLogEntry("DEBUG", "Sent message | session_id="+sessionID+" msg_id="+metadata.ID())
	return nil
}

// receiveMessages runs the receive loop for a session. When its
// connection is lost (see connLost) it closes it and attempts transparent
// resumption when reconnectFn is available. When the loop exits, it takes
// the session out
// of the app and emits session-closed, and reports removed and whether
// the session ended because its connection dropped, rather than because
// either side closed it. A session that is no longer in the app, because
// DisconnectSession or StopServer took it out or a resumed session
// replaced it, is left alone, and both results are false.
func (a *App) receiveMessages(session *liveSession) (dropped, removed bool) {
	defer close(session.ReceiveDone)

	var endErr error
	for {
		session.mu.Lock()
		transport := session.Transport
		session.mu.Unlock()
		metadata, payload, err := transport.ReceivePayload()
		if err != nil {
			endErr = err
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				a.addLogEntry("INFO", "Peer disconnected: "+session.ID)
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			case connLost(err):
				a.addLogEntry("INFO", "Connection closed: "+session.ID+
					": "+err.Error())
				// The socket may still be open, as after the peer reset
				// it. Closing it without a close frame keeps the session
				// resumable.
				_ = transport.CloseAbort()
				if session.reconnectFn != nil &&
					a.reconnectSession(session) {
					continue
				}
			default:
				a.addLogEntry("ERROR", "Receive error: "+err.Error())
			}
			break
		}

		if metadata.Route() == kamune.RouteSessionData {
			a.finishRelayToken(session, payload)
			continue
		}
		b := kamune.Bytes(nil)
		if err := proto.Unmarshal(payload, b); err != nil {
			a.addLogEntry("WARN", "bad payload: "+err.Error())
			continue
		}

		// Handle protocol-level routes before treating as chat.
		switch metadata.Route() {
		case kamune.RoutePing:
			if _, err := transport.Send(
				kamune.Bytes(b.GetValue()), kamune.RoutePong,
			); err != nil {
				a.addLogEntry("WARN", "Failed to send pong: "+err.Error())
			}
			continue
		case kamune.RoutePong:
			session.mu.Lock()
			ch := session.pongCh
			session.mu.Unlock()
			if ch != nil {
				select {
				case ch <- b.GetValue():
				default:
				}
			}
			continue
		}

		// The time the peer put on the message comes from its clock,
		// which it controls, so the message is listed by the time it
		// arrived.
		msgText := string(b.GetValue())
		msg := MessageInfo{
			Text:      msgText,
			Timestamp: a.now(),
			SentAt:    metadata.Timestamp(),
			IsLocal:   false,
		}

		a.mu.Lock()
		session.addMessage(msg)
		session.LastActivity = time.Now()
		notify := a.activeSessionID != session.ID &&
			session.notifyDue(a.now())
		a.mu.Unlock()

		incognito := a.sessionIncognito(session)
		if store := a.store(); store != nil && !incognito {
			if err := store.AddChatEntry(
				session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
			); err != nil {
				a.addLogEntry("WARN", "Failed to save received message: "+err.Error())
				a.emitEvent("history-save-failed", session.ID)
			}
		}

		if notify {
			a.SendNotification(
				"New Message", notificationText(msgText, incognito),
			)
		}

		a.emitEvent("message-received", session.ID, msg)
		a.emitEvent("session-updated", session.ID)
		a.addLogEntry("DEBUG", "Received message | session_id="+session.ID+" msg_id="+metadata.ID())
	}

	sessionsRemaining, removed := a.removeSession(session)
	if !removed {
		return false, false
	}
	// A dialed session is over once it stops reconnecting, so its relay
	// reconnect tokens are of no more use. serverHandler sees to those of
	// a server session.
	if !session.IsServer && !session.incognito {
		a.dropRelayPool(session.ID)
	}

	if store := a.store(); store != nil {
		a.loadHistorySessions(store)
	}

	a.emitEvent("session-closed", session.ID)

	if sessionsRemaining == 0 {
		a.setStatus(StatusDisconnected, "Not connected")
		a.addLogEntry("INFO", "All sessions disconnected")
	}
	return connLost(endErr), true
}

// connLost reports whether err, from Transport.ReceivePayload, means that
// the session's connection is gone while the session itself may go on,
// so that it may be resumed on a new connection: the connection was
// closed locally, by the peer or by the network (kamune.ErrConnClosed,
// which also covers resets), or the socket failed with an error that the
// core does not map to it, such as a host or network that became
// unreachable. A frame that fails to decrypt or verify, or comes out of
// order, ends the session for good, and so does a graceful close by the
// peer.
func connLost(err error) bool {
	if errors.Is(err, kamune.ErrConnClosed) {
		return true
	}
	_, ok := errors.AsType[*net.OpError](err)
	return ok
}

// sendLost reports whether err, from Transport.Send, means that the
// session's connection is gone: kamune.ErrConnClosed, or a write error
// that the core passes on without mapping it to that, such as the
// net.ErrClosed of a relay connection that its receive loop closed after
// a drop, a closed pipe, an end of file, or a socket error (see
// connLost).
func sendLost(err error) bool {
	if err == nil {
		return false
	}
	return connLost(err) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// maxLiveMessages caps the messages that a live session holds in memory
// and shows. A peer can send messages as fast as the connection carries
// them, and without a cap they would fill the memory of the app and of
// its window. The history in storage keeps every message of a session
// that is not incognito.
const maxLiveMessages = 1000

// addMessage adds msg to s, and drops the oldest message once s holds
// maxLiveMessages. It shifts the messages within their array, so a
// slice of s.Messages must not be read after a.mu is released: hand out
// a copy, as emitSessionMessages does. The caller holds a.mu.
func (s *liveSession) addMessage(msg MessageInfo) {
	s.msgCount++
	if over := len(s.Messages) + 1 - maxLiveMessages; over > 0 {
		n := copy(s.Messages, s.Messages[over:])
		clear(s.Messages[n:])
		s.Messages = s.Messages[:n]
	}
	s.Messages = append(s.Messages, msg)
}

// notificationInterval is the least time between two notifications for
// the messages of one session. A peer can send messages as fast as the
// connection carries them, and each would otherwise raise a system
// notification. The messages in between raise none, but the session
// lists them as usual.
const notificationInterval = 5 * time.Second

// notifyDue reports whether a message that s received at now raises a
// notification, which is so unless one was raised within the last
// notificationInterval, and records the notification. The caller holds
// a.mu.
func (s *liveSession) notifyDue(now time.Time) bool {
	if !s.lastNotified.IsZero() &&
		now.Sub(s.lastNotified) < notificationInterval {
		return false
	}
	s.lastNotified = now
	return true
}

// notificationPreviewRunes caps how much of a message a notification
// shows.
const notificationPreviewRunes = 50

// incognitoNotificationText is the notification body for a message
// received in incognito mode.
const incognitoNotificationText = "Message text is hidden in incognito mode"

// notificationText returns the body of the notification for a received
// message whose text is msg: its first notificationPreviewRunes runes. In
// incognito mode it holds none of the text, since the OS may keep
// notifications in a history that outlives the session.
func notificationText(msg string, incognito bool) string {
	if incognito {
		return incognitoNotificationText
	}
	runes := []rune(msg)
	if len(runes) <= notificationPreviewRunes {
		return msg
	}
	return string(runes[:notificationPreviewRunes]) + "…"
}

// keepAliveLoop sends periodic pings to detect dead connections. After 3
// consecutive ping failures, the session is closed.
func (a *App) keepAliveLoop(session *liveSession, stopCh <-chan struct{}) {
	const pingTimeout = 10 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-session.ReceiveDone:
			return
		case <-stopCh:
			return
		case <-ticker.C:
			session.mu.Lock()
			transport := session.Transport
			pongCh := session.pongCh
			failures := session.pingFailures
			session.mu.Unlock()
			a.addLogEntry("DEBUG", "keepalive: pinging peer | session_id="+session.ID+" failures="+
				strconv.Itoa(failures))
			if err := sendPing(transport, pongCh, pingTimeout); err != nil {
				session.mu.Lock()
				session.pingFailures++
				failures = session.pingFailures
				session.mu.Unlock()
				a.addLogEntry("DEBUG", "keepalive: ping failed | session_id="+session.ID+" error="+err.Error()+
					" failures="+strconv.Itoa(failures))
				if failures >= 3 {
					a.addLogEntry("WARN", "Peer unresponsive: "+session.PeerName)
					_ = transport.CloseAbort()
					return
				}
			} else {
				session.mu.Lock()
				session.pingFailures = 0
				session.lastPongAt = time.Now()
				session.mu.Unlock()
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
	// Drain any stale pong from a previous (timed-out) ping BEFORE sending.
	select {
	case <-pongCh:
	default:
	}
	if _, err := t.Send(kamune.Bytes(tok), kamune.RoutePing); err != nil {
		return err
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

// reconnectRetryable reports whether a failed reconnect may succeed on a
// later attempt. Missing storage or resumption state, a resume the peer
// rejected, a handshake the peer or the user refused, and a panic do not
// change between attempts (RFC007 §20.1).
func reconnectRetryable(err error) bool {
	for _, target := range []error{
		kamune.ErrNoResumptionState,
		kamune.ErrMissingStorage,
		kamune.ErrVerificationFailed,
		kamune.ErrHandshakeRejected,
		kamune.ErrPeerKeyMismatch,
		kamune.ErrSelfConnection,
		kamune.ErrVersionMismatch,
		kamune.ErrUnsupportedProtocol,
		kamune.ErrResumeInProgress,
		kamune.ErrResumeRefused,
		storage.ErrNotFound,
		storage.ErrSessionNotFound,
		storage.ErrPeerExpired,
	} {
		if errors.Is(err, target) {
			return false
		}
	}
	return true
}

// reconnectSession attempts to re-establish a session after an
// involuntary disconnect using resumption tokens. It retries with
// exponential backoff up to maxAttempts times, and gives up at once on an
// error that a retry cannot fix (see reconnectRetryable). Returns true if
// reconnection succeeded (caller should restart the receive loop).
//
// DisconnectSession, StopServer and ServiceShutdown cancel reconnectCtx
// before they read the session's transport under session.mu and close it,
// so a session they close never dials its peer again, and a transport
// dialed meanwhile is closed rather than put in place of the one they
// close.
func (a *App) reconnectSession(session *liveSession) bool {
	const (
		maxAttempts = 10
		baseDelay   = 1 * time.Second
		maxDelay    = 30 * time.Second
	)

	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := min(baseDelay*time.Duration(1<<(attempt-1)), maxDelay)
			select {
			case <-time.After(delay):
			case <-session.reconnectCtx.Done():
				return false
			}
		}
		if session.reconnectCtx.Err() != nil {
			return false
		}

		a.addLogEntry(
			"INFO", fmt.Sprintf("Reconnecting session %s (attempt %d/%d)", session.ID, attempt+1, maxAttempts),
		)
		a.emitEvent("session-reconnecting", session.ID, attempt+1, maxAttempts)

		t, err := session.reconnectFn(session.ID)
		if err != nil {
			a.addLogEntry("WARN", "Reconnect failed: "+err.Error())
			if !reconnectRetryable(err) {
				a.addLogEntry("WARN", "Reconnect stopped, the session "+
					"cannot be resumed: "+session.ID)
				return false
			}
			continue
		}

		if session.reconnectCtx.Err() != nil {
			_ = t.Close()
			return false
		}

		if t.Resumed() {
			newStopCh := make(chan struct{})
			session.mu.Lock()
			if session.reconnectCtx.Err() != nil {
				session.mu.Unlock()
				_ = t.Close()
				return false
			}
			session.Transport = t
			session.pingFailures = 0
			session.pongCh = make(chan []byte, 1)
			close(session.keepAliveDone)
			session.keepAliveDone = newStopCh
			session.mu.Unlock()

			a.addLogEntry("INFO", "Reconnected session "+session.ID)
			a.emitEvent("session-reconnected", session.ID)
			go a.keepAliveLoop(session, newStopCh)
			return true
		}

		a.addLogEntry("INFO",
			"Reconnect fell back to a cold session for "+session.ID)
		a.replaceSessionWithCold(session, t)
		return true
	}

	a.addLogEntry("WARN", "Reconnect failed after "+strconv.Itoa(maxAttempts)+" attempts: "+session.ID)
	return false
}

// replaceSessionWithCold ends the dropped session through the existing
// close path and starts a new live session for a reconnect that fell
// back to a cold handshake (RFC007 §20.1).
func (a *App) replaceSessionWithCold(
	old *liveSession, t *kamune.Transport,
) {
	oldID := old.ID
	a.mu.Lock()
	i := slices.Index(a.sessions, old)
	if i >= 0 {
		a.sessions = slices.Delete(a.sessions, i, i+1)
	}
	a.mu.Unlock()

	if !old.incognito {
		a.dropRelayPool(oldID)
	}
	a.emitEvent("session-closed", oldID)

	store := a.store()
	peer := t.RemotePeer()
	a.rememberPeer(store, peer, a.currentVerifMode(), old.incognito)
	identity := a.identifyPeer(store, peer)
	newID := t.SessionID()

	newStopCh := make(chan struct{})
	old.mu.Lock()
	old.ID = newID
	old.PeerName = identity.Label
	old.Identity = identity
	old.RemoteVersion = peer.AppVersion
	old.Transport = t
	old.pingFailures = 0
	old.pongCh = make(chan []byte, 1)
	close(old.keepAliveDone)
	old.keepAliveDone = newStopCh
	old.SessionStartedAt = time.Now()
	old.LastActivity = time.Now()
	old.mu.Unlock()

	if store != nil && !old.incognito {
		if err := store.CreateSession(newID, peer.PublicKey); err != nil {
			a.addLogEntry("WARN",
				"Failed to create session record: "+err.Error())
		}
		a.deriveAndStoreRelayTokens(t, old)
	}

	a.mu.Lock()
	old.mu.Lock()
	stopped := old.reconnectFn == nil || old.reconnectCtx == nil ||
		old.reconnectCtx.Err() != nil
	if stopped {
		old.mu.Unlock()
		a.mu.Unlock()
		_ = t.Close()
		return
	}
	a.sessions = append(a.sessions, old)
	info := old.info()
	old.mu.Unlock()
	a.mu.Unlock()

	a.emitEvent("session-new", info)
	a.addLogEntry("INFO", "New session after cold reconnect: "+newID)
	go a.keepAliveLoop(old, newStopCh)
}
