package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
	"google.golang.org/protobuf/proto"
)

func (s *liveSession) snapshotTransport() *kamune.Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Transport
}

// countMessage counts a message sent or received on the session.
func (s *liveSession) countMessage() {
	s.mu.Lock()
	s.msgCount++
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

func (s *liveSession) deliverPong(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.pongCh <- data:
	default:
	}
}

func closeSignal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (s *liveSession) stop() *kamune.Transport {
	s.mu.Lock()
	cancel := s.reconnectCancel
	s.reconnectCancel = nil
	s.reconnectFn = nil
	closeSignal(s.keepAliveDone)
	transport := s.Transport
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return transport
}

// handleSendMessage sends an encrypted message on an active session and adds it
// to the chat history (mirrors cmd/bus/messaging.go:13-62). The send runs
// after the command returns, in the order the commands arrived on the
// session; see queueSend.
func (d *Daemon) handleSendMessage(cmd Command) {
	var params SendMessageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if params.SessionID == "" {
		d.emitError(cmd.ID, "session_id_required", "session_id is required")
		return
	}
	if params.DataBase64 == "" {
		d.emitError(cmd.ID, "data_base64_required", "data_base64 is required")
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[params.SessionID]
	d.mu.RUnlock()

	if !ok {
		d.emitError(
			cmd.ID, "session_not_found",
			fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}

	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		d.emitError(
			cmd.ID, "invalid_base64",
			fmt.Sprintf("invalid base64 data: %v", err),
		)
		return
	}

	d.queueSend(session, queuedSend{cmd: cmd, data: data})
}

// queuedSend is a send_message command waiting to be sent.
type queuedSend struct {
	cmd  Command
	data []byte
}

// queueSend queues job on session without waiting for it to be sent.
// One goroutine per session sends the queued messages one at a time, so
// they go out, are stored and are reported in the order they were
// queued. The goroutine runs while the queue has messages.
func (d *Daemon) queueSend(session *liveSession, job queuedSend) {
	session.sendMu.Lock()
	session.sendQueue = append(session.sendQueue, job)
	start := !session.sending
	session.sending = true
	session.sendMu.Unlock()
	if start {
		d.wg.Go(func() { d.drainSends(session) })
	}
}

// drainSends sends the messages queued on session until none is left.
func (d *Daemon) drainSends(session *liveSession) {
	for {
		session.sendMu.Lock()
		if len(session.sendQueue) == 0 {
			session.sendQueue = nil
			session.sending = false
			session.sendMu.Unlock()
			return
		}
		job := session.sendQueue[0]
		session.sendQueue[0] = queuedSend{}
		session.sendQueue = session.sendQueue[1:]
		session.sendMu.Unlock()

		d.sendQueued(session, job)
	}
}

// sendQueued sends job on session and reports a panic as an error on
// job's command.
func (d *Daemon) sendQueued(session *liveSession, job queuedSend) {
	defer func() {
		if msg := recover(); msg != nil {
			d.emitError(
				job.cmd.ID,
				"goroutine_panic",
				fmt.Sprintf("goroutine panic: %v", msg),
			)
		}
	}()
	d.sendMessage(job.cmd, session, session.ID, job.data)
}

func (d *Daemon) sendMessage(
	cmd Command, session *liveSession, sessionID string, data []byte,
) {
	transport := session.snapshotTransport()
	metadata, err := transport.Send(
		kamune.Bytes(data), kamune.RouteExchangeMessages,
	)
	if err != nil {
		d.emitError(
			cmd.ID, "send_message_failed",
			fmt.Sprintf("failed to send message: %v", err),
		)
		return
	}

	session.countMessage()

	d.saveChatEntry(
		sessionID, data, metadata.Timestamp(), storage.SenderLocal,
	)

	d.emit(EvtMessageSent, cmd.ID, MapA{
		"session_id": sessionID,
		"timestamp":  metadata.Timestamp().Format(time.RFC3339Nano),
	})
	d.emit(EvtSessionUpdated, "", MapS{"session_id": sessionID})
	d.addLogEntry("DEBUG", "Sent message to "+sessionID)
}

// receiveMessages is the wrapper for client-side (dialed) sessions. It
// closes session.ReceiveDone when the receive loop exits and cleans up the
// session from the map, also when the loop panics. On involuntary
// disconnect (ErrConnClosed) it attempts transparent resumption when
// reconnectFn is available (mirrors cmd/bus/messaging.go:64-80). A
// session that ends on its own is stopped and its transport closed; see
// endSession.
func (d *Daemon) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)
	// endErr is the error that ended the session, if any.
	var endErr error
	defer func() {
		// A session the daemon closed itself is no longer listed, and
		// its closer stopped it.
		if d.finishSession(session) {
			endSession(session, endErr)
		}
	}()

	for {
		transport := session.snapshotTransport()
		metadata, payload, err := transport.ReceivePayload()
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				d.addLogEntry("INFO", "Peer disconnected: "+session.ID)
				d.dropRelayPool(session.ID)
			case errors.Is(err, kamune.ErrConnClosed):
				d.addLogEntry("INFO", "Connection closed: "+session.ID)
				// Release the dropped connection; a reconnect
				// makes a new one. CloseAbort keeps the
				// resumption tokens.
				_ = transport.CloseAbort()
				if d.reconnectSession(session) {
					continue
				}
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				d.addLogEntry("ERROR", "Receive error: "+err.Error())
			}
			endErr = err
			break
		}

		if metadata.Route() == kamune.RouteSessionData {
			d.finishRelayToken(session, payload)
			continue
		}
		b := kamune.Bytes(nil)
		if err := proto.Unmarshal(payload, b); err != nil {
			d.addLogEntry("WARN", "bad payload: "+err.Error())
			continue
		}

		switch metadata.Route() {
		case kamune.RoutePing:
			if _, err := transport.Send(
				kamune.Bytes(b.GetValue()), kamune.RoutePong,
			); err != nil {
				slog.Warn("failed to send pong",
					slog.String("session_id", session.ID),
					slog.Any("error", err),
				)
			}
			continue
		case kamune.RoutePong:
			session.deliverPong(b.GetValue())
			continue
		}

		session.countMessage()

		d.saveChatEntry(
			session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
		)

		d.emit(EvtMessageReceived, "", MapA{
			"session_id":  session.ID,
			"data_base64": base64.StdEncoding.EncodeToString(b.GetValue()),
			"timestamp":   metadata.Timestamp().Format(time.RFC3339Nano),
		})
		d.emit(EvtSessionUpdated, "", MapS{"session_id": session.ID})
		d.addLogEntry("DEBUG", "Received message from "+session.ID)
	}
}

// endSession stops session, a dialed session that ended on its own with
// err, and closes its transport: the kamune library leaves the connection
// open when it drops, and after some receive errors. A connection that
// dropped or that the peer closed is closed at once. Otherwise the peer
// may still be there: Close tells it that the session is over, and the
// session can no longer be resumed.
func endSession(session *liveSession, err error) {
	t := session.stop()
	if t == nil {
		return
	}
	if errors.Is(err, kamune.ErrPeerDisconnected) ||
		errors.Is(err, kamune.ErrConnClosed) {
		_ = t.CloseAbort()
		return
	}
	_ = t.Close()
}

// receiveMessagesBlocking is the blocking receive loop used by the server
// handler. It persists received messages and handles ping/pong (mirrors
// cmd/bus/messaging.go:82-133). It returns the error that ended the
// session.
func (d *Daemon) receiveMessagesBlocking(session *liveSession) error {
	t := session.snapshotTransport()

	for {
		metadata, payload, err := t.ReceivePayload()
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				d.addLogEntry("INFO", "Peer disconnected: "+session.ID)
				return err
			case errors.Is(err, kamune.ErrConnClosed):
				d.addLogEntry("INFO", "Connection closed: "+session.ID)
				return err
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				d.addLogEntry("ERROR", "Receive error: "+err.Error())
				return err
			}
		}

		if metadata.Route() == kamune.RouteSessionData {
			d.finishRelayToken(session, payload)
			continue
		}
		b := kamune.Bytes(nil)
		if err := proto.Unmarshal(payload, b); err != nil {
			d.addLogEntry("WARN", "bad payload: "+err.Error())
			continue
		}

		switch metadata.Route() {
		case kamune.RoutePing:
			if _, err := t.Send(
				kamune.Bytes(b.GetValue()), kamune.RoutePong,
			); err != nil {
				slog.Warn("failed to send pong",
					slog.String("session_id", session.ID),
					slog.Any("error", err),
				)
			}
			continue
		case kamune.RoutePong:
			session.deliverPong(b.GetValue())
			continue
		}

		session.countMessage()

		d.saveChatEntry(
			session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
		)

		d.emit(EvtMessageReceived, "", MapA{
			"session_id":  session.ID,
			"data_base64": base64.StdEncoding.EncodeToString(b.GetValue()),
			"timestamp":   metadata.Timestamp().Format(time.RFC3339Nano),
		})
		d.emit(EvtSessionUpdated, "", MapS{"session_id": session.ID})
		d.addLogEntry("DEBUG", "Received message from "+session.ID)
	}
}

// saveChatEntry adds a message of the session sessionID to its history,
// unless storage is closed or incognito is on. The message was sent or
// received all the same, so a failure is logged and reported with
// history_save_failed instead.
func (d *Daemon) saveChatEntry(
	sessionID string, data []byte, ts time.Time, sender storage.Sender,
) {
	store := d.store()
	if store == nil || d.isIncognito() {
		return
	}
	err := store.AddChatEntry(sessionID, data, ts, sender)
	if err == nil {
		return
	}
	d.addLogEntry("WARN",
		"Failed to save a message of session "+sessionID+" to history: "+
			err.Error())
	d.emit(EvtHistorySaveFailed, "", MapS{
		"session_id": sessionID, "error": err.Error(),
	})
}

// keepAliveLoop sends periodic pings to detect dead connections. After 3
// consecutive ping failures it closes the transport (mirrors
// cmd/bus/messaging.go:160-189).
func (d *Daemon) keepAliveLoop(
	session *liveSession,
	keepAliveDone <-chan struct{},
) {
	const pingTimeout = 10 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-session.ReceiveDone:
			return
		case <-keepAliveDone:
			return
		case <-ticker.C:
			session.mu.Lock()
			transport := session.Transport
			pongCh := session.pongCh
			session.mu.Unlock()
			if err := sendPing(transport, pongCh, pingTimeout); err != nil {
				session.mu.Lock()
				if session.Transport != transport {
					session.mu.Unlock()
					return
				}
				session.pingFailures++
				failures := session.pingFailures
				transport = session.Transport
				peerName := session.PeerName
				session.mu.Unlock()
				d.addLogEntry("DEBUG", "Keepalive ping failed: "+err.Error())
				if failures >= 3 {
					d.addLogEntry("WARN", "Peer unresponsive: "+peerName)
					_ = transport.CloseAbort()
					return
				}
			} else {
				session.mu.Lock()
				if session.Transport != transport {
					session.mu.Unlock()
					return
				}
				session.pingFailures = 0
				session.lastPongAt = time.Now()
				session.mu.Unlock()
			}
		}
	}
}

// sendPing sends a RoutePing and waits for a matching RoutePong within
// timeout. The token-based verification ensures the pong corresponds to
// this specific ping (mirrors cmd/bus/messaging.go:194-217).
type pingTransport interface {
	Send(kamune.Transferable, kamune.Route) (*kamune.Metadata, error)
}

func sendPing(
	t pingTransport, pongCh <-chan []byte, timeout time.Duration,
) error {
	const pingDataSize = 8
	tok := make([]byte, pingDataSize)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
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

var (
	// errNotResumable is returned by a reconnect function when the session
	// has no stored state to resume from.
	errNotResumable = errors.New("session cannot be resumed")
	// errReconnectPanic is returned by tryReconnect when the reconnect
	// function panics.
	errReconnectPanic = errors.New("reconnect panicked")
)

// tryReconnect calls fn and turns a panic into an error wrapping
// errReconnectPanic, so that a failed reconnect ends the session instead of
// the goroutine that receives on it.
func tryReconnect(
	fn func(string) (*kamune.Transport, error), sessionID string,
) (t *kamune.Transport, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			t, err = nil, fmt.Errorf("%w: %v", errReconnectPanic, msg)
		}
	}()
	return fn(sessionID)
}

// reconnectRetryable reports whether a failed reconnect may succeed on a
// later attempt. Missing storage or resumption state, a resume the peer
// rejected and a panic do not change between attempts.
func reconnectRetryable(err error) bool {
	for _, target := range []error{
		errNotResumable,
		errReconnectPanic,
		kamune.ErrMissingStorage,
		kamune.ErrResumptionRejected,
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

// reconnectSession attempts to re-establish a session after an involuntary
// disconnect using the stored reconnectFn. It retries with exponential backoff
// up to maxAttempts times, and gives up at once on an error that a retry
// cannot fix (mirrors cmd/bus/messaging.go:223-266).
func (d *Daemon) reconnectSession(session *liveSession) bool {
	const (
		maxAttempts = 10
		baseDelay   = 1 * time.Second
		maxDelay    = 30 * time.Second
	)

	session.mu.Lock()
	reconnectCtx := session.reconnectCtx
	reconnectFn := session.reconnectFn
	session.mu.Unlock()
	if reconnectCtx == nil || reconnectFn == nil {
		return false
	}

	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := time.Duration(min(int64(baseDelay)*int64(1<<(attempt-1)), int64(maxDelay)))
			select {
			case <-time.After(delay):
			case <-reconnectCtx.Done():
				return false
			}
		}

		d.addLogEntry("INFO", "Reconnecting session "+session.ID+" (attempt "+strconv.Itoa(attempt+1)+"/"+strconv.Itoa(maxAttempts)+")")

		d.emit(EvtSessionReconnecting, "", MapA{
			"session_id":   session.ID,
			"attempt":      attempt + 1,
			"max_attempts": maxAttempts,
		})

		t, err := tryReconnect(reconnectFn, session.ID)
		if err != nil {
			d.addLogEntry("WARN", "Reconnect failed: "+err.Error())
			if !reconnectRetryable(err) {
				return false
			}
			continue
		}

		if reconnectCtx.Err() != nil {
			t.Close()
			return false
		}

		session.mu.Lock()
		if session.reconnectFn == nil {
			session.mu.Unlock()
			t.Close()
			return false
		}
		session.Transport = t
		session.pingFailures = 0
		session.pongCh = make(chan []byte, 1)
		closeSignal(session.keepAliveDone)
		session.keepAliveDone = make(chan struct{})
		keepAliveDone := session.keepAliveDone
		session.mu.Unlock()

		d.addLogEntry("INFO", "Reconnected session "+session.ID)
		d.emit(EvtSessionReconnected, "", MapS{"session_id": session.ID})
		go d.keepAliveLoop(session, keepAliveDone)
		return true
	}

	d.addLogEntry("WARN", "Reconnect failed after "+strconv.Itoa(maxAttempts)+" attempts: "+session.ID)
	return false
}
