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
)

func (s *liveSession) snapshotTransport() *kamune.Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Transport
}

func (s *liveSession) appendMessage(msg MessageInfo) {
	s.mu.Lock()
	s.Messages = append(s.Messages, msg)
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

// handleSendMessage sends a message on an existing session and persists it
// to the chat history (mirrors cmd/bus/messaging.go:13-62).
func (d *Daemon) handleSendMessage(cmd Command) {
	var params SendMessageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[params.SessionID]
	d.mu.RUnlock()

	if !ok {
		d.emitError(
			cmd.ID, "session_not_found", fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}

	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		d.emitError(cmd.ID, "invalid_base64", fmt.Sprintf("invalid base64 data: %v", err))
		return
	}

	transport := session.snapshotTransport()
	metadata, err := transport.Send(
		kamune.Bytes(data), kamune.RouteExchangeMessages,
	)
	if err != nil {
		d.emitError(cmd.ID, "send_message_failed", fmt.Sprintf("failed to send message: %v", err))
		return
	}

	msg := MessageInfo{
		Text:      string(data),
		Timestamp: metadata.Timestamp(),
		IsLocal:   true,
	}

	session.appendMessage(msg)

	if store := d.store(); store != nil && !d.isIncognito() {
		store.AddChatEntry(
			params.SessionID, data, metadata.Timestamp(), storage.SenderLocal,
		)
	}

	d.emit(EvtMessageSent, cmd.ID, MapA{
		"session_id": params.SessionID,
		"timestamp":  metadata.Timestamp().Format(time.RFC3339Nano),
	})
	d.emit(EvtSessionUpdated, "", MapS{"session_id": params.SessionID})
	d.addLogEntry("DEBUG", "Sent message to "+params.SessionID)
}

// receiveMessages is the wrapper for client-side (dialed) sessions. It
// closes session.ReceiveDone when the receive loop exits and cleans up the
// session from the map. On involuntary disconnect (ErrConnClosed) it attempts
// transparent resumption when reconnectFn is available (mirrors
// cmd/bus/messaging.go:64-80).
func (d *Daemon) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)

	for {
		transport := session.snapshotTransport()
		b := kamune.Bytes(nil)
		metadata, err := transport.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				d.addLogEntry("INFO", "Peer disconnected: "+session.ID)
			case errors.Is(err, kamune.ErrConnClosed):
				d.addLogEntry("INFO", "Connection closed: "+session.ID)
				if d.reconnectSession(session) {
					continue
				}
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				d.addLogEntry("ERROR", "Receive error: "+err.Error())
			}
			break
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

		msgText := string(b.GetValue())
		msg := MessageInfo{
			Text:      msgText,
			Timestamp: metadata.Timestamp(),
			IsLocal:   false,
		}

		session.appendMessage(msg)

		if store := d.store(); store != nil && !d.isIncognito() {
			store.AddChatEntry(
				session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
			)
		}

		d.emit(EvtMessageReceived, "", MapA{
			"session_id":  session.ID,
			"data_base64": base64.StdEncoding.EncodeToString(b.GetValue()),
			"timestamp":   metadata.Timestamp().Format(time.RFC3339Nano),
		})
		d.emit(EvtSessionUpdated, "", MapS{"session_id": session.ID})
		d.addLogEntry("DEBUG", "Received message from "+session.ID)
	}

	d.removeSession(session.ID)
	d.setStatusIfEmpty(StatusDisconnected, "Not connected")
}

// receiveMessagesBlocking is the blocking receive loop used by the server
// handler. It persists received messages and handles ping/pong (mirrors
// cmd/bus/messaging.go:82-133).
func (d *Daemon) receiveMessagesBlocking(session *liveSession) {
	t := session.snapshotTransport()

	for {
		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				d.addLogEntry("INFO", "Peer disconnected: "+session.ID)
				return
			case errors.Is(err, kamune.ErrConnClosed):
				d.addLogEntry("INFO", "Connection closed: "+session.ID)
				return
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				d.addLogEntry("ERROR", "Receive error: "+err.Error())
				return
			}
		}

		switch metadata.Route() {
		case kamune.RoutePing:
			if _, err := t.Send(kamune.Bytes(b.GetValue()), kamune.RoutePong); err != nil {
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

		msgText := string(b.GetValue())
		msg := MessageInfo{
			Text:      msgText,
			Timestamp: metadata.Timestamp(),
			IsLocal:   false,
		}

		session.appendMessage(msg)

		if store := d.store(); store != nil && !d.isIncognito() {
			store.AddChatEntry(
				session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
			)
		}

		d.emit(EvtMessageReceived, "", MapA{
			"session_id":  session.ID,
			"data_base64": base64.StdEncoding.EncodeToString(b.GetValue()),
			"timestamp":   metadata.Timestamp().Format(time.RFC3339Nano),
		})
		d.emit(EvtSessionUpdated, "", MapS{"session_id": session.ID})
		d.addLogEntry("DEBUG", "Received message from "+session.ID)
	}
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
					_ = transport.Close()
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

// reconnectSession attempts to re-establish a session after an involuntary
// disconnect using the stored reconnectFn. It retries with exponential backoff
// up to maxAttempts times (mirrors cmd/bus/messaging.go:223-266).
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

		t, err := reconnectFn(session.ID)
		if err != nil {
			d.addLogEntry("WARN", "Reconnect failed: "+err.Error())
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
