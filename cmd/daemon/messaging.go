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

// handleSendMessage sends a message on an existing session and persists it
// to the chat history (mirrors cmd/bus/messaging.go:13-62).
func (d *Daemon) handleSendMessage(cmd Command) {
	var params SendMessageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[params.SessionID]
	d.mu.RUnlock()

	if !ok {
		d.emitError(
			cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}

	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid base64 data: %v", err))
		return
	}

	metadata, err := session.Transport.Send(
		kamune.Bytes(data), kamune.RouteExchangeMessages,
	)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to send message: %v", err))
		return
	}

	msg := MessageInfo{
		Text:      string(data),
		Timestamp: metadata.Timestamp(),
		IsLocal:   true,
	}

	d.mu.Lock()
	session.Messages = append(session.Messages, msg)
	session.LastActivity = time.Now()
	d.mu.Unlock()

	if store := d.store(); store != nil && !d.incognito {
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
		b := kamune.Bytes(nil)
		metadata, err := session.Transport.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				d.addLogEntry("INFO", "Peer disconnected: "+session.ID)
			case errors.Is(err, kamune.ErrConnClosed):
				d.addLogEntry("INFO", "Connection closed: "+session.ID)
				if session.reconnectFn != nil &&
					d.reconnectSession(session) {
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
			if _, err := session.Transport.Send(
				kamune.Bytes(b.GetValue()), kamune.RoutePong,
			); err != nil {
				slog.Warn("failed to send pong",
					slog.String("session_id", session.ID),
					slog.Any("error", err),
				)
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

		d.mu.Lock()
		session.Messages = append(session.Messages, msg)
		session.LastActivity = time.Now()
		d.mu.Unlock()

		if store := d.store(); store != nil && !d.incognito {
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
	t := session.Transport

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

		d.mu.Lock()
		session.Messages = append(session.Messages, msg)
		session.LastActivity = time.Now()
		d.mu.Unlock()

		if store := d.store(); store != nil && !d.incognito {
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
func (d *Daemon) keepAliveLoop(session *liveSession) {
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
			if err := sendPing(session.Transport, session.pongCh, pingTimeout); err != nil {
				session.pingFailures++
				d.addLogEntry("DEBUG", "Keepalive ping failed: "+err.Error())
				if session.pingFailures >= 3 {
					d.addLogEntry("WARN", "Peer unresponsive: "+session.PeerName)
					_ = session.Transport.Close()
					return
				}
			} else {
				session.pingFailures = 0
				session.lastPongAt = time.Now()
			}
		}
	}
}

// sendPing sends a RoutePing and waits for a matching RoutePong within
// timeout. The token-based verification ensures the pong corresponds to
// this specific ping (mirrors cmd/bus/messaging.go:194-217).
func sendPing(t *kamune.Transport, pongCh <-chan []byte, timeout time.Duration) error {
	const pingDataSize = 8
	tok := make([]byte, pingDataSize)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	if _, err := t.Send(kamune.Bytes(tok), kamune.RoutePing); err != nil {
		return err
	}
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
// disconnect using the stored reconnectFn. It retries with exponential backoff
// up to maxAttempts times (mirrors cmd/bus/messaging.go:223-266).
func (d *Daemon) reconnectSession(session *liveSession) bool {
	const (
		maxAttempts = 10
		baseDelay   = 1 * time.Second
		maxDelay    = 30 * time.Second
	)

	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := time.Duration(min(int64(baseDelay)*int64(1<<(attempt-1)), int64(maxDelay)))
			select {
			case <-time.After(delay):
			case <-session.reconnectCtx.Done():
				return false
			}
		}

		d.addLogEntry("INFO", "Reconnecting session "+session.ID+" (attempt "+strconv.Itoa(attempt+1)+"/"+strconv.Itoa(maxAttempts)+")")

		t, err := session.reconnectFn(session.ID)
		if err != nil {
			d.addLogEntry("WARN", "Reconnect failed: "+err.Error())
			continue
		}

		d.mu.Lock()
		session.Transport = t
		session.pingFailures = 0
		session.pongCh = make(chan []byte, 1)
		close(session.keepAliveDone)
		session.keepAliveDone = make(chan struct{})
		d.mu.Unlock()

		d.addLogEntry("INFO", "Reconnected session "+session.ID)
		go d.keepAliveLoop(session)
		return true
	}

	d.addLogEntry("WARN", "Reconnect failed after "+strconv.Itoa(maxAttempts)+" attempts: "+session.ID)
	return false
}
