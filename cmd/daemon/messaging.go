package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
// session from the map (mirrors cmd/bus/messaging.go:64-80).
func (d *Daemon) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)
	d.receiveMessagesBlocking(session)

	d.removeSession(session.ID)
	d.setStatusIfEmpty(StatusDisconnected, "Not connected")
}

// receiveMessagesBlocking is the main receive loop. It persists received
// messages to the chat history and emits events (mirrors
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

		if metadata.Route() == kamune.RoutePing {
			if _, err := t.Send(kamune.Bytes(b.GetValue()), kamune.RoutePong); err != nil {
				slog.Warn("failed to send pong",
					slog.String("session_id", session.ID),
					slog.Any("error", err),
				)
			}
			continue
		}
		if metadata.Route() == kamune.RoutePong {
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
