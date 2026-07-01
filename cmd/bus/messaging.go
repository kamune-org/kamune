package main

import (
	"errors"
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

	if store := a.store(); store != nil {
		store.AddChatEntry(
			sessionID, []byte(text), metadata.Timestamp(), storage.SenderLocal,
		)
	}

	runtime.EventsEmit(a.ctx, "message-sent", sessionID, msg)
	runtime.EventsEmit(a.ctx, "session-updated", sessionID)
	a.addLogEntry("DEBUG", "Sent message to "+sessionID)
	return nil
}

func (a *App) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)
	a.receiveMessagesBlocking(session)

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

func (a *App) receiveMessagesBlocking(session *liveSession) {
	t := session.Transport

	for {
		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				a.addLogEntry("INFO", "Peer disconnected: "+session.ID)
				return
			case errors.Is(err, kamune.ErrConnClosed):
				a.addLogEntry("INFO", "Connection closed: "+session.ID)
				return
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				a.addLogEntry("ERROR", "Receive error: "+err.Error())
				return
			}
		}

		// Handle protocol-level routes before treating as chat.
		switch metadata.Route() {
		case kamune.RoutePing:
			if err := t.Pong(b.GetValue()); err != nil {
				a.addLogEntry("WARN", "Failed to send pong: "+err.Error())
			}
			continue
		case kamune.RoutePong:
			// Pong is consumed by keepAliveLoop's Ping();
			// ignore stray pongs here.
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

		if store := a.store(); store != nil {
			store.AddChatEntry(session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer)
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
		a.addLogEntry("DEBUG", "Received message from "+session.ID)
	}
}

// keepAliveLoop sends periodic pings to detect dead connections. After 3
// consecutive ping failures, the session is closed.
func (a *App) keepAliveLoop(session *liveSession) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-session.ReceiveDone:
			return
		case <-ticker.C:
			if err := session.Transport.Ping(10 * time.Second); err != nil {
				session.pingFailures++
				if session.pingFailures >= 3 {
					a.addLogEntry("WARN", "Peer unresponsive: "+session.PeerName)
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
