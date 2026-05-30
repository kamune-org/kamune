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
	a.addLogEntry("DEBUG", "Sent message to "+sessionID)
	return nil
}

func (a *App) receiveMessages(session *liveSession) {
	defer close(session.ReceiveDone)
	a.receiveMessagesBlocking(session)
}

func (a *App) receiveMessagesBlocking(session *liveSession) {
	t := session.Transport

	for {
		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			if errors.Is(err, kamune.ErrConnClosed) {
				a.addLogEntry("INFO", "Connection closed: "+session.ID)
			} else {
				a.addLogEntry("ERROR", "Receive error: "+err.Error())
			}
			return
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
		a.addLogEntry("DEBUG", "Received message from "+session.ID)
	}
}
