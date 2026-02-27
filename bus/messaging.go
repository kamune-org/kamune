package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2/dialog"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/bus/logger"
)

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

// receiveMessagesBlocking receives messages in a blocking loop.
// This is used by the server handler to keep the connection alive.
func (c *ChatApp) receiveMessagesBlocking(session *Session) {
	for {
		b := kamune.Bytes(nil)
		metadata, err := session.Transport.Receive(b)
		if err != nil {
			// Save session state so it can be resumed later.
			c.saveSessionState(session)

			if errors.Is(err, kamune.ErrConnClosed) {
				c.runOnMain(func() {
					c.statusIndicator.SetStatus(StatusDisconnected, "Disconnected")
					c.updateStatusText("Connection closed")
				})
				logger.Infof("Connection closed for session %s", session.ID)
				return
			}
			logger.Errorf("receiving message for session %s: %v", session.ID, err)
			c.runOnMain(func() {
				c.statusIndicator.SetStatus(StatusError, "Receive error")
			})
			return
		}

		msgText := string(b.GetValue())
		msg := ChatMessage{
			Text:      msgText,
			Timestamp: metadata.Timestamp(),
			IsLocal:   false,
		}

		c.mu.Lock()
		session.Messages = append(session.Messages, msg)
		session.LastActivity = time.Now()
		isActiveSession := c.activeSession == session
		c.mu.Unlock()

		// Store in database
		go func(data []byte, ts time.Time) {
			if err := session.Transport.Store().AddChatEntry(
				session.ID,
				data,
				ts,
				kamune.SenderPeer,
			); err != nil {
				logger.Errorf("failed to persist peer chat entry for session %s: %v", session.ID, err)
			}
		}(b.GetValue(), metadata.Timestamp())

		// Send notification if different session is active
		if !isActiveSession {
			previewText := msgText
			if len(previewText) > 50 {
				previewText = previewText[:50] + "..."
			}
			c.sendNotification("New Message", previewText)
		}

		logger.Debugf("Received message in session %s: %d bytes", session.ID, len(msgText))
		c.refreshSessionMessages(session.ID)
	}
}

// receiveMessages receives messages for client connections.
// The caller is expected to invoke this in its own goroutine (go c.receiveMessages(session)).
// For server connections, use receiveMessagesBlocking instead.
func (c *ChatApp) receiveMessages(session *Session) {
	c.receiveMessagesBlocking(session)
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

// sendMessage sends the current message to the active session.
func (c *ChatApp) sendMessage() {
	text := strings.TrimSpace(c.messageEntry.Text)
	if text == "" {
		return
	}

	// Don't allow sending in history view mode
	if c.isViewingHistory() {
		return
	}

	c.mu.RLock()
	session := c.activeSession
	c.mu.RUnlock()

	if session == nil || session.Transport == nil {
		dialog.ShowError(errors.New("no active session"), c.window)
		return
	}

	metadata, err := session.Transport.Send(
		kamune.Bytes([]byte(text)),
		kamune.RouteExchangeMessages,
	)
	if err != nil {
		c.showError(fmt.Errorf("sending message: %w", err))
		logger.Errorf("Failed to send message: %v", err)
		return
	}

	msg := ChatMessage{
		Text:      text,
		Timestamp: metadata.Timestamp(),
		IsLocal:   true,
	}

	c.mu.Lock()
	session.Messages = append(session.Messages, msg)
	session.LastActivity = time.Now()
	c.mu.Unlock()

	// Store in database
	go func() {
		if err := session.Transport.Store().AddChatEntry(
			session.ID,
			[]byte(text),
			metadata.Timestamp(),
			kamune.SenderLocal,
		); err != nil {
			logger.Errorf("failed to persist local chat entry for session %s: %v", session.ID, err)
		}
	}()

	c.runOnMain(func() {
		if c.messageEntry != nil {
			c.messageEntry.SetText("")
		}
	})

	logger.Debugf("Sent message in session %s: %d bytes", session.ID, len(text))
	c.refreshSessionMessages(session.ID)
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

// refreshSessionMessages refreshes the tab for a specific session ID.
// Use this when a background session (not the active tab) receives a message.
func (c *ChatApp) refreshSessionMessages(sessionID string) {
	if c.tabManager == nil {
		return
	}
	c.tabManager.RefreshTab(sessionID)
}
