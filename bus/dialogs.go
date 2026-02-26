package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune/bus/logger"
)

// ---------------------------------------------------------------------------
// Connection dialogs
// ---------------------------------------------------------------------------

// showServerDialog displays the server configuration dialog.
func (c *ChatApp) showServerDialog() {
	if c.serverRunning {
		dialog.ShowInformation("Server Running", "A server is already running.\n\nStop the current server before starting a new one.", c.window)
		return
	}

	addrEntry := widget.NewEntry()
	addrEntry.SetText("127.0.0.1:9000")
	addrEntry.SetPlaceHolder("Address:Port")

	dbEntry := widget.NewEntry()
	dbEntry.SetText(getDefaultDBDir())
	dbEntry.SetPlaceHolder("Database path")

	form := widget.NewForm(
		widget.NewFormItem("Listen Address", addrEntry),
		widget.NewFormItem("Database", dbEntry),
	)

	d := dialog.NewCustomConfirm("Start Server", "Start", "Cancel", form, func(confirmed bool) {
		if confirmed {
			c.startServer(addrEntry.Text, dbEntry.Text)
		}
	}, c.window)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}

// showConnectDialog displays the client connection dialog.
func (c *ChatApp) showConnectDialog() {
	addrEntry := widget.NewEntry()
	addrEntry.SetText("127.0.0.1:9000")
	addrEntry.SetPlaceHolder("Address:Port")

	dbEntry := widget.NewEntry()
	dbEntry.SetText(getDefaultDBDir())
	dbEntry.SetPlaceHolder("Database path")

	form := widget.NewForm(
		widget.NewFormItem("Server Address", addrEntry),
		widget.NewFormItem("Database", dbEntry),
	)

	d := dialog.NewCustomConfirm("Connect to Server", "Connect", "Cancel", form, func(confirmed bool) {
		if confirmed {
			c.connectToServer(addrEntry.Text, dbEntry.Text)
		}
	}, c.window)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}

// ---------------------------------------------------------------------------
// Session info & disconnect
// ---------------------------------------------------------------------------

// showSessionInfo displays information about the current session.
func (c *ChatApp) showSessionInfo() {
	c.mu.RLock()
	session := c.activeSession
	c.mu.RUnlock()

	if session == nil {
		dialog.ShowInformation("No Session", "No active session selected", c.window)
		return
	}

	// Build session info content
	idLabel := widget.NewLabel(session.ID)
	idLabel.Wrapping = fyne.TextWrapWord

	copyBtn := widget.NewButtonWithIcon("Copy ID", theme.ContentCopyIcon(), func() {
		c.app.Clipboard().SetContent(session.ID)
		c.sendNotification("Copied", "Session ID copied to clipboard")
	})

	content := container.NewVBox(
		widget.NewLabelWithStyle("Session ID:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		idLabel,
		copyBtn,
		widget.NewSeparator(),
		widget.NewLabel(fmt.Sprintf("Messages: %d", len(session.Messages))),
		widget.NewLabel(fmt.Sprintf("Last Activity: %s", session.LastActivity.Format("2006-01-02 15:04:05"))),
	)

	d := dialog.NewCustom("Session Info", "Close", content, c.window)
	d.Resize(fyne.NewSize(450, 250))
	d.Show()
}

// disconnectActiveSession closes the current session.
func (c *ChatApp) disconnectActiveSession() {
	c.mu.Lock()
	session := c.activeSession
	c.mu.Unlock()

	if session == nil {
		dialog.ShowInformation("No Session", "No active session to disconnect", c.window)
		return
	}

	dialog.ShowConfirm("End Session", fmt.Sprintf("End session %s?\n\nThis will disconnect from the peer.", truncateSessionID(session.ID)), func(confirmed bool) {
		if confirmed {
			logger.Infof("Ending session: %s", session.ID)

			if session.Transport != nil {
				c.saveSessionState(session)
				if err := session.Transport.Close(); err != nil {
					logger.Errorf("failed to close transport for session %s: %v", session.ID, err)
				}
			}

			c.mu.Lock()
			// Remove from sessions list
			for i, s := range c.sessions {
				if s == session {
					c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
					break
				}
			}
			c.activeSession = nil
			c.mu.Unlock()

			c.sessionList.Refresh()
			c.refreshMessages()
			c.statusIndicator.SetStatus(StatusDisconnected, "Session ended")
			c.sendNotification("Session Ended", fmt.Sprintf("Disconnected from %s", truncateSessionID(session.ID)))
		}
	}, c.window)
}

// ---------------------------------------------------------------------------
// Clipboard helpers
// ---------------------------------------------------------------------------

// copyActiveSessionID copies the active session ID to clipboard.
func (c *ChatApp) copyActiveSessionID() {
	c.mu.RLock()
	session := c.activeSession
	c.mu.RUnlock()

	if session == nil {
		dialog.ShowInformation("No Session", "No active session selected", c.window)
		return
	}

	c.app.Clipboard().SetContent(session.ID)
	c.sendNotification("Copied", "Session ID copied to clipboard")
}

// copyFingerprint copies the fingerprint to clipboard.
func (c *ChatApp) copyFingerprint() {
	if c.emojiFingerprint == "" {
		dialog.ShowInformation("No Fingerprint", "No fingerprint available. Start a server or connect first.", c.window)
		return
	}

	// Copy both emoji and hex if available
	content := c.emojiFingerprint
	if c.hexFingerprint != "" {
		content = fmt.Sprintf("Emoji: %s\nHex: %s", c.emojiFingerprint, c.hexFingerprint)
	}

	c.app.Clipboard().SetContent(content)
	c.sendNotification("Copied", "Fingerprint copied to clipboard")
}
