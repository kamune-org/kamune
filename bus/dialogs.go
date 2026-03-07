package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune/bus/logger"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
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

	dbLabel := widget.NewLabel(c.dbPathDisplay())
	dbLabel.Wrapping = fyne.TextWrapWord
	dbLabel.Importance = widget.LowImportance

	form := widget.NewForm(
		widget.NewFormItem("Listen Address", addrEntry),
		widget.NewFormItem("Database", dbLabel),
	)

	d := dialog.NewCustomConfirm("Start Server", "Start", "Cancel", form, func(confirmed bool) {
		if confirmed {
			c.startServer(addrEntry.Text, c.DBPath())
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

	dbLabel := widget.NewLabel(c.dbPathDisplay())
	dbLabel.Wrapping = fyne.TextWrapWord
	dbLabel.Importance = widget.LowImportance

	form := widget.NewForm(
		widget.NewFormItem("Server Address", addrEntry),
		widget.NewFormItem("Database", dbLabel),
	)

	d := dialog.NewCustomConfirm("Connect to Server", "Connect", "Cancel", form, func(confirmed bool) {
		if confirmed {
			c.connectToServer(addrEntry.Text, c.DBPath())
		}
	}, c.window)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}

// ---------------------------------------------------------------------------
// Session info & disconnect
// ---------------------------------------------------------------------------

// showSessionInfo displays information about the current session.
// Supports both live sessions and history sessions.
func (c *ChatApp) showSessionInfo() {
	c.mu.RLock()
	liveSession := c.activeSession
	histSession := c.activeHistSession
	c.mu.RUnlock()

	if liveSession == nil && histSession == nil {
		dialog.ShowInformation("No Session", "No active session selected.", c.window)
		return
	}

	var sessionID string
	var msgCount int
	var lastActivity string
	var sessionType string
	var peerName string

	if liveSession != nil {
		sessionID = liveSession.ID
		msgCount = len(liveSession.Messages)
		lastActivity = liveSession.LastActivity.Format("2006-01-02 15:04:05")
		sessionType = "🔒 Live Session"
		peerName = liveSession.PeerName
	} else {
		sessionID = histSession.ID
		msgCount = histSession.MessageCount
		if !histSession.LastMessage.IsZero() {
			lastActivity = histSession.LastMessage.Format("2006-01-02 15:04:05")
		} else {
			lastActivity = "—"
		}
		sessionType = "📖 History Session"
		peerName = histSession.Name
	}

	// Build session info content
	typeLabel := widget.NewLabelWithStyle(sessionType, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	idLabel := widget.NewLabel(sessionID)
	idLabel.Wrapping = fyne.TextWrapWord

	copyBtn := widget.NewButtonWithIcon("Copy ID", theme.ContentCopyIcon(), func() {
		c.app.Clipboard().SetContent(sessionID)
		c.sendNotification("Copied", "Session ID copied to clipboard")
	})
	copyBtn.Importance = widget.LowImportance

	items := []fyne.CanvasObject{
		typeLabel,
		widget.NewSeparator(),
	}

	// Show peer name (display name) if set
	if peerName != "" {
		items = append(items,
			widget.NewLabelWithStyle("Name:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewLabel(peerName),
		)
	}

	// Rename button
	if liveSession != nil {
		renameBtn := widget.NewButtonWithIcon("Rename Session", theme.DocumentCreateIcon(), func() {
			c.showRenameSessionDialog(liveSession)
		})
		renameBtn.Importance = widget.LowImportance
		items = append(items, renameBtn)
		items = append(items, widget.NewSeparator())
	} else if histSession != nil {
		renameBtn := widget.NewButtonWithIcon("Rename Session", theme.DocumentCreateIcon(), func() {
			c.showRenameHistorySessionDialog(histSession)
		})
		renameBtn.Importance = widget.LowImportance
		items = append(items, renameBtn)
		items = append(items, widget.NewSeparator())
	}

	items = append(items,
		widget.NewLabelWithStyle("Session ID:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		idLabel,
		copyBtn,
		widget.NewSeparator(),
		widget.NewLabel(fmt.Sprintf("Messages: %d", msgCount)),
		widget.NewLabel(fmt.Sprintf("Last Activity: %s", lastActivity)),
	)

	// Show peer fingerprint for live sessions with a transport
	if liveSession != nil && liveSession.Transport != nil {
		remotePubKey := liveSession.Transport.RemotePublicKey()
		if len(remotePubKey) > 0 {
			emojiPeerFP := strings.Join(fingerprint.Emoji(remotePubKey), " • ")
			hexPeerFP := fingerprint.Hex(remotePubKey)

			peerFPLabel := widget.NewLabel(emojiPeerFP)
			peerFPLabel.Wrapping = fyne.TextWrapWord

			peerHexLabel := widget.NewLabel(hexPeerFP)
			peerHexLabel.Wrapping = fyne.TextWrapWord
			peerHexLabel.Importance = widget.LowImportance

			copyPeerFPBtn := widget.NewButtonWithIcon("Copy Peer Fingerprint", theme.ContentCopyIcon(), func() {
				content := fmt.Sprintf("Emoji: %s\nHex: %s", emojiPeerFP, hexPeerFP)
				c.app.Clipboard().SetContent(content)
				c.sendNotification("Copied", "Peer fingerprint copied to clipboard")
			})
			copyPeerFPBtn.Importance = widget.LowImportance

			items = append(items,
				widget.NewSeparator(),
				widget.NewLabelWithStyle("Peer Fingerprint:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				peerFPLabel,
				peerHexLabel,
				copyPeerFPBtn,
			)
		}
	}

	// Add history-specific info
	if histSession != nil {
		if !histSession.FirstMessage.IsZero() {
			items = append(items,
				widget.NewLabel(fmt.Sprintf("First Message: %s", histSession.FirstMessage.Format("2006-01-02 15:04:05"))),
			)
		}

		dbPath := c.DBPath()
		if dbPath != "" {
			dbLabel := widget.NewLabel(fmt.Sprintf("Database: %s", dbPath))
			dbLabel.Wrapping = fyne.TextWrapWord
			dbLabel.Importance = widget.LowImportance
			items = append(items, widget.NewSeparator(), dbLabel)
		}
	}

	content := container.NewVBox(items...)

	scrollable := container.NewVScroll(content)
	scrollable.SetMinSize(fyne.NewSize(440, 350))

	d := dialog.NewCustom("Session Info", "Close", scrollable, c.window)
	d.Resize(fyne.NewSize(480, 420))
	d.Show()
}

// showRenameSessionDialog shows a dialog to rename a live session.
func (c *ChatApp) showRenameSessionDialog(session *Session) {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Enter a display name...")
	c.mu.RLock()
	entry.SetText(session.PeerName)
	c.mu.RUnlock()

	form := widget.NewForm(
		widget.NewFormItem("Display Name", entry),
	)

	d := dialog.NewCustomConfirm("Rename Session", "Save", "Cancel", form, func(confirmed bool) {
		if !confirmed {
			return
		}
		newName := strings.TrimSpace(entry.Text)

		c.mu.Lock()
		session.PeerName = newName
		c.mu.Unlock()

		c.runOnMain(func() {
			c.sessionList.Refresh()
			c.tabManager.RefreshAllTabs()
		})

		if newName != "" {
			logger.Infof("Session %s renamed to %q", truncateSessionID(session.ID), newName)
		} else {
			logger.Infof("Session %s name cleared", truncateSessionID(session.ID))
		}
	}, c.window)
	d.Resize(fyne.NewSize(400, 160))
	d.Show()
}

// showRenameHistorySessionDialog shows a dialog to rename a history session.
// The name is persisted to the database via Storage.SetSessionName.
func (c *ChatApp) showRenameHistorySessionDialog(hs *HistorySession) {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Enter a display name...")
	c.mu.RLock()
	entry.SetText(hs.Name)
	c.mu.RUnlock()

	form := widget.NewForm(
		widget.NewFormItem("Display Name", entry),
	)

	d := dialog.NewCustomConfirm("Rename Session", "Save", "Cancel", form, func(confirmed bool) {
		if !confirmed {
			return
		}
		newName := strings.TrimSpace(entry.Text)

		go func() {
			dbPath := c.DBPath()
			store, err := storage.OpenStorage(
				storage.StorageWithDBPath(dbPath),
				storage.StorageWithNoPassphrase(),
			)
			if err != nil {
				c.showError(fmt.Errorf("opening database: %w", err))
				return
			}
			defer func() { _ = store.Close() }()

			if err := store.SetSessionName(hs.ID, newName); err != nil {
				c.showError(fmt.Errorf("saving session name: %w", err))
				return
			}

			c.mu.Lock()
			hs.Name = newName
			c.mu.Unlock()

			c.runOnMain(func() {
				if c.historyList != nil {
					c.historyList.Refresh()
				}
				c.tabManager.RefreshAllTabs()
			})

			if newName != "" {
				logger.Infof("History session %s renamed to %q", truncateSessionID(hs.ID), newName)
			} else {
				logger.Infof("History session %s name cleared", truncateSessionID(hs.ID))
			}
		}()
	}, c.window)
	d.Resize(fyne.NewSize(400, 160))
	d.Show()
}

// disconnectActiveSession closes the current session.
func (c *ChatApp) disconnectActiveSession() {
	c.mu.Lock()
	session := c.activeSession
	c.mu.Unlock()

	if session == nil {
		dialog.ShowInformation("No Session", "No active session to disconnect.", c.window)
		return
	}

	dialog.ShowConfirm("End Session",
		fmt.Sprintf("End session %s?\n\nThis will disconnect from the peer.", truncateSessionID(session.ID)),
		func(confirmed bool) {
			if confirmed {
				logger.Infof("Ending session: %s", session.ID)

				// Close the tab for this session
				c.tabManager.CloseTab(session.ID)

				c.mu.Lock()
				for i, s := range c.sessions {
					if s == session {
						c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
						break
					}
				}
				c.activeSession = nil
				c.mu.Unlock()

				c.sessionList.Refresh()
				c.statusIndicator.SetStatus(StatusDisconnected, "Session ended")
				c.sendNotification("Session Ended", fmt.Sprintf("Disconnected from %s", truncateSessionID(session.ID)))

				// Refresh history so the ended session appears there
				go c.refreshHistorySessions()
			}
		}, c.window)
}

// ---------------------------------------------------------------------------
// Clipboard helpers
// ---------------------------------------------------------------------------

// copyActiveSessionID copies the active session ID to clipboard.
func (c *ChatApp) copyActiveSessionID() {
	id := c.getDisplaySessionID()
	if id == "" {
		dialog.ShowInformation("No Session", "No active session selected.", c.window)
		return
	}

	c.app.Clipboard().SetContent(id)
	c.sendNotification("Copied", "Session ID copied to clipboard")
}

// copyFingerprint copies the fingerprint to clipboard.
func (c *ChatApp) copyFingerprint() {
	if c.emojiFingerprint == "" {
		dialog.ShowInformation("No Fingerprint", "No fingerprint available. Start a server or connect first.", c.window)
		return
	}

	content := c.emojiFingerprint
	if c.hexFingerprint != "" {
		content = fmt.Sprintf("Emoji: %s\nHex: %s", c.emojiFingerprint, c.hexFingerprint)
	}

	c.app.Clipboard().SetContent(content)
	c.sendNotification("Copied", "Fingerprint copied to clipboard")
}
