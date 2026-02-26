package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ---------------------------------------------------------------------------
// Log panel
// ---------------------------------------------------------------------------

// buildLogPanel creates the log viewer panel.
func (c *ChatApp) buildLogPanel() fyne.CanvasObject {
	logUI := c.logViewer.BuildUI()

	closeBtn := widget.NewButtonWithIcon("Close Logs", theme.CancelIcon(), func() {
		c.toggleLogPanel()
	})
	closeBtn.Importance = widget.LowImportance

	header := container.NewBorder(nil, nil, nil, closeBtn, widget.NewLabel(""))

	return container.NewBorder(header, nil, nil, nil, logUI)
}

// toggleLogPanel shows or hides the log panel.
func (c *ChatApp) toggleLogPanel() {
	c.logPanelOpen = !c.logPanelOpen
	if c.logPanelOpen {
		c.logPanel.Show()
		c.mainSplit.SetOffset(0.7)
	} else {
		c.logPanel.Hide()
		c.mainSplit.SetOffset(1.0)
	}
}

// ---------------------------------------------------------------------------
// Session panel (left sidebar)
// ---------------------------------------------------------------------------

// buildSessionPanel creates the left sidebar with session list and controls.
func (c *ChatApp) buildSessionPanel() fyne.CanvasObject {
	// Cleaner header with icon + title
	headerIcon := widget.NewIcon(theme.AccountIcon())
	headerTitle := widget.NewLabelWithStyle("Sessions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	headerRow := container.NewBorder(nil, nil, headerIcon, nil, headerTitle)
	header := container.NewPadded(headerRow)

	// Session list (use custom SessionItem widget)
	c.sessionList = widget.NewList(
		func() int {
			c.mu.RLock()
			defer c.mu.RUnlock()
			return len(c.sessions)
		},
		func() fyne.CanvasObject {
			return NewSessionItem("", false, 0, time.Time{})
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if id < len(c.sessions) {
				session := c.sessions[id]
				isActive := c.activeSession == session
				item := obj.(*SessionItem)
				item.Update(session.ID, isActive, len(session.Messages), session.LastActivity)
			}
		},
	)

	c.sessionList.OnSelected = func(id widget.ListItemID) {
		c.mu.Lock()
		if id < len(c.sessions) {
			c.activeSession = c.sessions[id]
		}
		c.mu.Unlock()
		c.sessionList.Refresh() // ensures active highlight updates across items
		c.refreshMessages()     // also updates welcome/empty overlays via refreshMessages
		c.updateStatus()
	}

	// Connection buttons
	serverBtn := widget.NewButtonWithIcon("Start Server", theme.ComputerIcon(), c.showServerDialog)
	serverBtn.Importance = widget.HighImportance

	clientBtn := widget.NewButtonWithIcon("Connect", theme.LoginIcon(), c.showConnectDialog)

	// Stop server button (initially hidden)
	c.stopServerBtn = widget.NewButtonWithIcon("Stop Server", theme.CancelIcon(), c.stopServer)
	c.stopServerBtn.Importance = widget.DangerImportance
	c.stopServerBtn.Hide()

	buttonBox := container.NewVBox(
		serverBtn,
		clientBtn,
		c.stopServerBtn,
	)

	// Fingerprint display with copy button
	c.fingerprintLbl = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	c.fingerprintLbl.Wrapping = fyne.TextWrapWord

	copyFingerprintBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		c.copyFingerprint()
	})
	copyFingerprintBtn.Importance = widget.LowImportance

	fingerprintContent := container.NewVBox(
		c.fingerprintLbl,
		container.NewCenter(copyFingerprintBtn),
	)

	fingerprintCard := widget.NewCard("Your Fingerprint", "", fingerprintContent)

	// Combine into sidebar
	sidebar := container.NewBorder(
		container.NewVBox(header, widget.NewSeparator(), buttonBox, widget.NewSeparator()),
		fingerprintCard,
		nil,
		nil,
		c.sessionList,
	)

	return container.NewPadded(sidebar)
}

// ---------------------------------------------------------------------------
// Chat panel (center)
// ---------------------------------------------------------------------------

// buildChatPanel creates the main chat area.
func (c *ChatApp) buildChatPanel() fyne.CanvasObject {
	// Messages display
	c.messageList = widget.NewList(
		func() int {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if c.activeSession == nil {
				return 0
			}
			return len(c.activeSession.Messages)
		},
		func() fyne.CanvasObject {
			return NewStyledMessageBubble("", time.Time{}, false)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if c.activeSession != nil && id < len(c.activeSession.Messages) {
				msg := c.activeSession.Messages[id]
				bubble := obj.(*StyledMessageBubble)
				bubble.Update(msg.Text, msg.Timestamp, msg.IsLocal)
				// Set copy callback for context menu support
				bubble.SetOnCopy(func(text string) {
					c.app.Clipboard().SetContent(text)
				})
			}
		},
	)

	// Welcome message when no session is active
	welcomeIcon := widget.NewIcon(theme.MailComposeIcon())
	welcomeTitle := widget.NewLabelWithStyle(
		"Welcome to Kamune Chat!",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)
	welcomeSubtitle := widget.NewLabelWithStyle(
		"Start a server or connect to a peer to begin messaging.\n\n"+
			"Shortcuts:\n• Ctrl+S - Start server\n• Ctrl+N - Connect to server\n• Ctrl+L - Toggle logs",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	welcomeSubtitle.Wrapping = fyne.TextWrapWord
	welcomeSubtitle.Importance = widget.LowImportance

	c.welcomeOverlay = container.NewCenter(
		container.NewVBox(
			container.NewCenter(welcomeIcon),
			welcomeTitle,
			welcomeSubtitle,
		),
	)

	// Empty session message (when session selected but no messages)
	emptySessionLabel := widget.NewLabelWithStyle(
		"No messages yet.\nStart the conversation!",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	emptySessionLabel.Importance = widget.LowImportance
	c.emptyOverlay = container.NewCenter(emptySessionLabel)

	// Message input area
	c.messageEntry = widget.NewMultiLineEntry()
	c.messageEntry.SetPlaceHolder("Type a message… (Enter to send)")
	c.messageEntry.SetMinRowsVisible(2)
	c.messageEntry.Wrapping = fyne.TextWrapWord

	// Enter-to-send
	c.messageEntry.OnSubmitted = func(s string) {
		c.sendMessage()
	}

	c.sendButton = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), c.sendMessage)
	c.sendButton.Importance = widget.HighImportance

	inputRow := container.NewBorder(nil, nil, nil, c.sendButton, c.messageEntry)
	inputArea := container.NewPadded(inputRow)

	// Initial state (no session selected) - hide empty overlay initially
	c.emptyOverlay.Hide()
	messageArea := container.NewStack(c.welcomeOverlay, c.emptyOverlay, c.messageList)

	// Session info header (shows when session is active)
	sessionInfoBar := c.buildSessionInfoBar()

	chatContent := container.NewBorder(sessionInfoBar, inputArea, nil, nil, messageArea)

	return chatContent
}

// ---------------------------------------------------------------------------
// Session info bar & status bar
// ---------------------------------------------------------------------------

// buildSessionInfoBar creates the info bar shown above the chat.
func (c *ChatApp) buildSessionInfoBar() fyne.CanvasObject {
	sessionLabel := widget.NewLabel("")
	sessionLabel.Importance = widget.LowImportance

	copyIDBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		c.copyActiveSessionID()
	})
	copyIDBtn.Importance = widget.LowImportance
	copyIDBtn.Hide()

	endSessionBtn := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
		c.disconnectActiveSession()
	})
	endSessionBtn.Importance = widget.LowImportance
	endSessionBtn.Hide()

	infoBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		c.showSessionInfo()
	})
	infoBtn.Importance = widget.LowImportance
	infoBtn.Hide()

	buttons := container.NewHBox(copyIDBtn, infoBtn, endSessionBtn)
	bar := container.NewBorder(nil, nil, sessionLabel, buttons)

	// Update bar when session changes. The goroutine exits when stopChan is
	// closed during cleanup, preventing a leak.
	go func() {
		var lastSessionID string
		for {
			select {
			case <-c.stopChan:
				return
			case <-time.After(200 * time.Millisecond):
			}

			c.mu.RLock()
			session := c.activeSession
			c.mu.RUnlock()

			if session != nil {
				if session.ID != lastSessionID {
					lastSessionID = session.ID
					fyne.Do(func() {
						sessionLabel.SetText(fmt.Sprintf("Session: %s", truncateSessionID(session.ID)))
						copyIDBtn.Show()
						infoBtn.Show()
						endSessionBtn.Show()
					})
				}
			} else if lastSessionID != "" {
				lastSessionID = ""
				fyne.Do(func() {
					sessionLabel.SetText("")
					copyIDBtn.Hide()
					infoBtn.Hide()
					endSessionBtn.Hide()
				})
			}
		}
	}()

	return container.NewVBox(bar, widget.NewSeparator())
}

// buildStatusBar creates the bottom status bar.
func (c *ChatApp) buildStatusBar() fyne.CanvasObject {
	c.statusLabel = widget.NewLabel("Not connected")

	// Log toggle button
	logToggleBtn := widget.NewButtonWithIcon("Logs", theme.ListIcon(), func() {
		c.toggleLogPanel()
	})
	logToggleBtn.Importance = widget.LowImportance

	// Version label
	versionLabel := widget.NewLabelWithStyle("v"+appVersion, fyne.TextAlignTrailing, fyne.TextStyle{})
	versionLabel.Importance = widget.LowImportance

	statusBox := container.NewHBox(c.statusIndicator, widget.NewSeparator(), c.statusLabel, layout.NewSpacer(), logToggleBtn, widget.NewSeparator(), versionLabel)

	separator := widget.NewSeparator()

	return container.NewVBox(separator, container.NewPadded(statusBox))
}
