package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"

	"github.com/kamune-org/kamune/bus/logger"
)

// notificationConfig controls notification behavior
type notificationConfig struct {
	enabled     bool
	soundOnRecv bool
}

const (
	appVersion = "1.1.0"
)

// ChatMessage represents a single message in the conversation
type ChatMessage struct {
	Text      string
	Timestamp time.Time
	IsLocal   bool
}

// Session represents an active chat session
type Session struct {
	ID           string
	PeerName     string
	Transport    *kamune.Transport
	Messages     []ChatMessage
	LastActivity time.Time
}

// ChatApp is the main application state
type ChatApp struct {
	app    fyne.App
	window fyne.Window

	// UI components
	sessionList    *widget.List
	messageList    *widget.List
	messageEntry   *widget.Entry
	sendButton     *widget.Button
	statusLabel    *widget.Label
	fingerprintLbl *widget.Label
	stopServerBtn  *widget.Button

	// Chat overlays (stored so we can reliably toggle them on session/message changes)
	welcomeOverlay fyne.CanvasObject
	emptyOverlay   fyne.CanvasObject

	// Log viewer panel
	logViewer    *LogViewer
	logPanel     fyne.CanvasObject
	logPanelOpen bool
	mainSplit    *container.Split

	// State
	sessions         []*Session
	activeSession    *Session
	mu               sync.RWMutex
	stopChan         chan struct{}
	isServer         bool
	serverRunning    bool
	emojiFingerprint string
	hexFingerprint   string
	serverListener   interface{ Close() error } // stores net.Listener for stopping

	// History viewer
	historyViewer *HistoryViewer

	// Status indicator
	statusIndicator *StatusIndicator

	// Notification settings
	notifications notificationConfig

	// GUI-based peer verifier
	verifier         *GUIVerifier
	verificationMode VerificationMode
}

// NewChatApp creates a new chat application instance
func NewChatApp(app fyne.App, window fyne.Window) *ChatApp {
	c := &ChatApp{
		app:              app,
		window:           window,
		sessions:         make([]*Session, 0),
		stopChan:         make(chan struct{}),
		verificationMode: VerificationModeQuick, // Auto-accept known peers
	}
	c.historyViewer = NewHistoryViewer(app, window)
	c.statusIndicator = NewStatusIndicator()
	c.notifications = notificationConfig{enabled: true, soundOnRecv: false}
	c.verifier = NewGUIVerifier(app, window)
	c.logViewer = NewLogViewer()
	return c
}

// BuildUI constructs the main user interface
func (c *ChatApp) BuildUI() fyne.CanvasObject {
	// Set up menus
	c.setupMenus()

	// Set up keyboard shortcuts
	c.setupShortcuts()

	// Create the session list panel (left sidebar)
	sessionPanel := c.buildSessionPanel()

	// Create the chat panel (center)
	chatPanel := c.buildChatPanel()

	// Create the status bar (bottom)
	statusBar := c.buildStatusBar()

	// Build log panel (hidden by default)
	c.logPanel = c.buildLogPanel()
	c.logPanel.Hide()

	// Main layout with split view
	split := container.NewHSplit(sessionPanel, chatPanel)
	split.SetOffset(0.25)

	// Create vertical split for log panel
	c.mainSplit = container.NewVSplit(split, c.logPanel)
	c.mainSplit.SetOffset(1.0) // Log panel hidden

	// Combine with status bar
	mainContent := container.NewBorder(nil, statusBar, nil, nil, c.mainSplit)

	// Start log viewer
	c.logViewer.Start()

	return mainContent
}

// buildLogPanel creates the log viewer panel
func (c *ChatApp) buildLogPanel() fyne.CanvasObject {
	logUI := c.logViewer.BuildUI()

	closeBtn := widget.NewButtonWithIcon("Close Logs", theme.CancelIcon(), func() {
		c.toggleLogPanel()
	})
	closeBtn.Importance = widget.LowImportance

	header := container.NewBorder(nil, nil, nil, closeBtn, widget.NewLabel(""))

	return container.NewBorder(header, nil, nil, nil, logUI)
}

// toggleLogPanel shows or hides the log panel
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

// setupMenus configures the application menu bar
func (c *ChatApp) setupMenus() {
	// File menu
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Start Server...", c.showServerDialog),
		fyne.NewMenuItem("Connect to Server...", c.showConnectDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("View History...", c.historyViewer.ShowHistoryDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() {
			c.cleanup()
			c.app.Quit()
		}),
	)

	// Edit menu
	editMenu := fyne.NewMenu("Edit",
		fyne.NewMenuItem("Clear Messages", func() {
			c.mu.Lock()
			if c.activeSession != nil {
				c.activeSession.Messages = make([]ChatMessage, 0)
			}
			c.mu.Unlock()
			c.refreshMessages()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Copy Session ID", func() {
			c.copyActiveSessionID()
		}),
		fyne.NewMenuItem("Copy Fingerprint", func() {
			c.copyFingerprint()
		}),
	)

	// Session menu
	sessionMenu := fyne.NewMenu("Session",
		fyne.NewMenuItem("Session Info", func() {
			c.showSessionInfo()
		}),
		fyne.NewMenuItem("Copy Session ID", func() {
			c.copyActiveSessionID()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("End Session", func() {
			c.disconnectActiveSession()
		}),
	)

	// View menu
	viewMenu := fyne.NewMenu("View",
		fyne.NewMenuItem("Toggle Logs", func() {
			c.toggleLogPanel()
		}),
		fyne.NewMenuItem("Clear Logs", func() {
			c.logViewer.Clear()
		}),
	)

	// Settings menu
	settingsMenu := fyne.NewMenu("Settings",
		fyne.NewMenuItem("Verification: Strict", func() {
			c.verificationMode = VerificationModeStrict
			c.showVerificationModeNotification()
		}),
		fyne.NewMenuItem("Verification: Quick", func() {
			c.verificationMode = VerificationModeQuick
			c.showVerificationModeNotification()
		}),
		fyne.NewMenuItem("Verification: Auto-Accept", func() {
			c.verificationMode = VerificationModeAutoAccept
			c.showVerificationModeNotification()
		}),
	)

	// Help menu
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("Keyboard Shortcuts", func() {
			c.showShortcutsHelp()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("About Kamune Chat", func() {
			dialog.ShowInformation("About Kamune Chat",
				fmt.Sprintf("Kamune Chat GUI v%s\n\nA secure messaging application built with Fyne.\n\nPowered by the Kamune protocol for end-to-end encrypted communication.\n\nShortcuts:\n• Ctrl+W - Close window\n• Ctrl+N - New connection\n• Ctrl+S - Start server\n• Ctrl+H - View history\n• Ctrl+L - Toggle logs", appVersion),
				c.window)
		}),
	)

	mainMenu := fyne.NewMainMenu(fileMenu, editMenu, sessionMenu, viewMenu, settingsMenu, helpMenu)
	c.window.SetMainMenu(mainMenu)
}

// showShortcutsHelp displays keyboard shortcuts
func (c *ChatApp) showShortcutsHelp() {
	shortcuts := `Keyboard Shortcuts:

• Ctrl+W / Cmd+W - Close application
• Ctrl+N / Cmd+N - Connect to server
• Ctrl+S / Cmd+S - Start server
• Ctrl+H / Cmd+H - View history
• Ctrl+L / Cmd+L - Toggle log panel
• Enter - Send message (in message field)

Right-click on sessions or messages for context menus.`

	dialog.ShowInformation("Keyboard Shortcuts", shortcuts, c.window)
}

// copyActiveSessionID copies the active session ID to clipboard
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

// copyFingerprint copies the fingerprint to clipboard
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

// showVerificationModeNotification displays the current verification mode
func (c *ChatApp) showVerificationModeNotification() {
	var modeText string
	switch c.verificationMode {
	case VerificationModeStrict:
		modeText = "Strict - All peers require verification"
	case VerificationModeQuick:
		modeText = "Quick - Known peers auto-accepted"
	case VerificationModeAutoAccept:
		modeText = "Auto-Accept - All peers accepted (testing only)"
	}
	dialog.ShowInformation("Verification Mode", modeText, c.window)
	logger.Infof("Verification mode changed to: %s", modeText)
}

// setupShortcuts configures keyboard shortcuts
func (c *ChatApp) setupShortcuts() {
	// Ctrl+W - Close window
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.cleanup()
		c.window.Close()
	})

	// Cmd+W for macOS
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierSuper,
	}, func(shortcut fyne.Shortcut) {
		c.cleanup()
		c.window.Close()
	})

	// Ctrl+N - New connection
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyN,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showConnectDialog()
	})

	// Ctrl+S - Start server
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyS,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showServerDialog()
	})

	// Ctrl+H - View history
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyH,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.historyViewer.ShowHistoryDialog()
	})

	// Ctrl+L - Toggle logs
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyL,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.toggleLogPanel()
	})

	// Escape - Close log panel if open
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyEscape,
	}, func(shortcut fyne.Shortcut) {
		if c.logPanelOpen {
			c.toggleLogPanel()
		}
	})
}

// cleanup performs cleanup when closing the application
func (c *ChatApp) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop log viewer
	if c.logViewer != nil {
		c.logViewer.Stop()
	}

	for _, session := range c.sessions {
		if session.Transport != nil {
			if err := session.Transport.Close(); err != nil {
				logger.Errorf("failed to close transport for session %s: %v", session.ID, err)
			}
		}
	}

	logger.Info("Application cleanup complete")
}

// disconnectActiveSession closes the current session
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

// showSessionInfo displays information about the current session
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

// buildSessionPanel creates the left sidebar with session list and controls
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

// buildChatPanel creates the main chat area
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

// buildSessionInfoBar creates the info bar shown above the chat
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

	// Update bar when session changes
	go func() {
		var lastSessionID string
		for {
			time.Sleep(200 * time.Millisecond)
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

// buildStatusBar creates the bottom status bar
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

// showServerDialog displays the server configuration dialog
func (c *ChatApp) showServerDialog() {
	if c.serverRunning {
		dialog.ShowInformation("Server Running", "A server is already running.\n\nStop the current server before starting a new one.", c.window)
		return
	}

	addrEntry := widget.NewEntry()
	addrEntry.SetText("127.0.0.1:9000")
	addrEntry.SetPlaceHolder("Address:Port")

	dbEntry := widget.NewEntry()
	dbEntry.SetText("./server.db")
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

// showConnectDialog displays the client connection dialog
func (c *ChatApp) showConnectDialog() {
	addrEntry := widget.NewEntry()
	addrEntry.SetText("127.0.0.1:9000")
	addrEntry.SetPlaceHolder("Address:Port")

	dbEntry := widget.NewEntry()
	dbEntry.SetText("./client.db")
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

// startServer initializes and starts the kamune server
func (c *ChatApp) startServer(addr, dbPath string) {
	c.isServer = true

	logger.Infof("Starting server on %s", addr)

	go func() {
		var opts []kamune.StorageOption
		opts = append(opts,
			kamune.StorageWithDBPath(dbPath),
			kamune.StorageWithNoPassphrase(),
		)

		// Get the appropriate verifier based on current mode
		remoteVerifier := c.verifier.GetVerifier(c.verificationMode)

		srv, err := kamune.NewServer(
			addr,
			c.serverHandler,
			kamune.ServeWithStorageOpts(opts...),
			kamune.ServeWithRemoteVerifier(remoteVerifier),
		)
		if err != nil {
			c.showError(fmt.Errorf("starting server: %w", err))
			logger.Errorf("Failed to start server: %v", err)
			return
		}

		// Update fingerprint & UI on main thread
		pubKey := srv.PublicKey().Marshal()
		fp := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hexFp := fingerprint.Hex(pubKey)
		c.emojiFingerprint = fp
		c.hexFingerprint = hexFp

		c.runOnMain(func() {
			c.fingerprintLbl.SetText(fp)
			c.serverRunning = true
			c.statusIndicator.SetStatus(StatusConnected, "Server running")
			c.updateStatusText(fmt.Sprintf("Server listening on %s", addr))
			if c.stopServerBtn != nil {
				c.stopServerBtn.Show()
			}
		})

		logger.Infof("Server started successfully on %s", addr)
		c.sendNotification("Server Started", fmt.Sprintf("Listening on %s", addr))

		if err := srv.ListenAndServe(); err != nil {
			// Ensure UI updates happen on main thread
			c.runOnMain(func() {
				c.serverRunning = false
				c.statusIndicator.SetStatus(StatusDisconnected, "Server stopped")
				c.updateStatusText("Server stopped")
				if c.stopServerBtn != nil {
					c.stopServerBtn.Hide()
				}
			})
			logger.Infof("Server stopped: %v", err)
		}
	}()
}

// stopServer stops the running server
func (c *ChatApp) stopServer() {
	if !c.serverRunning {
		dialog.ShowInformation("No Server", "No server is currently running.", c.window)
		return
	}

	dialog.ShowConfirm("Stop Server", "Stop the server?\n\nAll active sessions will be disconnected.", func(confirmed bool) {
		if !confirmed {
			return
		}

		logger.Info("Stopping server by user request")

		// Close all server sessions
		c.mu.Lock()
		for _, session := range c.sessions {
			if session.Transport != nil {
				if err := session.Transport.Close(); err != nil {
					logger.Errorf("failed to close session %s: %v", session.ID, err)
				}
			}
		}
		c.sessions = make([]*Session, 0)
		c.activeSession = nil
		c.serverRunning = false
		c.mu.Unlock()

		c.runOnMain(func() {
			c.sessionList.Refresh()
			c.refreshMessages()
			c.statusIndicator.SetStatus(StatusDisconnected, "Server stopped")
			c.updateStatusText("Server stopped")
			if c.stopServerBtn != nil {
				c.stopServerBtn.Hide()
			}
		})

		logger.Info("Server stopped successfully")
		c.sendNotification("Server Stopped", "All sessions disconnected")
	}, c.window)
}

// serverHandler handles incoming connections on the server.
// IMPORTANT: This function must block until the session is complete.
// If it returns early, the server's serve() defer will close the connection.
func (c *ChatApp) serverHandler(t *kamune.Transport) error {
	session := &Session{
		ID:           t.SessionID(),
		Transport:    t,
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now(),
	}

	c.mu.Lock()
	c.sessions = append(c.sessions, session)
	// Only set as active if no session is currently active
	if c.activeSession == nil {
		c.activeSession = session
	}
	c.mu.Unlock()

	// Update UI on main thread
	c.runOnMain(func() {
		c.sessionList.Refresh()
		c.refreshMessages()
		c.updateStatusText(fmt.Sprintf("New session: %s", truncateSessionID(session.ID)))
		// Send notification for new connection
		c.sendNotification("New Connection", fmt.Sprintf("Peer connected: %s", truncateSessionID(session.ID)))
	})

	logger.Infof("New session established: %s", session.ID)

	// CRITICAL FIX: Block here receiving messages instead of spawning goroutine.
	// The handler must stay alive to keep the connection open.
	c.receiveMessagesBlocking(session)

	// Clean up session from list when connection closes
	c.mu.Lock()
	for i, s := range c.sessions {
		if s == session {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			break
		}
	}
	if c.activeSession == session {
		c.activeSession = nil
	}
	c.mu.Unlock()

	c.runOnMain(func() {
		c.sessionList.Refresh()
		c.refreshMessages()
	})

	logger.Infof("Session closed: %s", session.ID)
	return nil
}

// sendNotification sends a desktop notification if enabled
func (c *ChatApp) sendNotification(title, content string) {
	if !c.notifications.enabled {
		return
	}
	c.app.SendNotification(fyne.NewNotification(title, content))
}

// truncateSessionID shortens a session ID for display
func truncateSessionID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// connectToServer connects to a kamune server as a client
func (c *ChatApp) connectToServer(addr, dbPath string) {
	c.isServer = false

	logger.Infof("Connecting to server at %s", addr)

	go func() {
		var dialOpts []kamune.StorageOption
		dialOpts = append(dialOpts,
			kamune.StorageWithDBPath(dbPath),
			kamune.StorageWithNoPassphrase(),
		)

		// Get the appropriate verifier based on current mode
		remoteVerifier := c.verifier.GetVerifier(c.verificationMode)

		dialer, err := kamune.NewDialer(
			addr,
			kamune.DialWithStorageOpts(dialOpts...),
			kamune.DialWithRemoteVerifier(remoteVerifier),
		)
		if err != nil {
			c.showError(fmt.Errorf("creating dialer: %w", err))
			logger.Errorf("Failed to create dialer: %v", err)
			return
		}

		// Update fingerprint display on main thread
		pubKey := dialer.PublicKey().Marshal()
		fp := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hexFp := fingerprint.Hex(pubKey)
		c.emojiFingerprint = fp
		c.hexFingerprint = hexFp

		c.runOnMain(func() {
			c.fingerprintLbl.SetText(fp)
			c.statusIndicator.SetStatus(StatusConnecting, "Connecting...")
			c.updateStatusText(fmt.Sprintf("Connecting to %s...", addr))
		})

		t, err := dialer.Dial()
		if err != nil {
			// UI updates on main thread
			c.runOnMain(func() {
				c.showError(fmt.Errorf("connecting: %w", err))
				c.statusIndicator.SetStatus(StatusError, "Connection failed")
			})
			logger.Errorf("Connection failed: %v", err)
			return
		}

		session := &Session{
			ID:           t.SessionID(),
			Transport:    t,
			Messages:     make([]ChatMessage, 0),
			LastActivity: time.Now(),
		}

		c.mu.Lock()
		c.sessions = append(c.sessions, session)
		c.activeSession = session
		c.mu.Unlock()

		// Update UI on main thread
		c.runOnMain(func() {
			c.sessionList.Refresh()
			c.refreshMessages()
			c.statusIndicator.SetStatus(StatusConnected, "Connected")
			c.updateStatusText(fmt.Sprintf("Connected - Session: %s", truncateSessionID(session.ID)))
		})

		logger.Infof("Connected successfully, session: %s", session.ID)
		c.sendNotification("Connected", fmt.Sprintf("Session: %s", truncateSessionID(session.ID)))

		// Start receiving messages in its own goroutine
		go c.receiveMessages(session)
	}()
}

// receiveMessagesBlocking receives messages in a blocking loop.
// This is used by the server handler to keep the connection alive.
func (c *ChatApp) receiveMessagesBlocking(session *Session) {
	for {
		b := kamune.Bytes(nil)
		metadata, err := session.Transport.Receive(b)
		if err != nil {
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
		c.refreshMessages()
	}
}

// receiveMessages starts a goroutine to receive messages for client connections.
// For server connections, use receiveMessagesBlocking instead.
func (c *ChatApp) receiveMessages(session *Session) {
	go c.receiveMessagesBlocking(session)
}

// sendMessage sends the current message to the active session
func (c *ChatApp) sendMessage() {
	text := strings.TrimSpace(c.messageEntry.Text)
	if text == "" {
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
	c.refreshMessages()
}

// refreshMessages updates the message list display
func (c *ChatApp) refreshMessages() {
	// Ensure Refresh runs on the main thread
	c.runOnMain(func() {
		if c.messageList != nil {
			c.messageList.Refresh()
		}
	})

	// Scroll to bottom with a slight delay to ensure list is updated
	c.mu.RLock()
	session := c.activeSession
	msgCount := 0
	if session != nil {
		msgCount = len(session.Messages)
	}
	c.mu.RUnlock()

	// Update welcome/empty overlays explicitly as sessions/messages change.
	c.runOnMain(func() {
		if c.welcomeOverlay == nil || c.emptyOverlay == nil {
			return
		}

		hasSession := session != nil

		if !hasSession {
			c.welcomeOverlay.Show()
			c.emptyOverlay.Hide()
			return
		}

		if msgCount == 0 {
			c.welcomeOverlay.Hide()
			c.emptyOverlay.Show()
			return
		}

		c.welcomeOverlay.Hide()
		c.emptyOverlay.Hide()
	})

	if msgCount > 0 {
		// Use goroutine with small delay then request scroll on main thread
		go func() {
			time.Sleep(50 * time.Millisecond)
			c.runOnMain(func() {
				if c.messageList != nil {
					c.messageList.ScrollToBottom()
				}
			})
		}()
	}
}

// updateStatus updates the status bar based on current state
func (c *ChatApp) updateStatus() {
	// Compute state under lock, but update widgets on the UI thread.
	c.mu.RLock()
	active := c.activeSession
	sessionCount := len(c.sessions)
	msgCount := 0
	activeID := ""
	if active != nil {
		activeID = active.ID
		msgCount = len(active.Messages)
	}
	c.mu.RUnlock()

	var text string
	if active != nil {
		text = fmt.Sprintf("Session: %s | Messages: %d", truncateSessionID(activeID), msgCount)
	} else if sessionCount > 0 {
		text = fmt.Sprintf("%d session(s) active", sessionCount)
	} else {
		text = "Not connected"
	}

	c.runOnMain(func() {
		if c.statusLabel != nil {
			c.statusLabel.SetText(text)
		}
	})
}

// updateStatusText sets a custom status message
func (c *ChatApp) updateStatusText(text string) {
	c.runOnMain(func() {
		if c.statusLabel != nil {
			c.statusLabel.SetText(text)
		}
	})
}

// runOnMain ensures the function runs on the Fyne UI thread
func (c *ChatApp) runOnMain(fn func()) {
	fyne.Do(fn)
}

func (c *ChatApp) showError(err error) {
	logger.Errorf("Error: %v", err)
	c.runOnMain(func() {
		dialog.ShowError(err, c.window)
	})
}
