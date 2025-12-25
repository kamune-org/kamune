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
)

// notificationConfig controls notification behavior
type notificationConfig struct {
	enabled     bool
	soundOnRecv bool
}

const (
	appVersion = "1.0.0"
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

	// Chat overlays (stored so we can reliably toggle them on session/message changes)
	welcomeOverlay fyne.CanvasObject
	emptyOverlay   fyne.CanvasObject

	// State
	sessions         []*Session
	activeSession    *Session
	mu               sync.RWMutex
	stopChan         chan struct{}
	isServer         bool
	serverRunning    bool
	emojiFingerprint string

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

	// Main layout with split view
	split := container.NewHSplit(sessionPanel, chatPanel)
	split.SetOffset(0.25)

	// Combine with status bar
	mainContent := container.NewBorder(nil, statusBar, nil, nil, split)

	return mainContent
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
	)

	// Session menu
	sessionMenu := fyne.NewMenu("Session",
		fyne.NewMenuItem("Disconnect", func() {
			c.disconnectActiveSession()
		}),
		fyne.NewMenuItem("Session Info", func() {
			c.showSessionInfo()
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
		fyne.NewMenuItem("About Kamune Chat", func() {
			dialog.ShowInformation("About Kamune Chat",
				"Kamune Chat GUI\n\nA secure messaging application built with Fyne.\n\nPowered by the Kamune protocol for end-to-end encrypted communication.",
				c.window)
		}),
	)

	mainMenu := fyne.NewMainMenu(fileMenu, editMenu, sessionMenu, settingsMenu, helpMenu)
	c.window.SetMainMenu(mainMenu)
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
}

// setupShortcuts configures keyboard shortcuts
func (c *ChatApp) setupShortcuts() {
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
}

// cleanup performs cleanup when closing the application
func (c *ChatApp) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, session := range c.sessions {
		if session.Transport != nil {
			if err := session.Transport.Close(); err != nil {
				// Best-effort cleanup: we can't surface UI here reliably, so just log.
				fmt.Printf("warning: failed to close transport for session %s: %v\n", session.ID, err)
			}
		}
	}
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

	dialog.ShowConfirm("Disconnect", "Are you sure you want to disconnect this session?", func(confirmed bool) {
		if confirmed {
			if session.Transport != nil {
				if err := session.Transport.Close(); err != nil {
					fmt.Printf("warning: failed to close transport for session %s: %v\n", session.ID, err)
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
			c.statusIndicator.SetStatus(StatusDisconnected, "Disconnected")
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

	info := fmt.Sprintf("Session ID: %s\n\nMessages: %d\n\nLast Activity: %s",
		session.ID,
		len(session.Messages),
		session.LastActivity.Format("2006-01-02 15:04:05"),
	)

	dialog.ShowInformation("Session Info", info, c.window)
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
		c.mu.RLock()
		if id < len(c.sessions) {
			c.activeSession = c.sessions[id]
		}
		c.mu.RUnlock()
		c.sessionList.Refresh() // ensures active highlight updates across items
		c.refreshMessages()     // also updates welcome/empty overlays via refreshMessages
		c.updateStatus()
	}

	// Connection buttons
	serverBtn := widget.NewButtonWithIcon("Start Server", theme.ComputerIcon(), c.showServerDialog)
	clientBtn := widget.NewButtonWithIcon("Connect", theme.LoginIcon(), c.showConnectDialog)

	buttonBox := container.NewVBox(
		serverBtn,
		clientBtn,
	)

	// Fingerprint display
	c.fingerprintLbl = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	c.fingerprintLbl.Wrapping = fyne.TextWrapWord

	fingerprintCard := widget.NewCard("Your Fingerprint", "", c.fingerprintLbl)

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
			"Use Ctrl+S to start a server\nUse Ctrl+N to connect to a server",
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

	// Enter-to-send (platform dependent for MultiLineEntry, but supported broadly via OnSubmitted)
	c.messageEntry.OnSubmitted = func(s string) {
		c.sendMessage()
	}

	c.sendButton = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), c.sendMessage)
	c.sendButton.Importance = widget.HighImportance

	inputRow := container.NewBorder(nil, nil, nil, c.sendButton, c.messageEntry)
	inputArea := container.NewPadded(inputRow)

	// Show/hide welcome/empty overlays based on active session + message count.
	// Use a stack but explicitly toggle visibility to avoid overlays rendering through.
	updateOverlays := func() {
		c.mu.RLock()
		hasSession := c.activeSession != nil
		msgCount := 0
		if c.activeSession != nil {
			msgCount = len(c.activeSession.Messages)
		}
		c.mu.RUnlock()

		if !hasSession {
			if c.welcomeOverlay != nil {
				c.welcomeOverlay.Show()
			}
			if c.emptyOverlay != nil {
				c.emptyOverlay.Hide()
			}
			return
		}

		if msgCount == 0 {
			if c.welcomeOverlay != nil {
				c.welcomeOverlay.Hide()
			}
			if c.emptyOverlay != nil {
				c.emptyOverlay.Show()
			}
			return
		}

		if c.welcomeOverlay != nil {
			c.welcomeOverlay.Hide()
		}
		if c.emptyOverlay != nil {
			c.emptyOverlay.Hide()
		}
	}

	// Initial state (no session selected)
	updateOverlays()

	messageArea := container.NewStack(c.welcomeOverlay, c.emptyOverlay, c.messageList)

	chatContent := container.NewBorder(nil, inputArea, nil, nil, messageArea)

	// Overlay state is updated via refreshMessages() and initial updateOverlays() above.

	return chatContent
}

// buildStatusBar creates the bottom status bar
func (c *ChatApp) buildStatusBar() fyne.CanvasObject {
	c.statusLabel = widget.NewLabel("Not connected")

	// Version label
	versionLabel := widget.NewLabelWithStyle("v"+appVersion, fyne.TextAlignTrailing, fyne.TextStyle{})
	versionLabel.Importance = widget.LowImportance

	statusBox := container.NewHBox(c.statusIndicator, widget.NewSeparator(), c.statusLabel, layout.NewSpacer(), versionLabel)

	separator := widget.NewSeparator()

	return container.NewVBox(separator, container.NewPadded(statusBox))
}

// showServerDialog displays the server configuration dialog
func (c *ChatApp) showServerDialog() {
	if c.serverRunning {
		dialog.ShowInformation("Server Running", "A server is already running.", c.window)
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
			return
		}

		// Update fingerprint & UI on main thread
		fp := strings.Join(fingerprint.Emoji(srv.PublicKey().Marshal()), " • ")
		c.emojiFingerprint = fp
		c.runOnMain(func() {
			c.fingerprintLbl.SetText(fp)
			c.serverRunning = true
			c.statusIndicator.SetStatus(StatusConnected, "Server running")
			c.updateStatusText(fmt.Sprintf("Server listening on %s", addr))
		})

		if err := srv.ListenAndServe(); err != nil {
			// Ensure UI updates happen on main thread
			c.runOnMain(func() {
				c.showError(fmt.Errorf("server error: %w", err))
				c.serverRunning = false
				c.statusIndicator.SetStatus(StatusError, "Server stopped")
			})
		}
	}()
}

// serverHandler handles incoming connections on the server
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
		c.updateStatusText(fmt.Sprintf("New session: %s", session.ID))
		// Send notification for new connection (ensure UI/main thread for Fyne)
		c.sendNotification("New Connection", fmt.Sprintf("Peer connected: %s", truncateSessionID(session.ID)))
	})

	// Start receiving messages in its own goroutine
	go c.receiveMessages(session)

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
		return id[:12] + "..."
	}
	return id
}

// connectToServer connects to a kamune server as a client
func (c *ChatApp) connectToServer(addr, dbPath string) {
	c.isServer = false

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
			return
		}

		// Update fingerprint display on main thread
		fp := strings.Join(fingerprint.Emoji(dialer.PublicKey().Marshal()), " • ")
		c.emojiFingerprint = fp
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
			c.updateStatusText(fmt.Sprintf("Connected - Session: %s", session.ID))
		})

		// Start receiving messages in its own goroutine
		go c.receiveMessages(session)
	}()
}

// receiveMessages handles incoming messages for a session
func (c *ChatApp) receiveMessages(session *Session) {
	for {
		b := kamune.Bytes(nil)
		metadata, err := session.Transport.Receive(b)
		if err != nil {
			if errors.Is(err, kamune.ErrConnClosed) {
				c.statusIndicator.SetStatus(StatusDisconnected, "Disconnected")
				c.updateStatusText("Connection closed")
				return
			}
			c.showError(fmt.Errorf("receiving message: %w", err))
			c.statusIndicator.SetStatus(StatusError, "Receive error")
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
		go func() {
			if err := session.Transport.Store().AddChatEntry(
				session.ID,
				b.GetValue(),
				metadata.Timestamp(),
				kamune.SenderPeer,
			); err != nil {
				fmt.Printf("warning: failed to persist peer chat entry for session %s: %v\n", session.ID, err)
			}
		}()

		// Send notification if different session is active
		if !isActiveSession {
			previewText := msgText
			if len(previewText) > 50 {
				previewText = previewText[:50] + "..."
			}
			c.sendNotification("New Message", previewText)
		}

		c.refreshMessages()
	}
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
			fmt.Printf("warning: failed to persist local chat entry for session %s: %v\n", session.ID, err)
		}
	}()

	c.runOnMain(func() {
		if c.messageEntry != nil {
			c.messageEntry.SetText("")
		}
	})
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
		text = fmt.Sprintf("Session: %s | Messages: %d", activeID, msgCount)
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

// showError displays an error dialog
func (c *ChatApp) runOnMain(fn func()) {
	// Always marshal UI work onto the Fyne UI thread.
	// This avoids runtime warnings like:
	// "*** Error in Fyne call thread, this should have been called in fyne.Do[AndWait] ***"
	//
	// Note: older Fyne versions do not expose Driver.RunOnMain(), so using fyne.Do()
	// is the most compatible approach here.
	fyne.Do(fn)
}

func (c *ChatApp) showError(err error) {
	c.runOnMain(func() {
		dialog.ShowError(err, c.window)
	})
}
