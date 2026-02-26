package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/bus/logger"
)

// getDefaultDBDir returns the default database path, checking KAMUNE_DB_PATH env var first.
func getDefaultDBDir() string {
	if envPath := os.Getenv("KAMUNE_DB_PATH"); envPath != "" {
		return filepath.Join(envPath, "db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "db"
	}
	return filepath.Join(home, ".config", "kamune", "db")
}

// notificationConfig controls notification behavior.
type notificationConfig struct {
	enabled     bool
	soundOnRecv bool
}

const appVersion = "1.1.0"

// ChatMessage represents a single message in the conversation.
type ChatMessage struct {
	Text      string
	Timestamp time.Time
	IsLocal   bool
}

// Session represents an active chat session.
type Session struct {
	ID           string
	PeerName     string
	Transport    *kamune.Transport
	Messages     []ChatMessage
	LastActivity time.Time
}

// ChatApp is the main application state.
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
	server           *kamune.Server

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

// NewChatApp creates a new chat application instance.
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

// BuildUI constructs the main user interface.
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

// cleanup performs cleanup when closing the application.
func (c *ChatApp) cleanup() {
	// Signal background goroutines (e.g. session-info-bar poller) to stop.
	// Use a select to avoid panicking if stopChan was already closed.
	select {
	case <-c.stopChan:
		// already closed
	default:
		close(c.stopChan)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Stop log viewer
	if c.logViewer != nil {
		c.logViewer.Stop()
	}

	// Shut down the server listener so ListenAndServe returns.
	if c.server != nil {
		if err := c.server.Close(); err != nil {
			logger.Errorf("failed to close server: %v", err)
		}
		c.server = nil
	}

	for _, session := range c.sessions {
		if session.Transport != nil {
			c.saveSessionState(session)
			if err := session.Transport.Close(); err != nil {
				logger.Errorf("failed to close transport for session %s: %v", session.ID, err)
			}
		}
	}

	logger.Info("Application cleanup complete")
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// sendNotification sends a desktop notification if enabled.
func (c *ChatApp) sendNotification(title, content string) {
	if !c.notifications.enabled {
		return
	}
	c.app.SendNotification(fyne.NewNotification(title, content))
}

// truncateSessionID shortens a session ID for display.
func truncateSessionID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// runOnMain ensures the function runs on the Fyne UI thread.
func (c *ChatApp) runOnMain(fn func()) {
	fyne.Do(fn)
}

// showError logs and displays an error dialog.
func (c *ChatApp) showError(err error) {
	logger.Errorf("Error: %v", err)
	c.runOnMain(func() {
		dialog.ShowError(err, c.window)
	})
}

// updateStatus updates the status bar based on current state.
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

// updateStatusText sets a custom status message.
func (c *ChatApp) updateStatusText(text string) {
	c.runOnMain(func() {
		if c.statusLabel != nil {
			c.statusLabel.SetText(text)
		}
	})
}
