package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/bus/logger"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

const appVersion = "2.0.0"

// getDefaultDBDir returns the default database path, checking KAMUNE_DB_PATH
// env var first.
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

// HistorySession represents a past session loaded from the database.
type HistorySession struct {
	ID           string
	Name         string
	MessageCount int
	FirstMessage time.Time
	LastMessage  time.Time
	Messages     []ChatMessage
	Loaded       bool
}

// SidebarMode controls what is displayed in the sidebar.
type SidebarMode int

const (
	SidebarModeSessions SidebarMode = iota
	SidebarModeHistory
)

// ChatApp is the main application state.
type ChatApp struct {
	app    fyne.App
	window fyne.Window

	// UI components
	sessionList    *widget.List
	messageEntry   *widget.Entry
	sendButton     *widget.Button
	statusLabel    *widget.Label
	fingerprintLbl *widget.Label
	stopServerBtn  *widget.Button

	// Chat tabs
	tabManager     *ChatTabManager
	welcomeOverlay fyne.CanvasObject

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

	// Database path (single source of truth for all DB consumers)
	dbPath string

	// History sessions (past sessions from DB)
	historySessions   []*HistorySession
	activeHistSession *HistorySession
	historyLoaded     bool
	sidebarMode       SidebarMode
	historyList       *widget.List
	sidebarTabs       *container.AppTabs
	historyRefreshBtn *widget.Button

	// History viewer (standalone window)
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
		dbPath:           getDefaultDBDir(),
		sessions:         make([]*Session, 0),
		historySessions:  make([]*HistorySession, 0),
		stopChan:         make(chan struct{}),
		verificationMode: VerificationModeQuick,
		sidebarMode:      SidebarModeSessions,
	}
	c.historyViewer = NewHistoryViewer(app, window, c.DBPath)
	c.statusIndicator = NewStatusIndicator()
	c.notifications = notificationConfig{enabled: true, soundOnRecv: false}
	c.verifier = NewGUIVerifier(app, window)
	c.logViewer = NewLogViewer()
	c.tabManager = NewChatTabManager(c)
	return c
}

// BuildUI constructs the main user interface.
func (c *ChatApp) BuildUI() fyne.CanvasObject {
	c.setupMenus()
	c.setupShortcuts()

	// Left sidebar with tabs for sessions and history
	sessionPanel := c.buildSessionPanel()

	// Center chat panel
	chatPanel := c.buildChatPanel()

	// Bottom status bar
	statusBar := c.buildStatusBar()

	// Log panel (hidden by default)
	c.logPanel = c.buildLogPanel()
	c.logPanel.Hide()

	// Horizontal split: sidebar | chat
	split := container.NewHSplit(sessionPanel, chatPanel)
	split.SetOffset(0.26)

	// Vertical split for log panel
	c.mainSplit = container.NewVSplit(split, c.logPanel)
	c.mainSplit.SetOffset(1.0)

	mainContent := container.NewBorder(nil, statusBar, nil, nil, c.mainSplit)

	// Start log viewer
	c.logViewer.Start()

	// Load fingerprint and history from existing storage in a single DB open.
	go c.initFromStorage()

	return mainContent
}

// initFromStorage opens the database once on startup to load both the
// identity fingerprint and history sessions, avoiding redundant DB opens.
func (c *ChatApp) initFromStorage() {
	dbPath := c.DBPath()

	if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
		return
	}

	store, err := storage.OpenStorage(
		storage.StorageWithDBPath(dbPath),
		storage.StorageWithNoPassphrase(),
	)
	if err != nil {
		logger.Debugf("No existing storage to load from: %v", err)
		return
	}
	defer func() { _ = store.Close() }()

	// ── Fingerprint ──
	pubKey, err := store.PublicKey()
	if err != nil {
		logger.Debugf("No identity key found in storage: %v", err)
	} else {
		fp := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hexFp := fingerprint.Hex(pubKey)

		c.mu.Lock()
		c.emojiFingerprint = fp
		c.hexFingerprint = hexFp
		c.mu.Unlock()

		c.runOnMain(func() {
			if c.fingerprintLbl != nil {
				c.fingerprintLbl.SetText(fp)
			}
		})

		logger.Infof("Loaded fingerprint from existing identity")
	}

	// ── History sessions ──
	c.loadHistoryFromStorage(store)
}

// DBPath returns the current database path.
func (c *ChatApp) DBPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dbPath
}

// SetDBPath updates the database path and refreshes history.
func (c *ChatApp) SetDBPath(path string) {
	c.mu.Lock()
	c.dbPath = path
	c.mu.Unlock()

	logger.Infof("Database path changed to: %s", path)
	c.refreshHistorySessions()
}

// loadHistorySessions opens the database and loads history sessions.
// Use loadHistoryFromStorage when you already have an open *Storage.
func (c *ChatApp) loadHistorySessions(dbPath string) {
	store, err := storage.OpenStorage(
		storage.StorageWithDBPath(dbPath),
		storage.StorageWithNoPassphrase(),
	)
	if err != nil {
		logger.Errorf("failed to open history database: %v", err)
		return
	}
	defer func() { _ = store.Close() }()

	c.loadHistoryFromStorage(store)
}

// loadHistoryFromStorage loads past sessions from an already-open storage
// into the sidebar. It uses ListSessionsByRecent which obtains timestamps via
// cursor seeks and key counts from BoltDB stats — no chat payloads are
// decrypted.
func (c *ChatApp) loadHistoryFromStorage(storage *storage.Storage) {
	summaries, err := storage.ListSessionsByRecent()
	if err != nil {
		logger.Errorf("failed to list history sessions: %v", err)
		return
	}

	if len(summaries) == 0 {
		c.mu.Lock()
		c.historyLoaded = true
		c.mu.Unlock()
		return
	}

	sessions := make([]*HistorySession, 0, len(summaries))
	for _, s := range summaries {
		sessions = append(sessions, &HistorySession{
			ID:           s.ID,
			MessageCount: s.MessageCount,
			FirstMessage: s.FirstMessage,
			LastMessage:  s.LastMessage,
			Name:         s.Name,
		})
	}

	c.mu.Lock()
	c.historySessions = sessions
	c.historyLoaded = true
	c.mu.Unlock()

	c.runOnMain(func() {
		if c.historyList != nil {
			c.historyList.Refresh()
		}
	})

	logger.Infof("Loaded %d history sessions", len(sessions))
}

// loadHistoryMessages loads the full chat messages for a history session.
func (c *ChatApp) loadHistoryMessages(hs *HistorySession) error {
	if hs.Loaded {
		return nil
	}

	dbPath := c.DBPath()

	store, err := storage.OpenStorage(
		storage.StorageWithDBPath(dbPath),
		storage.StorageWithNoPassphrase(),
	)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = store.Close() }()

	entries, err := store.GetChatHistory(hs.ID)
	if err != nil {
		return fmt.Errorf("loading history: %w", err)
	}

	msgs := make([]ChatMessage, 0, len(entries))
	for _, entry := range entries {
		msgs = append(msgs, ChatMessage{
			Text:      string(entry.Data),
			Timestamp: entry.Timestamp,
			IsLocal:   entry.Sender == storage.SenderLocal,
		})
	}

	c.mu.Lock()
	hs.Messages = msgs
	hs.Loaded = true
	hs.MessageCount = len(msgs)
	if len(msgs) > 0 {
		hs.FirstMessage = msgs[0].Timestamp
		hs.LastMessage = msgs[len(msgs)-1].Timestamp
	}
	c.mu.Unlock()

	return nil
}

// refreshHistorySessions reloads the history session list.
func (c *ChatApp) refreshHistorySessions() {
	dbPath := c.DBPath()

	// Reset
	c.mu.Lock()
	c.historySessions = make([]*HistorySession, 0)
	c.activeHistSession = nil
	c.historyLoaded = false
	c.mu.Unlock()

	c.runOnMain(func() {
		if c.historyList != nil {
			c.historyList.Refresh()
		}
	})

	go c.loadHistorySessions(dbPath)
}

// isViewingHistory returns true if the user is viewing a history session.
func (c *ChatApp) isViewingHistory() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.activeHistSession != nil && c.activeSession == nil
}

// dbPathDisplay returns a shortened version of the DB path for UI display.
func (c *ChatApp) dbPathDisplay() string {
	p := c.DBPath()
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(p, home) {
		p = "~" + p[len(home):]
	}
	return p
}

// getDisplayMessages returns messages to show in the message list.
// Delegates to the selected tab in the tab manager, falling back to
// direct active session pointers when no tab manager is available.
func (c *ChatApp) getDisplayMessages() []ChatMessage {
	if c.tabManager != nil {
		ct := c.tabManager.SelectedTab()
		if ct != nil {
			return c.tabManager.tabMessages(ct)
		}
	}

	// Fallback for tests or cases without a tab manager.
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.activeSession != nil {
		return c.activeSession.Messages
	}
	if c.activeHistSession != nil && c.activeHistSession.Loaded {
		return c.activeHistSession.Messages
	}
	return nil
}

// getDisplaySessionID returns the session ID for the current view.
// Delegates to the selected tab in the tab manager, falling back to
// direct active session pointers when no tab manager is available.
func (c *ChatApp) getDisplaySessionID() string {
	if c.tabManager != nil {
		ct := c.tabManager.SelectedTab()
		if ct != nil {
			return ct.ID
		}
	}

	// Fallback for tests or cases without a tab manager.
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.activeSession != nil {
		return c.activeSession.ID
	}
	if c.activeHistSession != nil {
		return c.activeHistSession.ID
	}
	return ""
}

// cleanup performs cleanup when closing the application.
func (c *ChatApp) cleanup() {
	select {
	case <-c.stopChan:
	default:
		close(c.stopChan)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.logViewer != nil {
		c.logViewer.Stop()
	}

	if c.server != nil {
		if err := c.server.Close(); err != nil {
			logger.Errorf("failed to close server: %v", err)
		}
		c.server = nil
	}

	logger.Info("Application cleanup complete")
}

// deleteHistorySession removes a session's stored chat history from the database.
func (c *ChatApp) deleteHistorySession(hs *HistorySession) {
	if hs == nil {
		return
	}

	dialog.ShowConfirm(
		"Delete Session History",
		fmt.Sprintf(
			"Permanently delete history for session %s?\n\nThis cannot be undone.",
			truncateSessionID(hs.ID),
		),
		func(confirmed bool) {
			if !confirmed {
				return
			}

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

				if err := store.DeleteSession(hs.ID); err != nil {
					c.showError(fmt.Errorf("deleting session: %w", err))
					return
				}

				logger.Infof("Deleted history session: %s", hs.ID)

				// Close the tab if it's open for this session
				c.tabManager.CloseTab(hs.ID)

				// If we're viewing the deleted session, deselect it
				c.mu.Lock()
				if c.activeHistSession == hs {
					c.activeHistSession = nil
				}
				c.mu.Unlock()

				c.refreshHistorySessions()
			}()
		}, c.window)
}

// ---------------------------------------------------------------------------
// Helpers
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
	c.mu.RLock()
	active := c.activeSession
	histActive := c.activeHistSession
	sessionCount := len(c.sessions)
	msgCount := 0
	activeID := ""
	if active != nil {
		activeID = active.ID
		msgCount = len(active.Messages)
	} else if histActive != nil {
		activeID = histActive.ID
		msgCount = histActive.MessageCount
	}
	c.mu.RUnlock()

	var text string
	if active != nil {
		text = fmt.Sprintf("Session: %s  •  %d messages", truncateSessionID(activeID), msgCount)
	} else if histActive != nil {
		text = fmt.Sprintf("History: %s  •  %d messages", truncateSessionID(activeID), msgCount)
	} else if sessionCount > 0 {
		text = fmt.Sprintf("%d active session(s)", sessionCount)
	} else {
		text = "Ready"
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
