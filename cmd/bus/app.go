package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zalando/go-keyring"
)

const keychainService = "kamune"

func keychainAccount(dbPath string) string {
	return "db-passphrase:" + dbPath
}

type ConnectionStatus string

const (
	StatusDisconnected ConnectionStatus = "disconnected"
	StatusConnecting   ConnectionStatus = "connecting"
	StatusConnected    ConnectionStatus = "connected"
	StatusError        ConnectionStatus = "error"
)

const appVersion = "2.0.0"

type VerificationMode int

const (
	VerificationModeStrict     VerificationMode = 0
	VerificationModeQuick      VerificationMode = 1
	VerificationModeAutoAccept VerificationMode = 2
)

type SessionInfo struct {
	ID           string    `json:"id"`
	PeerName     string    `json:"peerName"`
	IsServer     bool      `json:"isServer"`
	MsgCount     int       `json:"msgCount"`
	LastActivity time.Time `json:"lastActivity"`
}

type HistorySessionInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	MessageCount int       `json:"messageCount"`
	FirstMessage time.Time `json:"firstMessage"`
	LastMessage  time.Time `json:"lastMessage"`
	Loaded       bool      `json:"loaded"`
}

type MessageInfo struct {
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	IsLocal   bool      `json:"isLocal"`
}

type StatusInfo struct {
	Status  ConnectionStatus `json:"status"`
	Message string           `json:"message"`
}

type LogEntryInfo struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type liveSession struct {
	ID           string
	PeerName     string
	Transport    *kamune.Transport
	Messages     []MessageInfo
	LastActivity time.Time
	ReceiveDone  chan struct{}
	IsServer     bool
}

type historySession struct {
	ID           string
	Name         string
	Loaded       bool
	MessageCount int
	FirstMessage time.Time
	LastMessage  time.Time
}

type pendingVerification struct {
	result chan error
	peerID string
	hex    string
}

type App struct {
	ctx     context.Context
	mu      sync.RWMutex

	sessions     []*liveSession
	histSessions []*historySession
	server       *kamune.Server
	serverDone   chan struct{}

	dbPath      string
	db          *storage.Storage
	storeMu     sync.Mutex
	passphrase  []byte
	storageReady bool
	emojiFP     string
	hexFP       string
	verifMode   VerificationMode
	appVersion  string

	status          ConnectionStatus
	statusMsg       string
	activeSessionID string

	logEntries    []LogEntryInfo
	logMu         sync.RWMutex
	logBufferSize int

	verifMu       sync.Mutex
	verifRequests map[int64]*pendingVerification
	verifIDCounter atomic.Int64
}

func NewApp() *App {
	return &App{
		sessions:      make([]*liveSession, 0),
		histSessions:  make([]*historySession, 0),
		status:        StatusDisconnected,
		statusMsg:     "Not connected",
		verifMode:     VerificationModeQuick,
		appVersion:    appVersion,
		logBufferSize: 200,
		logEntries:    make([]LogEntryInfo, 0, 200),
		verifRequests: make(map[int64]*pendingVerification),
	}
}

func (a *App) store() *storage.Storage {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()
	if a.db != nil {
		return a.db
	}
	store, err := storage.OpenStorage(
		storage.WithDBPath(a.dbPath),
		storage.WithPassphraseHandler(a.passphraseHandler()),
	)
	if err != nil {
		return nil
	}
	a.db = store
	return a.db
}

func (a *App) passphraseHandler() storage.PassphraseHandler {
	return func() ([]byte, error) {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if a.passphrase == nil {
			return []byte(""), nil
		}
		return a.passphrase, nil
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	homeDir, err := os.UserHomeDir()
	if err != nil {
		a.addLogEntry("ERROR", "Failed to get home dir: "+err.Error())
		return
	}
	a.dbPath = filepath.Join(homeDir, ".config", "kamune", "db")

	passphrase, err := keyring.Get(keychainService, keychainAccount(a.dbPath))
	switch {
	case err == nil && passphrase == "":
		// Orphaned empty keychain entry — clean it up.
		_ = keyring.Delete(keychainService, keychainAccount(a.dbPath))
		a.addLogEntry("WARN", "Removed orphaned empty passphrase from keychain")

	case err == nil && passphrase != "":
		a.mu.Lock()
		a.passphrase = []byte(passphrase)
		a.mu.Unlock()

		store, storeErr := storage.OpenStorage(
			storage.WithDBPath(a.dbPath),
			storage.WithPassphraseHandler(a.passphraseHandler()),
		)
		if storeErr == nil {
			a.storeMu.Lock()
			a.db = store
			a.storeMu.Unlock()
			a.addLogEntry("INFO", "Loaded passphrase from keychain")
			a.initFromStorage()
			return
		}

		a.mu.Lock()
		a.passphrase = nil
		a.mu.Unlock()
		keyring.Delete(keychainService, keychainAccount(a.dbPath))
		a.addLogEntry("WARN", "Keychain passphrase is invalid, clearing and prompting")
	}

	a.addLogEntry("INFO", "Application started — awaiting passphrase")
}

func (a *App) shutdown(ctx context.Context) {
	a.addLogEntry("INFO", "Application shutting down")

	var serverDone chan struct{}
	a.mu.Lock()
	for _, s := range a.sessions {
		s.Transport.Close()
	}
	for _, s := range a.sessions {
		<-s.ReceiveDone
	}
	a.sessions = nil
	if a.server != nil {
		a.server.Close()
		a.server = nil
	}
	serverDone = a.serverDone
	a.serverDone = nil
	a.mu.Unlock()

	// Wait for the ListenAndServe goroutine to finish.
	if serverDone != nil {
		<-serverDone
	}

	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	a.storeMu.Unlock()

	a.addLogEntry("INFO", "Shutdown complete")
}

func (a *App) addLogEntry(level, msg string) {
	entry := LogEntryInfo{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
	}

	a.logMu.Lock()
	a.logEntries = append(a.logEntries, entry)
	if len(a.logEntries) > a.logBufferSize {
		a.logEntries = a.logEntries[len(a.logEntries)-a.logBufferSize:]
	}
	a.logMu.Unlock()

	runtime.EventsEmit(a.ctx, "log-entry", entry)

	lvl := slog.LevelInfo
	switch level {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	}
	slog.Log(a.ctx, lvl, msg)
}

func (a *App) setStatus(status ConnectionStatus, msg string) {
	a.mu.Lock()
	a.status = status
	a.statusMsg = msg
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "status-changed", StatusInfo{Status: status, Message: msg})
}

func (a *App) initFromStorage() {
	if _, err := os.Stat(a.dbPath); os.IsNotExist(err) {
		a.addLogEntry("DEBUG", "No existing storage to load from")
		a.mu.Lock()
		a.emojiFP = ""
		a.hexFP = ""
		a.storageReady = true
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "")
		return
	}

	store := a.store()
	if store == nil {
		a.addLogEntry("ERROR", "Storage is not available")
		return
	}

	pubKey, err := store.PublicKey()
	if err == nil {
		emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hex := fingerprint.Hex(pubKey)

		a.mu.Lock()
		a.emojiFP = emoji
		a.hexFP = hex
		a.storageReady = true
		a.mu.Unlock()

		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", emoji, hex)
		a.addLogEntry("INFO", "Loaded fingerprint from existing identity")
	} else {
		a.mu.Lock()
		a.emojiFP = ""
		a.hexFP = ""
		a.storageReady = true
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "")
		a.addLogEntry("DEBUG", "No identity key found: "+err.Error())
	}

	a.loadHistorySessions(a.db)
}

func (a *App) loadHistorySessions(store *storage.Storage) {
	summaries, err := store.ListSessionsByRecent()
	if err != nil {
		a.addLogEntry("WARN", "Could not list history sessions: "+err.Error())
		return
	}

	a.mu.Lock()
	a.histSessions = make([]*historySession, 0, len(summaries))
	for _, s := range summaries {
		a.histSessions = append(a.histSessions, &historySession{
			ID:           s.ID,
			Name:         s.Name,
			MessageCount: s.MessageCount,
			FirstMessage: s.FirstMessage,
			LastMessage:  s.LastMessage,
		})
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "history-updated")
}

// ---- Exported bindings ----

func (a *App) GetVersion() string {
	return a.appVersion
}

func (a *App) GetStatus() StatusInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return StatusInfo{Status: a.status, Message: a.statusMsg}
}

func (a *App) GetFingerprint() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]string{"emoji": a.emojiFP, "hex": a.hexFP}
}

func (a *App) GetDBPath() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.dbPath
}

func (a *App) SetDBPath(path string) {
	a.mu.Lock()
	a.dbPath = path
	a.passphrase = nil
	a.emojiFP = ""
	a.hexFP = ""
	a.storageReady = false
	a.mu.Unlock()

	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	a.storeMu.Unlock()

	runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "")
	runtime.EventsEmit(a.ctx, "request-passphrase")
	a.addLogEntry("INFO", "DB path changed to: "+path)
}

func (a *App) GetVerificationMode() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return int(a.verifMode)
}

func (a *App) SetVerificationMode(mode int) {
	a.mu.Lock()
	a.verifMode = VerificationMode(mode)
	a.mu.Unlock()
	a.addLogEntry("INFO", "Verification mode set to: "+verifModeName(VerificationMode(mode)))
	runtime.EventsEmit(a.ctx, "verification-mode-changed", mode)
}

func (a *App) SubmitPassphrase(passphrase string, saveToKeychain bool) error {
	a.mu.Lock()
	a.passphrase = []byte(passphrase)
	a.mu.Unlock()

	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	a.storeMu.Unlock()

	store := a.store()
	if store == nil {
		a.mu.Lock()
		a.passphrase = nil
		a.mu.Unlock()
		return fmt.Errorf("wrong passphrase or corrupted database")
	}

	if saveToKeychain && passphrase != "" {
		if err := keyring.Set(keychainService, keychainAccount(a.dbPath), passphrase); err != nil {
			a.addLogEntry("WARN", "Failed to save passphrase to keychain: "+err.Error())
		} else {
			a.addLogEntry("INFO", "Passphrase saved to keychain")
		}
	}

	a.initFromStorage()
	return nil
}

func (a *App) GetStorageReady() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.storageReady
}

func (a *App) HasKeychainPassphrase() bool {
	a.mu.RLock()
	path := a.dbPath
	a.mu.RUnlock()
	_, err := keyring.Get(keychainService, keychainAccount(path))
	return err == nil
}

func (a *App) ClearKeychainPassphrase() error {
	a.mu.RLock()
	path := a.dbPath
	a.mu.RUnlock()
	if err := keyring.Delete(keychainService, keychainAccount(path)); err != nil {
		return fmt.Errorf("failed to clear keychain: %w", err)
	}
	a.addLogEntry("INFO", "Passphrase cleared from keychain")
	return nil
}

func verifModeName(m VerificationMode) string {
	switch m {
	case VerificationModeStrict:
		return "Strict"
	case VerificationModeQuick:
		return "Quick"
	case VerificationModeAutoAccept:
		return "Auto-Accept"
	default:
		return "Unknown"
	}
}

func (a *App) GetSessions() []SessionInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]SessionInfo, 0, len(a.sessions))
	for _, s := range a.sessions {
		result = append(result, SessionInfo{
			ID:           s.ID,
			PeerName:     s.PeerName,
			IsServer:     s.IsServer,
			MsgCount:     len(s.Messages),
			LastActivity: s.LastActivity,
		})
	}
	return result
}

func (a *App) GetHistorySessions() []HistorySessionInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]HistorySessionInfo, 0, len(a.histSessions))
	for _, hs := range a.histSessions {
		info := HistorySessionInfo{
			ID:           hs.ID,
			Name:         hs.Name,
			Loaded:       hs.Loaded,
			MessageCount: hs.MessageCount,
			FirstMessage: hs.FirstMessage,
			LastMessage:  hs.LastMessage,
		}
		result = append(result, info)
	}
	return result
}

func (a *App) GetSessionMessages(sessionID string) []MessageInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, s := range a.sessions {
		if s.ID == sessionID {
			msgs := make([]MessageInfo, len(s.Messages))
			copy(msgs, s.Messages)
			return msgs
		}
	}
	return nil
}

func (a *App) GetHistoryMessages(sessionID string) []MessageInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, hs := range a.histSessions {
		if hs.ID == sessionID && hs.Loaded {
			store := a.store()
			if store == nil {
				return nil
			}

			entries, err := store.GetChatHistory(sessionID)
			if err != nil {
				a.addLogEntry("ERROR", "Failed to get chat history: "+err.Error())
				return nil
			}

			msgs := make([]MessageInfo, len(entries))
			for i, e := range entries {
				msgs[i] = MessageInfo{
					Text:      string(e.Data),
					Timestamp: e.Timestamp,
					IsLocal:   e.Sender == storage.SenderLocal,
				}
			}
			return msgs
		}
	}
	return nil
}

func (a *App) GetLogEntries() []LogEntryInfo {
	a.logMu.RLock()
	defer a.logMu.RUnlock()
	result := make([]LogEntryInfo, len(a.logEntries))
	copy(result, a.logEntries)
	return result
}

func (a *App) ClearLogs() {
	a.logMu.Lock()
	a.logEntries = a.logEntries[:0]
	a.logMu.Unlock()
	runtime.EventsEmit(a.ctx, "logs-cleared")
}

func (a *App) CopyToClipboard(text string) error {
	return runtime.ClipboardSetText(a.ctx, text)
}

func (a *App) SendNotification(title, message string) {
	runtime.EventsEmit(a.ctx, "notification", title, message)
}

func (a *App) ToggleFullscreen() {
	if runtime.WindowIsFullscreen(a.ctx) {
		runtime.WindowUnfullscreen(a.ctx)
	} else {
		runtime.WindowFullscreen(a.ctx)
	}
	runtime.EventsEmit(a.ctx, "fullscreen-changed", runtime.WindowIsFullscreen(a.ctx))
}

func (a *App) SetActiveSession(sessionID string) {
	a.mu.Lock()
	a.activeSessionID = sessionID
	a.mu.Unlock()
}

func (a *App) RenameSession(sessionID string, name string) {
	a.mu.Lock()
	for _, s := range a.sessions {
		if s.ID == sessionID {
			s.PeerName = name
			break
		}
	}
	a.mu.Unlock()
	runtime.EventsEmit(a.ctx, "session-updated")
}

func (a *App) RenameHistorySession(sessionID string, name string) {
	store := a.store()
	if store == nil {
		return
	}

	err := store.SetSessionName(sessionID, name)
	if err != nil {
		a.addLogEntry("ERROR", "Failed to rename history session: "+err.Error())
		return
	}

	a.mu.Lock()
	for _, hs := range a.histSessions {
		if hs.ID == sessionID {
			hs.Name = name
			break
		}
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "history-updated")
	a.addLogEntry("INFO", "Renamed history session: "+sessionID)
}

func (a *App) DeleteHistorySession(sessionID string) {
	store := a.store()
	if store == nil {
		return
	}

	err := store.DeleteSession(sessionID)
	if err != nil {
		a.addLogEntry("ERROR", "Failed to delete history session: "+err.Error())
		return
	}

	a.mu.Lock()
	for i, hs := range a.histSessions {
		if hs.ID == sessionID {
			a.histSessions = append(a.histSessions[:i], a.histSessions[i+1:]...)
			break
		}
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "history-updated")
	a.addLogEntry("INFO", "Deleted history session: "+sessionID)
}

func (a *App) RefreshHistory() {
	store := a.store()
	if store == nil {
		return
	}

	a.loadHistorySessions(store)
	a.addLogEntry("INFO", "History refreshed")
}

func (a *App) LoadHistoryMessages(sessionID string) {
	a.mu.Lock()
	for _, hs := range a.histSessions {
		if hs.ID == sessionID {
			hs.Loaded = true
			break
		}
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "history-loaded", sessionID)
}

func (a *App) GetSessionInfo(sessionID string) map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, s := range a.sessions {
		if s.ID == sessionID {
			return map[string]interface{}{
				"type":          "live",
				"peerName":      s.PeerName,
				"sessionID":     s.ID,
				"messageCount":  len(s.Messages),
				"lastActivity":  s.LastActivity.Format(time.RFC3339),
				"isServer":      s.IsServer,
			}
		}
	}

	for _, hs := range a.histSessions {
		if hs.ID == sessionID {
			info := map[string]interface{}{
				"type":      "history",
				"name":      hs.Name,
				"sessionID": hs.ID,
			}
			return info
		}
	}

	return nil
}

func truncateSessionID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:8] + "..." + id[len(id)-4:]
}
