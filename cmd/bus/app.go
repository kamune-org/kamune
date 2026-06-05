package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zalando/go-keyring"
)

type ver struct {
	major, minor int
}

func parseVer(v string) (ver, bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return ver{}, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ver{}, false
	}
	return ver{major: maj, minor: min}, true
}

func checkMinorMismatch(local, remote string) (string, bool) {
	if remote == "" {
		return "", false
	}
	lv, ok := parseVer(local)
	if !ok {
		return "", false
	}
	rv, ok := parseVer(remote)
	if !ok {
		return "", false
	}
	if lv.major == rv.major && lv.minor != rv.minor {
		return fmt.Sprintf("Minor version mismatch (v%s vs v%s): things may not work as expected", remote, local), true
	}
	return "", false
}

const channelTimeout = 5 * time.Second

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
	StatusVerifying    ConnectionStatus = "verifying"
)

var appVersion = "dev"

type VerificationMode int

const (
	VerificationModeStrict     VerificationMode = 0
	VerificationModeQuick      VerificationMode = 1
	VerificationModeAutoAccept VerificationMode = 2
)

type SessionInfo struct {
	ID            string    `json:"id"`
	PeerName      string    `json:"peerName"`
	IsServer      bool      `json:"isServer"`
	MsgCount      int       `json:"msgCount"`
	LastActivity  time.Time `json:"lastActivity"`
	TransportType string    `json:"transportType"`
	RemoteVersion string    `json:"remoteVersion"`
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
	ID            string
	PeerName      string
	RemoteVersion string
	Transport     *kamune.Transport
	Messages      []MessageInfo
	LastActivity  time.Time
	ReceiveDone   chan struct{}
	IsServer      bool
	TransportType string
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

type relayToken struct {
	Token     string        `json:"token"`
	Consumed  bool          `json:"consumed"`
	TTL       time.Duration `json:"ttl"`
	ExpiresAt time.Time     `json:"expiresAt"`
	listener  kamune.Listener
}

type ShareInfo struct {
	URL              string          `json:"url"`
	Transport        string          `json:"transport"`
	Address          string          `json:"address"`
	Port             string          `json:"port"`
	FingerprintEmoji string          `json:"fingerprintEmoji"`
	FingerprintHex   string          `json:"fingerprintHex"`
	RelayInfo        *ShareRelayInfo `json:"relayInfo,omitempty"`
}

type ShareRelayInfo struct {
	Address  string `json:"address"`
	Scheme   string `json:"scheme"`
	Token    string `json:"token"`
	Password bool   `json:"password"`
}

type App struct {
	ctx context.Context
	mu  sync.RWMutex

	sessions            []*liveSession
	histSessions        []*historySession
	server              *kamune.Server
	serverDone          chan struct{}
	serverTransportType string

	relayAddr      string
	relayPassword  string
	relayTokens    []relayToken
	relayListeners *multiListener

	startCtx    context.Context
	startCancel context.CancelFunc

	dbPath       string
	db           *storage.Storage
	storeMu      sync.Mutex
	passphrase   atomic.Value // stores []byte
	storageReady bool
	pubKey       []byte
	myName       string

	status          ConnectionStatus
	statusMsg       string
	activeSessionID string
	verifMode       VerificationMode
	appVersion      string
	fingerprintFmt  string

	serverAddr      string
	serverTransport string
	serverRelayAddr string
	serverName      string
	serverPassword  string

	logEntries    []LogEntryInfo
	logMu         sync.RWMutex
	logBufferSize int

	verifMu        sync.Mutex
	verifRequests  map[int64]*pendingVerification
	verifIDCounter atomic.Int64

	verifRadioItems  []*menu.MenuItem
}

func NewApp() *App {
	return &App{
		sessions:       make([]*liveSession, 0),
		histSessions:   make([]*historySession, 0),
		status:         StatusDisconnected,
		statusMsg:      "Not connected",
		verifMode:      VerificationModeQuick,
		appVersion:     appVersion,
		fingerprintFmt: "hex",
		logBufferSize:  200,
		logEntries:     make([]LogEntryInfo, 0, 200),
		verifRequests:  make(map[int64]*pendingVerification),
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
		p, _ := a.passphrase.Load().([]byte)
		return p, nil
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	homeDir, err := os.UserHomeDir()
	if err != nil {
		a.addLogEntry("ERROR", "Failed to get home dir: "+err.Error())
		return
	}

	if envPath := os.Getenv("KAMUNE_DB_PATH"); envPath != "" {
		a.dbPath = envPath
	} else {
		a.dbPath = filepath.Join(homeDir, ".config", "kamune", "db")
	}

	passphrase, err := keyring.Get(keychainService, keychainAccount(a.dbPath))
	switch {
	case err == nil && passphrase == "":
		a.passphrase.Store([]byte(passphrase))

		store, storeErr := storage.OpenStorage(
			storage.WithDBPath(a.dbPath),
			storage.WithPassphraseHandler(a.passphraseHandler()),
		)
		if storeErr == nil {
			a.storeMu.Lock()
			a.db = store
			a.storeMu.Unlock()
			a.addLogEntry("INFO", "Loaded empty passphrase from keychain — no password")
			a.initFromStorage()
			return
		}

		a.passphrase.Store([]byte(nil))
		_ = keyring.Delete(keychainService, keychainAccount(a.dbPath))
		a.addLogEntry("WARN", "Saved empty passphrase is invalid, clearing and prompting")

	case err == nil && passphrase != "":
		a.passphrase.Store([]byte(passphrase))

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

		a.passphrase.Store([]byte(nil))
		keyring.Delete(keychainService, keychainAccount(a.dbPath))
		a.addLogEntry("WARN", "Keychain passphrase is invalid, clearing and prompting")

	default:
		if err != nil {
			a.addLogEntry("WARN", "Keychain lookup failed: "+err.Error())
		}
	}

	a.addLogEntry("INFO", "Application started — awaiting passphrase")
}

func (a *App) shutdown(ctx context.Context) {
	a.addLogEntry("INFO", "Application shutting down")

	var sessions []*liveSession
	var serverDone chan struct{}

	a.mu.Lock()
	if a.relayListeners != nil {
		a.relayListeners.Close()
		a.relayListeners = nil
	}
	if a.server != nil {
		a.server.Close()
		a.server = nil
	}
	sessions = append([]*liveSession(nil), a.sessions...)
	a.sessions = nil
	serverDone = a.serverDone
	a.serverDone = nil
	a.mu.Unlock()

	for _, s := range sessions {
		s.Transport.Close()
	}
	for _, s := range sessions {
		waitOrTimeout(s.ReceiveDone, "session receive: "+s.ID)
	}

	if serverDone != nil {
		waitOrTimeout(serverDone, "ListenAndServe")
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

func waitOrTimeout[T any](ch <-chan T, label string) {
	select {
	case <-ch:
	case <-time.After(channelTimeout):
		slog.Warn("Timeout waiting for " + label)
	}
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
		a.pubKey = nil
		a.storageReady = true
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "", "", "")
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
		b64 := fingerprint.Base64(pubKey)
		hex := fingerprint.Hex(pubKey)
		sum := fingerprint.Sum(pubKey)

		a.mu.Lock()
		a.pubKey = pubKey
		a.storageReady = true
		a.mu.Unlock()

		name, nameErr := store.GetSettings("bus", "local_name")
		if nameErr == nil && name == "" {
			name = fingerprint.Pseudonym(pubKey)
			_ = store.SetSettings("bus", "local_name", name)
		}
		if nameErr == nil {
			a.mu.Lock()
			a.myName = name
			a.mu.Unlock()
			runtime.EventsEmit(a.ctx, "local-name-changed", name)
		}

		modeStr, modeErr := store.GetSettings("bus", "verification_mode")
		if modeErr == nil && modeStr != "" {
			if mode, err := strconv.Atoi(modeStr); err == nil {
				a.mu.Lock()
				a.verifMode = VerificationMode(mode)
				a.mu.Unlock()

				for _, item := range a.verifRadioItems {
					item.Checked = false
				}
				if mode >= 0 && mode < len(a.verifRadioItems) {
					a.verifRadioItems[mode].Checked = true
				}
				runtime.MenuUpdateApplicationMenu(a.ctx)
				runtime.EventsEmit(a.ctx, "verification-mode-changed", mode)
			}
		}

		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", emoji, b64, hex, sum)
		a.addLogEntry("INFO", "Loaded fingerprint from existing identity")
	} else {
		a.mu.Lock()
		a.pubKey = nil
		a.storageReady = true
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "storage-ready")
		runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "", "", "")
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

func (a *App) GetLibraryVersion() string {
	return kamune.AppVersion
}

func (a *App) GetMyName() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.myName
}

const maxNameLength = 32

func (a *App) SetMyName(name string) error {
	if len(name) > maxNameLength {
		return fmt.Errorf("name must be %d characters or fewer", maxNameLength)
	}

	store := a.store()
	if store != nil {
		if err := store.SetSettings("bus", "local_name", name); err != nil {
			return fmt.Errorf("persist name: %w", err)
		}
	}

	a.mu.Lock()
	a.myName = name
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "local-name-changed", name)
	return nil
}

func (a *App) GetStatus() StatusInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return StatusInfo{Status: a.status, Message: a.statusMsg}
}

func (a *App) GetFingerprint() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	emoji := ""
	b64 := ""
	hex := ""
	sum := ""
	if len(a.pubKey) > 0 {
		emoji = strings.Join(fingerprint.Emoji(a.pubKey), " • ")
		b64 = fingerprint.Base64(a.pubKey)
		hex = fingerprint.Hex(a.pubKey)
		sum = fingerprint.Sum(a.pubKey)
	}
	return map[string]string{"emoji": emoji, "b64": b64, "hex": hex, "sum": sum}
}

func (a *App) GetDBPath() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.dbPath
}

func (a *App) SetDBPath(path string) {
	a.mu.Lock()
	a.dbPath = path
	a.passphrase.Store([]byte(nil))
	a.pubKey = nil
	a.storageReady = false
	a.mu.Unlock()

	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	a.storeMu.Unlock()

	runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "", "", "")
	runtime.EventsEmit(a.ctx, "request-passphrase")
	a.addLogEntry("INFO", "DB path changed to: "+path)
}

func (a *App) OpenFileDialog() string {
	dir, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Database Directory",
	})
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "db")
}

func (a *App) GetVerificationMode() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return int(a.verifMode)
}

func (a *App) SetVerificationMode(mode int) bool {
	a.mu.RLock()
	if a.verifMode == VerificationMode(mode) {
		a.mu.RUnlock()
		return false
	}
	serverRunning := a.server != nil
	a.mu.RUnlock()

	if serverRunning {
		result, err := runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
			Type:          runtime.QuestionDialog,
			Title:         "Restart Server?",
			Message:       "The verification mode change only applies to new client connections. To apply it to incoming server connections as well, the server must restart. This will disconnect all active sessions.",
			Buttons:       []string{"Restart Server", "Cancel"},
			DefaultButton: "Cancel",
			CancelButton:  "Cancel",
		})
		if err != nil || result == "Cancel" {
			return false
		}
	}

	a.mu.RLock()
	oldMode := a.verifMode
	a.mu.RUnlock()

	a.mu.Lock()
	a.verifMode = VerificationMode(mode)
	a.mu.Unlock()
	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "verification_mode", strconv.Itoa(mode))
	}
	a.addLogEntry("INFO", "Verification mode set to: "+verifModeName(VerificationMode(mode)))
	runtime.EventsEmit(a.ctx, "verification-mode-changed", mode)

	if serverRunning {
		if err := a.restartServer(); err != nil {
			a.addLogEntry("ERROR", "Failed to restart server after mode change: "+err.Error())
			a.mu.Lock()
			a.verifMode = oldMode
			a.mu.Unlock()
			if store := a.store(); store != nil {
				_ = store.SetSettings("bus", "verification_mode", strconv.Itoa(int(oldMode)))
			}
			runtime.EventsEmit(a.ctx, "verification-mode-changed", int(oldMode))
			runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
				Type:    runtime.ErrorDialog,
				Title:   "Restart Failed",
				Message: "Failed to restart server. The verification mode has been reverted.\n\nError: " + err.Error(),
			})
			return false
		}
	}

	return true
}

func (a *App) markRelayTokenConsumed(token string) {
	a.mu.Lock()
	for i := range a.relayTokens {
		if a.relayTokens[i].Token == token && !a.relayTokens[i].Consumed {
			a.relayTokens[i].Consumed = true
			break
		}
	}
	tokens := make([]relayToken, len(a.relayTokens))
	copy(tokens, a.relayTokens)
	a.mu.Unlock()
	runtime.EventsEmit(a.ctx, "relay-tokens", tokens)

	// Discard consumed tokens after a brief grace period so the UI can
	// show the consumed state briefly before it disappears.
	go func() {
		time.Sleep(4 * time.Second)
		a.mu.Lock()
		idx := -1
		for i, t := range a.relayTokens {
			if t.Token == token {
				idx = i
				break
			}
		}
		if idx == -1 {
			a.mu.Unlock()
			return
		}
		rt := a.relayTokens[idx]
		a.relayTokens = append(a.relayTokens[:idx], a.relayTokens[idx+1:]...)
		a.mu.Unlock()
		if s, ok := rt.listener.(interface{ Stop() }); ok {
			s.Stop()
		}
		runtime.EventsEmit(a.ctx, "relay-tokens", a.getRelayTokens())
		a.addLogEntry("INFO", "Discarded consumed relay token")
	}()
}

func (a *App) getRelayTokens() []relayToken {
	tokens := make([]relayToken, len(a.relayTokens))
	copy(tokens, a.relayTokens)
	return tokens
}

func (a *App) GetFingerprintFormat() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.fingerprintFmt
}

func (a *App) SetFingerprintFormat(fmt string) {
	a.mu.Lock()
	a.fingerprintFmt = fmt
	a.mu.Unlock()
	runtime.EventsEmit(a.ctx, "fingerprint-format-changed", fmt)
	a.addLogEntry("DEBUG", "Fingerprint format set to: "+fmt)
}

func (a *App) SubmitPassphrase(passphrase string, saveToKeychain bool) error {
	a.passphrase.Store([]byte(passphrase))

	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
	a.storeMu.Unlock()

	store := a.store()
	if store == nil {
		a.passphrase.Store([]byte(nil))
		return fmt.Errorf("wrong passphrase or corrupted database")
	}

	if saveToKeychain {
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
			ID:            s.ID,
			PeerName:      s.PeerName,
			IsServer:      s.IsServer,
			MsgCount:      len(s.Messages),
			LastActivity:  s.LastActivity,
			TransportType: s.TransportType,
			RemoteVersion: s.RemoteVersion,
		})
	}
	return result
}

func (a *App) GetServerRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.server != nil
}

func (a *App) GetServerTransport() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverTransportType
}

func (a *App) GetRelayToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.relayTokens) > 0 {
		return a.relayTokens[len(a.relayTokens)-1].Token
	}
	return ""
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
			sort.SliceStable(msgs, func(i, j int) bool {
				return msgs[i].Timestamp.Before(msgs[j].Timestamp)
			})
			return msgs
		}
	}
	return nil
}

func (a *App) GetHistoryMessages(sessionID string) []MessageInfo {
	a.mu.RLock()
	var found bool
	for _, hs := range a.histSessions {
		if hs.ID == sessionID && hs.Loaded {
			found = true
			break
		}
	}
	a.mu.RUnlock()

	if !found {
		return nil
	}

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
}

func (a *App) ExportLogsToFile() error {
	a.logMu.RLock()
	entries := make([]LogEntryInfo, len(a.logEntries))
	copy(entries, a.logEntries)
	a.logMu.RUnlock()

	filePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export Logs",
		DefaultFilename: fmt.Sprintf("kamune-logs-%s.txt", time.Now().Format("2006-01-02_150405")),
		Filters: []runtime.FileFilter{
			{DisplayName: "Text Files", Pattern: "*.txt"},
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
	if err != nil {
		return fmt.Errorf("save dialog: %w", err)
	}
	if filePath == "" {
		return nil
	}

	go func() {
		f, err := os.Create(filePath)
		if err != nil {
			a.addLogEntry("ERROR", "Export logs: create file: "+err.Error())
			return
		}
		defer f.Close()

		for _, e := range entries {
			if _, err := fmt.Fprintf(f, "%s [%s] %s\n", e.Timestamp.Format(time.RFC3339), e.Level, e.Message); err != nil {
				a.addLogEntry("ERROR", "Export logs: write: "+err.Error())
				return
			}
		}
	}()

	return nil
}

func (a *App) CopyToClipboard(text string) error {
	return runtime.ClipboardSetText(a.ctx, text)
}

func (a *App) SendNotification(title, message string) {
	runtime.EventsEmit(a.ctx, "notification", title, message)
}

func (a *App) SaveCardPNG(dataURL string) error {
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(dataURL, prefix) {
		return fmt.Errorf("invalid data URL")
	}
	data, err := base64.StdEncoding.DecodeString(dataURL[len(prefix):])
	if err != nil {
		return fmt.Errorf("decode base64: %w", err)
	}

	filePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Connection Card",
		DefaultFilename: fmt.Sprintf("kamune-connection-card-%s.png", time.Now().Format("2006-01-02_150405")),
		Filters: []runtime.FileFilter{
			{DisplayName: "PNG Images", Pattern: "*.png"},
		},
	})
	if err != nil {
		return fmt.Errorf("save dialog: %w", err)
	}
	if filePath == "" {
		return nil
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
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
				"transportType": s.TransportType,
				"remoteVersion": s.RemoteVersion,
			}
		}
	}

	for _, hs := range a.histSessions {
		if hs.ID == sessionID {
			info := map[string]interface{}{
				"type":         "history",
				"name":         hs.Name,
				"sessionID":    hs.ID,
				"messageCount": hs.MessageCount,
				"firstMessage": hs.FirstMessage.Format(time.RFC3339),
				"lastMessage":  hs.LastMessage.Format(time.RFC3339),
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
