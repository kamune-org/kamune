package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v3/pkg/application"
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

// p2pListenerI is the interface shared by broker-based and direct P2P
// listeners. Both support Close and Addr; only the broker variant has
// Token and refresh logic.
type p2pListenerI interface {
	Close() error
	Addr() *net.UDPAddr
}

// SessionInfo describes a live session to the frontend. PeerName is the
// session's label: the name stored for the peer's key, a name the user
// gave the session, or a key-derived label for a peer that is not
// stored. ClaimedName is the name the peer introduced itself with, which
// proves nothing and is only shown as the peer's claim.
type SessionInfo struct {
	ID               string        `json:"id"`
	PeerName         string        `json:"peerName"`
	ClaimedName      string        `json:"claimedName"`
	PeerKey          string        `json:"peerKey"`
	PeerFingerprint  string        `json:"peerFingerprint"`
	KnownPeer        bool          `json:"knownPeer"`
	NameMismatch     bool          `json:"nameMismatch"`
	NameConflict     bool          `json:"nameConflict"`
	IsServer         bool          `json:"isServer"`
	MsgCount         int           `json:"msgCount"`
	LastActivity     time.Time     `json:"lastActivity"`
	TransportType    string        `json:"transportType"`
	RemoteVersion    string        `json:"remoteVersion"`
	SessionTTL       time.Duration `json:"sessionTTL"`
	SessionStartedAt time.Time     `json:"sessionStartedAt"`
}

// ConnectResult is the structured return value of ConnectToServer. On
// success ErrorCode is empty and SessionID is the kamune session ID. On
// failure ErrorCode is a stable string the frontend can switch on (e.g.
// "hole_punch_failed" → show P2PFallbackDialog; "missing_broker" → prompt
// for a broker address; etc.). The error is reserved for programmer /
// transport-level errors that should never reach the user; user-facing
// failure is signaled via ErrorCode.
type ConnectResult struct {
	SessionID string `json:"sessionId"`
	ErrorCode string `json:"errorCode"`
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

type ServerStatusInfo struct {
	Running   bool   `json:"running"`
	Transport string `json:"transport"`
	Addr      string `json:"addr"`
	RelayAddr string `json:"relayAddr"`
	Name      string `json:"name"`
	StartedAt string `json:"startedAt,omitempty"`
}

type LogEntryInfo struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type liveSession struct {
	mu               sync.Mutex
	ID               string
	PeerName         string
	Identity         peerIdentity
	RemoteVersion    string
	Transport        *kamune.Transport
	relayToken       *relayconn.RelayTokenPending
	Messages         []MessageInfo
	LastActivity     time.Time
	ReceiveDone      chan struct{}
	IsServer         bool
	TransportType    string
	SessionTTL       time.Duration
	SessionStartedAt time.Time
	pingFailures     int
	lastPongAt       time.Time
	pongCh           chan []byte

	reconnectFn     func(sessionID string) (*kamune.Transport, error)
	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc
	keepAliveDone   chan struct{}
}

// info returns the frontend view of s. The caller holds a.mu.
func (s *liveSession) info() SessionInfo {
	return SessionInfo{
		ID:               s.ID,
		PeerName:         s.PeerName,
		ClaimedName:      s.Identity.ClaimedName,
		PeerKey:          s.Identity.KeyB64,
		PeerFingerprint:  s.Identity.Fingerprint,
		KnownPeer:        s.Identity.Known,
		NameMismatch:     s.Identity.NameMismatch,
		NameConflict:     s.Identity.NameConflict,
		IsServer:         s.IsServer,
		MsgCount:         len(s.Messages),
		LastActivity:     s.LastActivity,
		TransportType:    s.TransportType,
		RemoteVersion:    s.RemoteVersion,
		SessionTTL:       s.SessionTTL,
		SessionStartedAt: s.SessionStartedAt,
	}
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
	Token      string        `json:"token"`
	Consumed   bool          `json:"consumed"`
	TTL        time.Duration `json:"ttl"`
	SessionTTL time.Duration `json:"sessionTtl"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	// Mode is "static" when derived from a peer public key, "random"
	// when the relay assigned the token. Used by the sidebar to
	// group / label entries distinctly.
	Mode string `json:"mode"`
	// PeerPubB64 is set when Mode == "static"; identifies the
	// peer this token was derived for (so the sidebar can show the
	// peer's name alongside the token).
	PeerPubB64 string `json:"peerPubB64,omitempty"`
	listener   kamune.Listener
	sessionID  string
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
	ctx       context.Context
	ctxCancel context.CancelFunc
	wails     *application.App
	window    *application.WebviewWindow
	appMenu   *application.Menu
	mu        sync.RWMutex

	sessions            []*liveSession
	histSessions        []*historySession
	server              *kamune.Server
	serverVerifMode     VerificationMode
	serverDone          chan struct{}
	serverTransportType string

	relayAddr       string
	relayPassword   string
	relaySessionTTL time.Duration
	relayTokens     []relayToken
	relayListeners  *multiListener

	brokerClient *BrokerClient
	p2pListener  p2pListenerI
	p2pTokens    []p2pToken

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

	serverAddr           string
	serverTransport      string
	serverRelayAddr      string
	serverName           string
	serverPassword       string
	serverBrokerAddr     string
	serverPeerPubB64     string
	serverDirectPeerAddr string
	serverUseP2P         bool
	serverUseBroker      bool

	logEntries    []LogEntryInfo
	logMu         sync.RWMutex
	logBufferSize int
	logLevel      string
	theme         string

	verifMu        sync.Mutex
	verifRequests  map[int64]*pendingVerification
	verifIDCounter atomic.Int64

	verifRadioItems []*application.MenuItem

	incognito         bool
	incognitoMenuItem *application.MenuItem

	peers []PeerInfo
}

func NewApp() *App {
	bc, err := NewBrokerClient()
	if err != nil {
		// X25519 key generation is a fatal startup error: the bus needs a
		// stable broker identity, and the OS RNG is the only failure source.
		slog.Error("init broker client", "err", err)
		os.Exit(1)
	}
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
		logLevel:       "INFO",
		verifRequests:  make(map[int64]*pendingVerification),
		peers:          make([]PeerInfo, 0),
		brokerClient:   bc,
		p2pTokens:      make([]p2pToken, 0),
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

func (a *App) ServiceStartup(
	ctx context.Context, _ application.ServiceOptions,
) error {
	ctx, cancel := context.WithCancel(ctx)
	a.ctx = ctx
	a.ctxCancel = cancel

	homeDir, err := os.UserHomeDir()
	if err != nil {
		a.addLogEntry("ERROR", "Failed to get home dir: "+err.Error())
		return nil
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
			return nil
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
			return nil
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
	return nil
}

func (a *App) ServiceShutdown() error {
	a.addLogEntry("INFO", "Application shutting down")
	if a.ctxCancel != nil {
		a.ctxCancel()
	}

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
		if s.reconnectCancel != nil {
			s.reconnectCancel()
		}
	}
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
	return nil
}

func (a *App) emitEvent(eventName string, data ...any) {
	if a.wails == nil {
		return
	}
	a.wails.Event.Emit(eventName, data...)
}

func (a *App) updateMenu() {
	if a.appMenu != nil {
		a.appMenu.Update()
	}
}

func (a *App) lifeCtx() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func (a *App) confirm(
	title, message, action, cancel string,
) bool {
	if a.wails == nil {
		return false
	}
	yesLabel, noLabel := action, cancel
	if runtime.GOOS == "windows" {
		yesLabel, noLabel = "Yes", "No"
	}
	done := make(chan bool, 1)
	d := a.wails.Dialog.Question().
		SetTitle(title).
		SetMessage(message)
	d.AddButton(yesLabel).OnClick(func() { done <- true })
	no := d.AddButton(noLabel)
	no.OnClick(func() { done <- false })
	d.SetDefaultButton(no)
	d.SetCancelButton(no)
	d.Show()
	return <-done
}

func (a *App) errorDialog(title, message string) {
	if a.wails == nil {
		return
	}
	a.wails.Dialog.Error().
		SetTitle(title).
		SetMessage(message).
		Show()
}

func (a *App) saveFile(
	title, filename string, filters [][2]string,
) (string, error) {
	if a.wails == nil {
		return "", nil
	}
	opts := &application.SaveFileDialogOptions{
		Title:                title,
		Filename:             filename,
		CanCreateDirectories: true,
	}
	d := a.wails.Dialog.SaveFileWithOptions(opts)
	for _, f := range filters {
		d.AddFilter(f[0], f[1])
	}
	path, err := d.PromptForSingleSelection()
	if path == "" {
		return "", nil
	}
	return path, err
}

func (a *App) addLogEntry(level, msg string) {
	entry := LogEntryInfo{
		Timestamp: time.Now(),
		Level:     level,
		Message:   "[cmd/bus] " + msg,
	}

	a.logMu.Lock()
	a.logEntries = append(a.logEntries, entry)
	if len(a.logEntries) > a.logBufferSize {
		a.logEntries = a.logEntries[len(a.logEntries)-a.logBufferSize:]
	}
	a.logMu.Unlock()

	a.emitEvent("log-entry", entry)
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

	a.emitEvent("status-changed", StatusInfo{Status: status, Message: msg})
}

func (a *App) initFromStorage() {
	if _, err := os.Stat(a.dbPath); os.IsNotExist(err) {
		a.addLogEntry("DEBUG", "No existing storage to load from")
		a.mu.Lock()
		a.pubKey = nil
		a.storageReady = true
		a.mu.Unlock()
		a.emitEvent("storage-ready")
		a.emitEvent("fingerprint-changed", "", "", "", "")
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
			a.emitEvent("local-name-changed", name)
		}

		modeStr, modeErr := store.GetSettings("bus", "verification_mode")
		if modeErr == nil && modeStr != "" {
			if mode, err := strconv.Atoi(modeStr); err == nil {
				a.mu.Lock()
				a.verifMode = VerificationMode(mode)
				a.mu.Unlock()

				for _, item := range a.verifRadioItems {
					item.SetChecked(false)
				}
				if mode >= 0 && mode < len(a.verifRadioItems) {
					a.verifRadioItems[mode].SetChecked(true)
				}
				a.updateMenu()
				a.emitEvent("verification-mode-changed", mode)
			}
		}

		incognitoStr, incognitoErr := store.GetSettings("bus", "incognito")
		if incognitoErr == nil && incognitoStr == "true" {
			a.mu.Lock()
			a.incognito = true
			a.mu.Unlock()
			a.emitEvent("incognito-changed", true)
		}

		logLevel, logLevelErr := store.GetSettings("bus", "log_level")
		if logLevelErr == nil && logLevel != "" {
			a.mu.Lock()
			a.logLevel = logLevel
			a.mu.Unlock()
			a.emitEvent("log-level-changed", logLevel)
		}

		theme, themeErr := store.GetSettings("bus", "theme")
		if themeErr == nil && theme != "" {
			a.mu.Lock()
			a.theme = theme
			a.mu.Unlock()
			a.emitEvent("theme-changed", theme)
		}

		a.emitEvent("storage-ready")
		a.emitEvent("fingerprint-changed", emoji, b64, hex, sum)
		a.addLogEntry("INFO", "Loaded fingerprint from existing identity")
	} else {
		a.mu.Lock()
		a.pubKey = nil
		a.storageReady = true
		a.mu.Unlock()
		a.emitEvent("storage-ready")
		a.emitEvent("fingerprint-changed", "", "", "", "")
		a.addLogEntry("DEBUG", "No identity key found: "+err.Error())
	}

	a.loadHistorySessions(a.db)
	a.refreshPeersCache()
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

	a.emitEvent("history-updated")
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

	a.emitEvent("local-name-changed", name)
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

	a.emitEvent("fingerprint-changed", "", "", "", "")
	a.emitEvent("request-passphrase")
	a.addLogEntry("INFO", "DB path changed to: "+path)
}

func (a *App) OpenFileDialog() string {
	if a.wails == nil {
		return ""
	}
	dir, err := a.wails.Dialog.OpenFile().
		SetTitle("Select Database Directory").
		CanChooseDirectories(true).
		CanChooseFiles(false).
		PromptForSingleSelection()
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
		if !a.confirm(
			"Restart Server?",
			"The verification mode change only applies to new "+
				"client connections. To apply it to incoming server "+
				"connections as well, the server must restart. This "+
				"will disconnect all active sessions.",
			"Restart Server",
			"Cancel",
		) {
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
	a.emitEvent("verification-mode-changed", mode)

	if serverRunning {
		if err := a.restartServer(); err != nil {
			a.addLogEntry("ERROR", "Failed to restart server after mode change: "+err.Error())
			a.mu.Lock()
			a.verifMode = oldMode
			a.mu.Unlock()
			if store := a.store(); store != nil {
				_ = store.SetSettings("bus", "verification_mode", strconv.Itoa(int(oldMode)))
			}
			a.emitEvent("verification-mode-changed", int(oldMode))
			a.errorDialog(
				"Restart Failed",
				"Failed to restart server. The verification mode "+
					"has been reverted.\n\nError: "+err.Error(),
			)
			return false
		}
	}

	return true
}

func (a *App) GetIncognito() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.incognito
}

func (a *App) SetIncognito(on bool) bool {
	a.mu.RLock()
	if a.incognito == on {
		a.mu.RUnlock()
		return false
	}
	a.mu.RUnlock()

	a.mu.Lock()
	a.incognito = on
	a.mu.Unlock()

	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "incognito", strconv.FormatBool(on))
	}
	a.addLogEntry("INFO", "Incognito mode: "+strconv.FormatBool(on))
	a.emitEvent("incognito-changed", on)
	return true
}

func (a *App) UpdateIncognitoMenu(on bool) {
	if a.incognitoMenuItem != nil {
		a.incognitoMenuItem.SetChecked(on)
		a.updateMenu()
	}
}

func (a *App) GetTheme() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.theme
}

func (a *App) SetTheme(theme string) {
	a.mu.RLock()
	if a.theme == theme {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	a.mu.Lock()
	a.theme = theme
	a.mu.Unlock()

	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "theme", theme)
	}
	a.addLogEntry("INFO", "Theme: "+theme)
	a.emitEvent("theme-changed", theme)
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
	a.emitEvent("relay-tokens", tokens)

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
		tokens := a.relayTokensSnapshotLocked()
		a.mu.Unlock()
		if s, ok := rt.listener.(interface{ Stop() }); ok {
			s.Stop()
		}
		a.emitEvent("relay-tokens", tokens)
		a.addLogEntry("INFO", "Discarded consumed relay token")
	}()
}

func (a *App) relayTokensSnapshotLocked() []relayToken {
	tokens := make([]relayToken, len(a.relayTokens))
	copy(tokens, a.relayTokens)
	return tokens
}

func (a *App) getRelayTokens() []relayToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.relayTokensSnapshotLocked()
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
	a.emitEvent("fingerprint-format-changed", fmt)
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
		result = append(result, s.info())
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

func (a *App) GetServerBrokerAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverBrokerAddr
}

func (a *App) GetServerStatus() ServerStatusInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	status := ServerStatusInfo{
		Running:   a.server != nil,
		Transport: a.serverTransportType,
		Addr:      a.serverAddr,
		RelayAddr: a.serverRelayAddr,
		Name:      a.serverName,
	}
	if status.Running {
		var earliest time.Time
		for _, s := range a.sessions {
			if s.IsServer && !s.SessionStartedAt.IsZero() &&
				(earliest.IsZero() || s.SessionStartedAt.Before(earliest)) {
				earliest = s.SessionStartedAt
			}
		}
		if !earliest.IsZero() {
			status.StartedAt = earliest.Format(time.RFC3339)
		}
	}
	return status
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

	filePath, err := a.saveFile(
		"Export Logs",
		fmt.Sprintf(
			"kamune-logs-%s.txt",
			time.Now().Format("2006-01-02_150405"),
		),
		[][2]string{
			{"Text Files", "*.txt"},
			{"All Files", "*"},
		},
	)
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

func (a *App) GetLogLevel() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.logLevel
}

func (a *App) SetLogLevel(level string) {
	a.mu.Lock()
	a.logLevel = level
	a.mu.Unlock()
	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "log_level", level)
	}
}

func (a *App) CopyToClipboard(text string) error {
	if a.wails == nil {
		return fmt.Errorf("clipboard unavailable")
	}
	if !a.wails.Clipboard.SetText(text) {
		return fmt.Errorf("failed to set clipboard")
	}
	return nil
}

func (a *App) SendNotification(title, message string) {
	a.emitEvent("notification", title, message)
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

	filePath, err := a.saveFile(
		"Save Connection Card",
		fmt.Sprintf(
			"kamune-connection-card-%s.png",
			time.Now().Format("2006-01-02_150405"),
		),
		[][2]string{{"PNG Images", "*.png"}},
	)
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
	if a.window == nil {
		return
	}
	a.window.ToggleFullscreen()
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
	a.emitEvent("session-updated")
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

	a.emitEvent("history-updated")
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

	a.emitEvent("history-updated")
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

	a.emitEvent("history-loaded", sessionID)
}

func (a *App) GetSessionInfo(sessionID string) map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, s := range a.sessions {
		if s.ID == sessionID {
			return map[string]interface{}{
				"type":            "live",
				"peerName":        s.PeerName,
				"claimedName":     s.Identity.ClaimedName,
				"knownPeer":       s.Identity.Known,
				"peerFingerprint": s.Identity.Fingerprint,
				"peerKey":         s.Identity.KeyB64,
				"sessionID":       s.ID,
				"messageCount":    len(s.Messages),
				"lastActivity":    s.LastActivity.Format(time.RFC3339),
				"isServer":        s.IsServer,
				"transportType":   s.TransportType,
				"remoteVersion":   s.RemoteVersion,
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
