package main

import (
	"context"
	"encoding/base64"
	"errors"
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
	bolterrors "go.etcd.io/bbolt/errors"
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

// valid reports whether m is one of the defined verification modes.
func (m VerificationMode) valid() bool {
	return m >= VerificationModeStrict && m <= VerificationModeAutoAccept
}

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

	// incognito is the incognito mode the session started in. It is set
	// before the session is published and never changes; see
	// App.sessionIncognito.
	incognito bool

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
	// label names the peer in log entries; see peerIdentity.Label.
	label string
	hex   string
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

	sessions        []*liveSession
	histSessions    []*historySession
	server          *kamune.Server
	serverVerifMode VerificationMode
	// serverIncognito is the incognito mode the server was started in.
	serverIncognito     bool
	serverDone          chan struct{}
	serverTransportType string

	relayAddr       string
	relayPassword   string
	relaySessionTTL time.Duration
	relayTokens     []relayToken
	relayListeners  *multiListener
	// relayResumes counts the awaitRelayResume calls for the sessions of
	// the relay server that relayListeners serves. They write to the
	// database, so StopServer waits for them.
	relayResumes *sync.WaitGroup
	// relayResumeWindow overrides defaultRelayResumeWindow when positive.
	relayResumeWindow time.Duration
	// relayResumeWait, when set, replaces the wait between the relay
	// resume registrations of awaitRelayResume; see App.waitResume.
	relayResumeWait func(ctx context.Context, d time.Duration) bool

	brokerClient *BrokerClient
	p2pListener  p2pListenerI
	p2pTokens    []p2pToken

	startCtx    context.Context
	startCancel context.CancelFunc
	// starting counts StartServer calls in progress. CancelStartServer
	// clears startCancel at once, but the call may still go on to use the
	// database, so this stays set until it returns.
	starting int
	// dialOps counts ConnectToServer calls in progress.
	dialOps int
	// closing counts StopServer and DisconnectSession calls that have
	// taken the server or a session out of the app and are still closing
	// it, which uses the database.
	closing int

	dbPath string
	// db is the open database, or nil until the user unlocks one. Only
	// unlockDB opens it; see store.
	db      *storage.Storage
	storeMu sync.Mutex
	// pendingSettings holds settings changed while no database was open.
	// They are written once one is unlocked. storeMu guards it.
	pendingSettings map[string]string
	// unlockMu serializes unlockDB calls.
	unlockMu sync.Mutex
	// noPassphrase is set while the open database has no passphrase.
	noPassphrase bool
	// storageErr says why the last unlock with a saved passphrase failed.
	storageErr string
	// dbTimeout bounds the wait for a database another process holds.
	// Zero keeps the storage default.
	dbTimeout    time.Duration
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
	// verifTimeout overrides verificationTimeout when positive.
	verifTimeout time.Duration
	// verifPrevStatus is the status from before the open prompts.
	verifPrevStatus StatusInfo

	verifRadioItems []*application.MenuItem

	incognito         bool
	incognitoMenuItem *application.MenuItem

	peers []PeerInfo

	// onEvent, when set, receives every event the app emits, so tests can
	// observe events without a Wails runtime.
	onEvent func(name string, data ...any)
	// confirmFn, when set, answers confirm in place of a native dialog.
	confirmFn func(title, message string) bool
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

// ErrStorageLocked is returned by bindings that need the database while
// none is unlocked.
var ErrStorageLocked = errors.New("the database is not unlocked yet")

// store returns the open database, or nil while none is unlocked. It never
// opens one: the database is opened only with a passphrase the user chose,
// or one saved in the keychain for it, so nothing can create it, or open
// it with the wrong passphrase, before the user has made that choice.
func (a *App) store() *storage.Storage {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()
	return a.db
}

// openDB opens the database at path with passphrase. create says whether
// a database that does not exist yet is created.
func (a *App) openDB(
	path string, passphrase []byte, create bool,
) (*storage.Storage, error) {
	return storage.OpenStorage(
		storage.WithDBPath(path),
		storage.WithPassphraseHandler(func() ([]byte, error) {
			return passphrase, nil
		}),
		storage.WithCreateDB(create),
		storage.WithTimeout(a.dbTimeout),
	)
}

// ErrNoSavedPassphrase is returned by UnlockWithSavedPassphrase when the
// keychain holds no passphrase for the database.
var ErrNoSavedPassphrase = errors.New(
	"no passphrase is saved in the keychain for this database",
)

// unlockError is a failure to open the database, with a message for the
// user. It wraps the storage error.
type unlockError struct {
	msg string
	err error
}

func (e *unlockError) Error() string { return e.msg }
func (e *unlockError) Unwrap() error { return e.err }

// describeOpenError returns err, an error from opening the database, with
// a message that says what went wrong.
func describeOpenError(err error) error {
	var msg string
	switch {
	case errors.Is(err, storage.ErrWrongPassphrase):
		msg = "Wrong passphrase"
	case errors.Is(err, bolterrors.ErrTimeout):
		msg = "The database is in use by another program, such as the " +
			"Kamune TUI, the daemon or another Bus window. Close it and " +
			"try again"
	case errors.Is(err, os.ErrNotExist):
		msg = "There is no database at this path"
	case errors.Is(err, storage.ErrCorruptMetadata):
		msg = "The database's key data is missing or damaged"
	case errors.Is(err, storage.ErrInsecurePermissions):
		msg = "Other users can access the database file, and its " +
			"permissions could not be restricted"
	case errors.Is(err, storage.ErrUnsupportedFormat):
		msg = "The database was written by a newer version of Kamune"
	default:
		msg = "Could not open the database: " + err.Error()
	}
	return &unlockError{msg: msg, err: err}
}

// ErrStorageBusy is returned when the database would change while the
// server, a dial or a session still uses the open one.
var ErrStorageBusy = errors.New(
	"stop the server and close every session before changing the database",
)

// ErrStorageOpen is returned when the database to unlock is already the
// open one.
var ErrStorageOpen = errors.New("this database is already unlocked")

// ErrPassphraseRequired is returned by SubmitPassphrase for an empty
// passphrase. OpenWithoutPassphrase opens a database without one.
var ErrPassphraseRequired = errors.New(
	"enter a passphrase, or choose to use the database without one",
)

// noPassphraseWarning is the confirmation text shown before a database is
// used without a passphrase.
const noPassphraseWarning = "Without a passphrase, the database is not " +
	"protected: the key that encrypts it can be derived from the file " +
	"alone. Anyone who gets a copy of the file, for example from a " +
	"backup or a lost or seized device, can read your identity key, " +
	"your saved peers and your chat history, and can use your " +
	"identity.\n\n" +
	"Use a passphrase unless this database is only for testing."

// storageBusyLocked reports whether anything holds on to the open
// database: a server that is starting, running or stopping, with its
// listeners, a dial in progress or a session that is live or closing. The
// server, dialers and transports keep the Storage they were given, so it
// must stay open while they run. The caller holds a.mu.
func (a *App) storageBusyLocked() bool {
	return a.server != nil || a.starting > 0 || a.dialOps > 0 ||
		a.closing > 0 || len(a.sessions) > 0 || a.relayListeners != nil ||
		a.p2pListener != nil
}

// doneClosing ends a teardown counted in a.closing.
func (a *App) doneClosing() {
	a.mu.Lock()
	a.closing--
	a.mu.Unlock()
}

// canUnlock returns ErrStorageBusy while anything uses the open database
// and ErrStorageOpen when path is the open database.
func (a *App) canUnlock(path string) error {
	a.mu.RLock()
	busy := a.storageBusyLocked()
	samePath := filepath.Clean(path) == filepath.Clean(a.dbPath)
	a.mu.RUnlock()
	if busy {
		return ErrStorageBusy
	}
	if samePath && a.store() != nil {
		return ErrStorageOpen
	}
	return nil
}

// unlockDB opens the database at path with passphrase, creating it when
// create is set, and makes it the open database. A database open before
// is closed only once the new one has opened, so a failed unlock leaves
// it in use. unlockDB refuses while anything uses the open database, and
// when path is the database already open.
func (a *App) unlockDB(path string, passphrase []byte, create bool) error {
	if path == "" {
		return errors.New("no database path")
	}

	a.unlockMu.Lock()
	defer a.unlockMu.Unlock()

	if err := a.canUnlock(path); err != nil {
		return err
	}

	store, err := a.openDB(path, passphrase, create)
	if err != nil {
		return err
	}

	// Swap under a.mu, so that no server or dial can start with the
	// database that is about to close.
	a.mu.Lock()
	if a.storageBusyLocked() {
		a.mu.Unlock()
		_ = store.Close()
		return ErrStorageBusy
	}
	a.dbPath = path
	a.pubKey = nil
	a.storageReady = false
	a.noPassphrase = len(passphrase) == 0
	a.storeMu.Lock()
	old := a.db
	a.db = store
	pending := a.pendingSettings
	a.pendingSettings = nil
	a.storeMu.Unlock()
	a.mu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			a.addLogEntry("WARN", "Failed to close database: "+err.Error())
		}
	}
	for key, value := range pending {
		if err := store.SetSettings("bus", key, value); err != nil {
			a.addLogEntry("WARN", "Failed to save setting "+key+": "+
				err.Error())
		}
	}
	return nil
}

// saveSetting stores a bus setting in the open database. While none is
// open, the setting is kept and written once one is unlocked.
func (a *App) saveSetting(key, value string) {
	a.storeMu.Lock()
	store := a.db
	if store == nil {
		if a.pendingSettings == nil {
			a.pendingSettings = make(map[string]string)
		}
		a.pendingSettings[key] = value
	}
	a.storeMu.Unlock()

	if store == nil {
		return
	}
	if err := store.SetSettings("bus", key, value); err != nil {
		a.addLogEntry("WARN", "Failed to save setting "+key+": "+
			err.Error())
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
	case errors.Is(err, keyring.ErrNotFound):
	case err != nil:
		a.addLogEntry("WARN", "Keychain lookup failed: "+err.Error())
	default:
		if a.unlockSaved(a.dbPath, passphrase) == nil {
			return nil
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
	if a.onEvent != nil {
		a.onEvent(eventName, data...)
	}
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
	if a.confirmFn != nil {
		return a.confirmFn(title, message)
	}
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
		Message:   "[cmd/bus] " + escapeLogText(msg),
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

// replaceStatus sets the status to status and msg only while it is still
// want, so a stale restore does not overwrite a newer status.
func (a *App) replaceStatus(
	want, status ConnectionStatus, msg string,
) {
	a.mu.Lock()
	if a.status != want {
		a.mu.Unlock()
		return
	}
	a.status = status
	a.statusMsg = msg
	a.mu.Unlock()

	a.emitEvent("status-changed", StatusInfo{Status: status, Message: msg})
}

// initFromStorage loads the identity, settings, history and peers from
// the open database and reports that storage is ready.
func (a *App) initFromStorage() {
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
			mode, ok := parseVerificationMode(modeStr)
			if !ok {
				a.addLogEntry("WARN", fmt.Sprintf(
					"Unknown stored verification mode %q, using Strict",
					modeStr,
				))
				mode = VerificationModeStrict
			}
			a.mu.Lock()
			a.verifMode = mode
			a.mu.Unlock()

			checkVerifRadio(a.verifRadioItems, int(mode))
			a.updateMenu()
			a.emitEvent("verification-mode-changed", int(mode))
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

	a.loadHistorySessions(store)
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
			Name:         sanitizeName(s.Name),
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

// SetMyName sets the name this side introduces itself with. It must be
// at most maxLocalNameLength bytes and pass kamune.ValidatePeerName, which
// NewServer and NewDialer enforce.
func (a *App) SetMyName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) > maxLocalNameLength {
		return fmt.Errorf(
			"name must be %d bytes or fewer", maxLocalNameLength,
		)
	}
	if err := kamune.ValidatePeerName(name); err != nil {
		return err
	}

	store := a.store()
	if store == nil {
		return ErrStorageLocked
	}
	if err := store.SetSettings("bus", "local_name", name); err != nil {
		return fmt.Errorf("persist name: %w", err)
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

// autoAcceptWarning is the confirmation text shown before Auto-Accept is
// turned on.
const autoAcceptWarning = "Auto-Accept admits every peer that connects " +
	"without asking you to compare fingerprints, so anyone who can reach " +
	"you gets a session. Outside incognito mode each new peer is also " +
	"saved as a known peer, under a name derived from its key, and Quick " +
	"mode later admits saved peers without asking.\n\n" +
	"Use it only for testing, on a network you trust."

// SetVerificationMode switches the verification mode new connections use
// and reports whether it changed. Switching to Auto-Accept always asks
// for confirmation, and a running server asks before it restarts.
func (a *App) SetVerificationMode(mode int) bool {
	if !VerificationMode(mode).valid() {
		a.addLogEntry("WARN",
			fmt.Sprintf("Rejected unknown verification mode %d", mode))
		return false
	}
	if a.store() == nil {
		a.addLogEntry("WARN",
			"Unlock the database before changing the verification mode")
		return false
	}

	a.mu.RLock()
	if a.verifMode == VerificationMode(mode) {
		a.mu.RUnlock()
		return false
	}
	serverRunning := a.server != nil
	a.mu.RUnlock()

	const restartNote = "The verification mode change only applies to " +
		"new client connections. To apply it to incoming server " +
		"connections as well, the server must restart. This will " +
		"disconnect all active sessions."

	switch {
	case VerificationMode(mode) == VerificationModeAutoAccept:
		// Turning verification off must never happen by accident, for
		// example through the menu shortcut, so it always asks.
		msg := autoAcceptWarning
		if serverRunning {
			msg += "\n\n" + restartNote
		}
		if !a.confirm(
			"Turn Off Peer Verification?", msg, "Use Auto-Accept", "Cancel",
		) {
			a.addLogEntry("INFO", "Kept verification mode: "+
				verifModeName(a.currentVerifMode()))
			return false
		}
	case serverRunning:
		if !a.confirm(
			"Restart Server?", restartNote, "Restart Server", "Cancel",
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
		if err := a.restartServer(
			"apply the verification mode change",
		); err != nil {
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

// sessionIncognito reports whether s keeps its messages off the disk: it
// started in incognito mode, which it keeps for its whole life, or
// incognito mode is on now.
func (a *App) sessionIncognito(s *liveSession) bool {
	return s.incognito || a.GetIncognito()
}

// incognitoBusyLocked reports whether a server start or a dial is in
// progress. Each reads the incognito mode when it begins, so a change
// would not reach the session it makes. The caller holds a.mu.
func (a *App) incognitoBusyLocked() bool {
	return a.starting > 0 || a.dialOps > 0
}

// incognitoBusyNote says why incognito mode cannot change while a server
// starts or a dial is in progress.
const incognitoBusyNote = "wait until the server has started and every " +
	"connection attempt has ended"

// refuseIncognito logs and shows why incognito mode was not changed.
func (a *App) refuseIncognito(reason string) {
	msg := "Incognito mode not changed: " + reason
	a.addLogEntry("WARN", msg)
	a.emitEvent("toast", msg, "warning")
}

// incognitoRestartNote is the confirmation text shown before a change of
// incognito mode restarts the server.
const incognitoRestartNote = "The server decides when it starts whether " +
	"incoming sessions are stored, so it must restart for the incognito " +
	"mode change to apply to them. This will disconnect all active " +
	"sessions."

// SetIncognito turns incognito mode on or off and reports whether it
// changed. It does nothing until a database is unlocked, and while a
// server start or a dial is in progress. A running server restarts, once
// the user confirms, so that its sessions follow the new mode. A session
// started in incognito mode stays in it.
func (a *App) SetIncognito(on bool) bool {
	if a.store() == nil {
		a.addLogEntry("WARN",
			"Unlock the database before changing incognito mode")
		return false
	}

	a.mu.RLock()
	unchanged := a.incognito == on
	serverRunning := a.server != nil
	busy := a.incognitoBusyLocked()
	a.mu.RUnlock()
	if unchanged {
		return false
	}
	if busy {
		a.refuseIncognito(incognitoBusyNote)
		return false
	}
	if serverRunning && !a.confirm(
		"Restart Server?", incognitoRestartNote, "Restart Server", "Cancel",
	) {
		return false
	}

	a.mu.Lock()
	if a.incognito == on {
		a.mu.Unlock()
		return false
	}
	if a.incognitoBusyLocked() {
		a.mu.Unlock()
		a.refuseIncognito(incognitoBusyNote)
		return false
	}
	if (a.server != nil) != serverRunning {
		// The server started or stopped while the user was asked, so
		// whether it must restart is no longer known.
		a.mu.Unlock()
		a.refuseIncognito("the server started or stopped meanwhile; " +
			"try again")
		return false
	}
	a.incognito = on
	a.mu.Unlock()

	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "incognito", strconv.FormatBool(on))
	}
	a.addLogEntry("INFO", "Incognito mode: "+strconv.FormatBool(on))
	a.emitEvent("incognito-changed", on)

	if serverRunning {
		if err := a.restartServer(
			"apply the incognito mode change",
		); err != nil {
			a.addLogEntry("ERROR",
				"Failed to restart server after incognito change: "+
					err.Error())
			a.errorDialog(
				"Restart Failed",
				"The server stopped and could not start again.\n\n"+
					"Error: "+err.Error(),
			)
		}
	}
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

	a.saveSetting("theme", theme)
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

// SubmitPassphrase opens the database at path with passphrase, creating
// it if it does not exist, and makes it the open database in place of
// the one open before. It refuses while the server, a dial or a session
// uses the open database, and when path is the database already open.
func (a *App) SubmitPassphrase(
	path, passphrase string, saveToKeychain bool,
) error {
	if passphrase == "" {
		return ErrPassphraseRequired
	}
	if err := a.unlockDB(path, []byte(passphrase), true); err != nil {
		if errors.Is(err, ErrStorageBusy) || errors.Is(err, ErrStorageOpen) {
			return err
		}
		return describeOpenError(err)
	}
	a.setStorageError("")
	a.addLogEntry("INFO", "Opened database: "+path)

	if saveToKeychain {
		if err := keyring.Set(
			keychainService, keychainAccount(path), passphrase,
		); err != nil {
			a.addLogEntry("WARN", "Failed to save passphrase to keychain: "+err.Error())
		} else {
			a.addLogEntry("INFO", "Passphrase saved to keychain")
		}
	}

	a.initFromStorage()
	return nil
}

// OpenWithoutPassphrase opens the database at path without a passphrase,
// creating it if it does not exist, once the user confirms that such a
// database is not protected. It reports false when the user declines.
// With saveToKeychain, the empty passphrase is saved for path, and the
// database opens without asking at the next start.
func (a *App) OpenWithoutPassphrase(
	path string, saveToKeychain bool,
) (bool, error) {
	if err := a.canUnlock(path); err != nil {
		return false, err
	}
	if !a.confirm(
		"Use the Database Without a Passphrase?", noPassphraseWarning,
		"Use Without Passphrase", "Cancel",
	) {
		return false, nil
	}
	if err := a.unlockDB(path, []byte{}, true); err != nil {
		if errors.Is(err, ErrStorageBusy) || errors.Is(err, ErrStorageOpen) {
			return false, err
		}
		return false, describeOpenError(err)
	}
	a.setStorageError("")
	a.addLogEntry("WARN", "Opened database without a passphrase: "+path)

	if saveToKeychain {
		if err := keyring.Set(
			keychainService, keychainAccount(path), "",
		); err != nil {
			a.addLogEntry("WARN",
				"Failed to save to keychain: "+err.Error())
		}
	}

	a.initFromStorage()
	return true, nil
}

// UnlockWithSavedPassphrase opens the existing database at path with the
// passphrase saved for it in the keychain, as at startup. It lets the
// user try again after the saved passphrase failed for a reason other
// than being wrong, such as another program holding the database.
func (a *App) UnlockWithSavedPassphrase(path string) error {
	passphrase, err := keyring.Get(keychainService, keychainAccount(path))
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNoSavedPassphrase
	}
	if err != nil {
		return fmt.Errorf("keychain lookup failed: %w", err)
	}
	return a.unlockSaved(path, passphrase)
}

// unlockSaved opens the existing database at path with passphrase, which
// was saved for it in the keychain. A failure never removes the saved
// passphrase, since it may be the only copy: another program may hold the
// database, or the file may be missing, damaged or another database, which
// the passphrase does not open even though it opens the right one. Only
// ForgetSavedPassphrase removes it, once the user confirms. The failure is
// kept for GetStorageError.
func (a *App) unlockSaved(path, passphrase string) error {
	err := a.unlockDB(path, []byte(passphrase), false)
	if errors.Is(err, ErrStorageBusy) || errors.Is(err, ErrStorageOpen) {
		return err
	}
	if err != nil {
		err = describeOpenError(err)
		if errors.Is(err, storage.ErrWrongPassphrase) {
			err = &unlockError{
				msg: "The passphrase saved in the keychain does not " +
					"open this database. It was kept, since it may open " +
					"a copy of it. Enter the passphrase, or forget the " +
					"saved one",
				err: err,
			}
		}
		a.addLogEntry("ERROR",
			"Could not open the database with the passphrase saved in "+
				"the keychain, which was kept: "+err.Error())
		a.setStorageError(err.Error())
		return err
	}

	a.setStorageError("")
	if passphrase == "" {
		a.addLogEntry("WARN", "Opened database without a "+
			"passphrase, as saved in the keychain: anyone "+
			"who can read its file can read it")
	} else {
		a.addLogEntry("INFO", "Loaded passphrase from keychain")
	}
	a.initFromStorage()
	return nil
}

// forgetPassphraseWarning is the confirmation text shown before a saved
// passphrase is removed from the keychain.
const forgetPassphraseWarning = "Remove the passphrase saved in the " +
	"system keychain for this database?\n\n%s\n\n" +
	"If you do not know it and have no other copy of it, nothing that " +
	"it encrypts, in this database or in a copy of it, can be read again."

// ForgetSavedPassphrase removes the passphrase saved in the keychain for
// the database at path, once the user confirms. It reports false when the
// user declines, and returns ErrNoSavedPassphrase when none is saved.
func (a *App) ForgetSavedPassphrase(path string) (bool, error) {
	account := keychainAccount(path)
	if _, err := keyring.Get(keychainService, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return false, ErrNoSavedPassphrase
		}
		return false, fmt.Errorf("keychain lookup failed: %w", err)
	}
	if !a.confirm(
		"Forget the Saved Passphrase?",
		fmt.Sprintf(forgetPassphraseWarning, path),
		"Forget", "Cancel",
	) {
		return false, nil
	}
	if err := keyring.Delete(keychainService, account); err != nil {
		return false, fmt.Errorf("failed to clear keychain: %w", err)
	}
	a.setStorageError("")
	a.addLogEntry("INFO", "Passphrase removed from keychain: "+path)
	return true, nil
}

func (a *App) setStorageError(msg string) {
	a.mu.Lock()
	a.storageErr = msg
	a.mu.Unlock()
}

// GetStorageError returns why the database could not be opened with the
// passphrase saved in the keychain, or "" when it could.
func (a *App) GetStorageError() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.storageErr
}

// GetNoPassphrase reports whether the open database has no passphrase,
// so anyone who can read its file can read its contents.
func (a *App) GetNoPassphrase() bool {
	if a.store() == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.noPassphrase
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

// parseVerificationMode parses a stored verification mode. ok is false
// for a value that is not a defined mode.
func parseVerificationMode(s string) (m VerificationMode, ok bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	m = VerificationMode(n)
	return m, m.valid()
}

// checkVerifRadio checks the menu item of mode and unchecks the others.
// A mode without an item leaves every item unchecked.
func checkVerifRadio(items []*application.MenuItem, mode int) {
	for i, item := range items {
		item.SetChecked(i == mode)
	}
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
	a.saveSetting("log_level", level)
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

// RenameSession gives a live session a local label.
func (a *App) RenameSession(sessionID string, name string) error {
	name, err := validateLabel(name)
	if err != nil {
		return err
	}
	a.mu.Lock()
	for _, s := range a.sessions {
		if s.ID == sessionID {
			s.PeerName = name
			break
		}
	}
	a.mu.Unlock()
	a.emitEvent("session-updated")
	return nil
}

// RenameHistorySession gives a stored session a label.
func (a *App) RenameHistorySession(sessionID string, name string) error {
	name, err := validateLabel(name)
	if err != nil {
		return err
	}
	store := a.store()
	if store == nil {
		return errors.New("storage is not available")
	}

	err = store.SetSessionName(sessionID, name)
	if err != nil {
		a.addLogEntry("ERROR", "Failed to rename history session: "+err.Error())
		return fmt.Errorf("rename session: %w", err)
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
	return nil
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
