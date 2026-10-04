package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/zalando/go-keyring"
)

const keychainService = "kamune"

var (
	errPassphraseRequired = errors.New(
		"KAMUNE_DB_PASSPHRASE not set and db_no_passphrase is false; use submit_passphrase to provide one",
	)
	errStorageBusy = errors.New(
		"storage cannot be replaced while networking is active",
	)
	errEmptyPassphrase = errors.New(
		"passphrase is empty; open an unencrypted database with " +
			"open_storage and db_no_passphrase",
	)
)

func keychainAccount(dbPath string) string {
	if dbPath == "" {
		return "db-passphrase:default"
	}
	return "db-passphrase:" + dbPath
}

// keychainGet returns the passphrase saved for dbPath. Only the account
// named by the full path is used. Older versions also used an account named
// by the file's base name, which databases in different directories share.
func keychainGet(dbPath string) (string, error) {
	return keyring.Get(keychainService, keychainAccount(dbPath))
}

// keychainDelete removes the passphrase saved for dbPath. Like keychainGet,
// it leaves the base-name account of older versions alone.
func keychainDelete(dbPath string) error {
	return keyring.Delete(keychainService, keychainAccount(dbPath))
}

func parseLogLevel(level string) (slog.Level, bool) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, true
	case "INFO":
		return slog.LevelInfo, true
	case "WARN", "WARNING":
		return slog.LevelWarn, true
	case "ERROR":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func applySlogLevel(level string) bool {
	lvl, ok := parseLogLevel(level)
	if !ok {
		return false
	}
	daemonLogLevel.Set(lvl)
	return true
}

func validFingerprintFormat(format string) bool {
	switch format {
	case "hex", "emoji", "b64", "sum":
		return true
	default:
		return false
	}
}

// storageSettings are the settings that an opened storage may override.
type storageSettings struct {
	fingerprintFmt string
	logLevel       string
	verifMode      VerificationMode
	incognito      bool
}

// Daemon manages the kamune server and client connections
type Daemon struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.RWMutex
	sessions      map[string]*liveSession
	histSessions  []*historySession
	server        *kamune.Server
	serverDone    chan struct{}
	serverRunning bool
	pubKey        []byte
	myName        string
	dbPath        string
	pendingDBPath string
	verifMode     VerificationMode
	incognito     bool

	// baseSettings holds the settings in effect before the first storage
	// was loaded. Every storage that is loaded starts from them, so no
	// setting carries over from a storage opened earlier.
	baseSettings *storageSettings

	verifMu        sync.Mutex
	verifRequests  map[int64]*pendingVerification
	verifIDCounter atomic.Int64
	// verifPrevStatus and verifPrevMsg hold, under verifMu, the status
	// that the pending verifications replaced: the last one other than
	// verifying that was current when one of them began.
	verifPrevStatus ConnectionStatus
	verifPrevMsg    string

	serverAddr           string
	serverTransport      string
	serverRelayAddr      string
	serverName           string
	serverPassword       string
	serverBrokerAddr     string
	serverPeerPubB64     string
	serverDirectPeerAddr string

	relayAddr       string
	relayPassword   string
	relaySessionTTL time.Duration
	relayTimeout    time.Duration
	matchTimeout    time.Duration
	relayTokens     []relayToken
	relayListeners  *multiListener

	p2pTokens    []p2pToken
	p2pListener  kamune.Listener
	brokerClient *BrokerClient

	startCtx    context.Context
	startCancel context.CancelFunc
	startDone   chan struct{}
	dialOps     int

	status    ConnectionStatus
	statusMsg string

	output   *json.Encoder
	outputMu sync.Mutex

	storeMu  sync.Mutex
	db       *storage.Storage
	dbUnlock storageUnlock

	logEntries    []LogEntryInfo
	logMu         sync.RWMutex
	logBufferSize int
	logLevel      string

	fingerprintFmt string

	wg           sync.WaitGroup
	shutdownOnce sync.Once
}

// NewDaemon creates a new daemon instance
func NewDaemon() *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		sessions:       make(map[string]*liveSession),
		histSessions:   make([]*historySession, 0),
		output:         json.NewEncoder(os.Stdout),
		ctx:            ctx,
		cancel:         cancel,
		verifMode:      VerificationModeQuick,
		relayTimeout:   defaultRelayTimeout,
		matchTimeout:   defaultMatchTimeout,
		status:         StatusDisconnected,
		statusMsg:      "Not connected",
		verifRequests:  make(map[int64]*pendingVerification),
		logBufferSize:  200,
		logEntries:     make([]LogEntryInfo, 0, 200),
		logLevel:       "INFO",
		fingerprintFmt: "hex",
	}
}

// emit sends an event to stdout
func (d *Daemon) emit(evt Evt, correlationID ID, data any) {
	d.outputMu.Lock()
	defer d.outputMu.Unlock()

	event := Event{
		Type: "evt",
		Evt:  evt,
		ID:   correlationID,
		Data: data,
	}
	if err := d.output.Encode(event); err != nil {
		slog.Error("failed to emit event", slog.Any("error", err))
	}
}

// emitError sends an error event
func (d *Daemon) emitError(correlationID ID, code string, errMsg string) {
	d.emit(EvtError, correlationID, MapS{"error": errMsg, "code": code})
}

// addLogEntry logs a message at the given level and stores it in the in-memory
// log buffer for retrieval via get_logs. Also emits evt_log_entry for live
// subscribers.
func (d *Daemon) addLogEntry(level, msg string) {
	var lvl slog.Level
	switch level {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.Log(d.ctx, lvl, msg)

	entry := LogEntryInfo{
		Timestamp: time.Now(),
		Level:     level,
		Message:   "[cmd/daemon] " + msg,
	}

	d.logMu.Lock()
	d.logEntries = append(d.logEntries, entry)
	if len(d.logEntries) > d.logBufferSize {
		d.logEntries = d.logEntries[len(d.logEntries)-d.logBufferSize:]
	}
	d.logMu.Unlock()

	d.emit(EvtLogEntry, "", entry)
}

// setStatus updates the daemon's connection status and emits status_changed.
func (d *Daemon) setStatus(status ConnectionStatus, msg string) {
	d.mu.Lock()
	d.status = status
	d.statusMsg = msg
	d.mu.Unlock()

	d.emit(EvtStatusChanged, "", MapS{
		"status": string(status), "message": msg,
	})
}

func (d *Daemon) isIncognito() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.incognito
}

// store returns the single shared storage instance, or nil if not open.
func (d *Daemon) store() *storage.Storage {
	d.storeMu.Lock()
	defer d.storeMu.Unlock()
	return d.db
}

// closeStore closes the shared storage if open. Safe to call multiple times.
func (d *Daemon) closeStore() {
	d.storeMu.Lock()
	store := d.db
	d.db = nil
	d.dbUnlock = storageUnlock{}
	d.storeMu.Unlock()
	if store != nil {
		if err := store.Close(); err != nil {
			slog.Warn("error closing storage", slog.Any("error", err))
		}
	}
}

// requireStorage emits a "not opened" error and returns false if storage is
// not open. Callers should `return` immediately when this returns false.
func (d *Daemon) requireStorage(cmdID ID) bool {
	if d.store() == nil {
		d.emitError(cmdID, "storage_not_opened", "storage not opened — call open_storage first")
		return false
	}
	return true
}

func (d *Daemon) storageBusy() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.server != nil || d.startCancel != nil || d.dialOps > 0 ||
		len(d.sessions) > 0
}

// storageUnlock says how a storage is unlocked: with passphrase, or with
// none when noPassphrase is set.
type storageUnlock struct {
	passphrase   []byte
	noPassphrase bool
}

func (u storageUnlock) options(path string) []storage.StorageOption {
	var opts []storage.StorageOption
	if path != "" {
		opts = append(opts, storage.WithDBPath(path))
	}
	if u.noPassphrase {
		return append(opts, storage.WithNoPassphrase())
	}
	pass := u.passphrase
	return append(opts, storage.WithPassphraseHandler(
		func() ([]byte, error) { return pass, nil },
	))
}

// samePath reports whether a and b name the same existing file.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// replaceStore opens the storage at path and installs it in place of the
// current one, which is closed. bbolt locks a database file while it is
// open, so a second open of the open file would wait for the lock and
// fail. When path is the open file, the current store is therefore closed
// first, and opened again as it was if the new open fails.
func (d *Daemon) replaceStore(path string, unlock storageUnlock) error {
	d.mu.RLock()
	curPath := d.dbPath
	d.mu.RUnlock()
	d.storeMu.Lock()
	reopen := d.db != nil && samePath(curPath, path)
	curUnlock := d.dbUnlock
	d.storeMu.Unlock()

	if reopen {
		d.closeStore()
	}
	store, err := storage.OpenStorage(unlock.options(path)...)
	if err == nil {
		d.installStore(store, path, unlock)
		return nil
	}
	if !reopen {
		return err
	}
	prev, prevErr := storage.OpenStorage(curUnlock.options(curPath)...)
	if prevErr != nil {
		return fmt.Errorf(
			"%w; reopening the previous storage failed: %v", err, prevErr,
		)
	}
	d.installStore(prev, curPath, curUnlock)
	return err
}

func (d *Daemon) installStore(
	store *storage.Storage, path string, unlock storageUnlock,
) {
	d.storeMu.Lock()
	old := d.db
	d.db = store
	d.dbUnlock = unlock
	d.storeMu.Unlock()

	d.mu.Lock()
	d.dbPath = path
	d.pendingDBPath = ""
	d.mu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			slog.Warn("error closing replaced storage", slog.Any("error", err))
		}
	}
}

// openStorage opens storage at the given path and replaces the current
// store with it. When the new storage fails to open, the current store is
// kept; see replaceStore. A passphrase from KAMUNE_DB_PASSPHRASE is never
// saved to the keychain.
func (d *Daemon) openStorage(params OpenStorageParams) error {
	if d.storageBusy() {
		return errStorageBusy
	}

	unlock := storageUnlock{noPassphrase: params.DBNoPassphrase}
	if !params.DBNoPassphrase {
		d.mu.Lock()
		d.pendingDBPath = params.StoragePath
		d.mu.Unlock()

		pass := os.Getenv("KAMUNE_DB_PASSPHRASE")
		if pass == "" {
			return errPassphraseRequired
		}
		unlock.passphrase = []byte(pass)
	}

	return d.replaceStore(params.StoragePath, unlock)
}

// Run starts the daemon's main loop
func (d *Daemon) Run() {
	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		select {
		case <-sigCh:
			slog.Info("received shutdown signal")
			d.Shutdown()
		case <-d.ctx.Done():
		}
	}()

	// Emit ready event
	d.emit(EvtReady, "", MapS{
		"version": version, "pid": fmt.Sprintf("%d", os.Getpid()),
		"protocol_version": "1",
	})

	// Read commands from stdin using bufio.Reader so lines exceeding
	// maxScanTokenSize don't cause an unrecoverable scanner error that kills
	// the daemon.
	reader := bufio.NewReader(os.Stdin)

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			if !errors.Is(err, io.EOF) {
				slog.Error("stdin reader error", slog.Any("error", err))
			}
			break
		}

		if len(line) > maxScanTokenSize {
			d.emitError("", "line_too_long", "line exceeds maximum allowed length")
			continue
		}

		lineStr := strings.TrimRight(string(line), "\r\n")
		if lineStr == "" {
			continue
		}

		var cmd Command
		if err := json.Unmarshal([]byte(lineStr), &cmd); err != nil {
			d.emitError("", "invalid_json", fmt.Sprintf("invalid JSON: %v", err))
			continue
		}

		if cmd.Type != "cmd" {
			d.emitError(cmd.ID, "unknown_message_type", fmt.Sprintf("unknown message type: %s", cmd.Type))
			continue
		}

		d.handleCommand(cmd)
	}

	if d.ctx.Err() != nil {
		d.wg.Wait()
		return
	}

	// stdin closed without a shutdown command — clean up all resources.
	d.Shutdown()
}

// handleCommand processes a single command
func (d *Daemon) handleCommand(cmd Command) {
	switch cmd.CMD {
	case CmdOpenStorage:
		d.handleOpenStorage(cmd)
	case CmdSubmitPassphrase:
		d.handleSubmitPassphrase(cmd)
	case CmdStartServer:
		d.handleStartServer(cmd)
	case CmdStopServer:
		d.handleStopServer(cmd)
	case CmdRestartServer:
		d.handleRestartServer(cmd)
	case CmdCancelStartServer:
		d.handleCancelStartServer(cmd)
	case CmdGetServerStatus:
		d.handleGetServerStatus(cmd)
	case CmdGetStatus:
		d.handleGetStatus(cmd)
	case CmdDial:
		d.handleDial(cmd)
	case CmdSendMessage:
		d.handleSendMessage(cmd)
	case CmdListSessions:
		d.handleListSessions(cmd)
	case CmdCloseSession:
		d.handleCloseSession(cmd)
	case CmdRenameSession:
		d.handleRenameSession(cmd)
	case CmdGenerateRelayToken:
		d.handleGenerateRelayToken(cmd)
	case CmdRemoveRelayToken:
		d.handleRemoveRelayToken(cmd)
	case CmdListRelayTokens:
		d.handleListRelayTokens(cmd)
	case CmdGenerateP2PToken:
		d.handleGenerateP2PToken(cmd)
	case CmdRemoveP2PToken:
		d.handleRemoveP2PToken(cmd)
	case CmdListP2PTokens:
		d.handleListP2PTokens(cmd)
	case CmdGetShareInfo:
		d.handleGetShareInfo(cmd)
	case CmdVerifyResponse:
		d.handleVerifyResponse(cmd)
	case CmdSetVerificationMode:
		d.handleSetVerificationMode(cmd)
	case CmdGetVerificationMode:
		d.handleGetVerificationMode(cmd)
	case CmdGetHistorySessions:
		d.handleGetHistorySessions(cmd)
	case CmdGetHistoryMessages:
		d.handleGetHistoryMessages(cmd)
	case CmdLoadHistory:
		d.handleLoadHistory(cmd)
	case CmdRenameHistorySession:
		d.handleRenameHistorySession(cmd)
	case CmdDeleteHistorySession:
		d.handleDeleteHistorySession(cmd)
	case CmdRefreshHistory:
		d.handleRefreshHistory(cmd)
	case CmdListPeers:
		d.handleListPeers(cmd)
	case CmdDeletePeer:
		d.handleDeletePeer(cmd)
	case CmdGetFingerprint:
		d.handleGetFingerprint(cmd)
	case CmdGetMyName:
		d.handleGetMyName(cmd)
	case CmdSetMyName:
		d.handleSetMyName(cmd)
	case CmdGetVersion:
		d.handleGetVersion(cmd)
	case CmdGetLibraryVersion:
		d.handleGetLibraryVersion(cmd)
	case CmdGetIncognito:
		d.handleGetIncognito(cmd)
	case CmdSetIncognito:
		d.handleSetIncognito(cmd)
	case CmdAddPeer:
		d.handleAddPeer(cmd)
	case CmdRenamePeer:
		d.handleRenamePeer(cmd)
	case CmdGetPeer:
		d.handleGetPeer(cmd)
	case CmdGetSessionInfo:
		d.handleGetSessionInfo(cmd)
	case CmdGetLogs:
		d.handleGetLogs(cmd)
	case CmdClearLogs:
		d.handleClearLogs(cmd)
	case CmdExportLogs:
		d.handleExportLogs(cmd)
	case CmdGetLogLevel:
		d.handleGetLogLevel(cmd)
	case CmdSetLogLevel:
		d.handleSetLogLevel(cmd)
	case CmdHasKeychainPassphrase:
		d.handleHasKeychainPassphrase(cmd)
	case CmdClearKeychainPassphrase:
		d.handleClearKeychainPassphrase(cmd)
	case CmdGetFingerprintFormat:
		d.handleGetFingerprintFormat(cmd)
	case CmdSetFingerprintFormat:
		d.handleSetFingerprintFormat(cmd)
	case CmdShutdown:
		d.handleShutdown(cmd)
	default:
		d.emitError(cmd.ID, "unknown_command", fmt.Sprintf("unknown command: %s", cmd.CMD))
	}
}

// handleOpenStorage opens the single shared storage.
func (d *Daemon) handleOpenStorage(cmd Command) {
	var params OpenStorageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if params.StoragePath == "" {
		d.emitError(cmd.ID, "storage_path_required", "storage_path is required")
		return
	}
	if err := d.openStorage(params); err != nil {
		if errors.Is(err, errStorageBusy) {
			d.emitError(cmd.ID, "storage_busy", err.Error())
			return
		}
		d.emitError(cmd.ID, "storage_open_failed", fmt.Sprintf("failed to open storage: %v", err))
		return
	}

	d.loadIdentityAndHistory()

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "opened", "storage_path": params.StoragePath,
	})
}

// handleSubmitPassphrase re-opens storage with a new passphrase. Requires a
// prior open_storage call (so d.dbPath is set). The passphrase is saved to
// the system keychain only when the command asks for it. An empty
// passphrase is refused: an unencrypted database must be opened with
// open_storage and db_no_passphrase.
func (d *Daemon) handleSubmitPassphrase(cmd Command) {
	var params SubmitPassphraseParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if params.Passphrase == "" {
		d.emitError(cmd.ID, "passphrase_required", errEmptyPassphrase.Error())
		return
	}

	d.mu.RLock()
	dbPath := d.pendingDBPath
	if dbPath == "" {
		dbPath = d.dbPath
	}
	d.mu.RUnlock()

	if dbPath == "" {
		d.emitError(cmd.ID, "storage_not_opened", "storage not opened — call open_storage first")
		return
	}

	if d.storageBusy() {
		d.emitError(cmd.ID, "storage_busy", errStorageBusy.Error())
		return
	}

	err := d.replaceStore(
		dbPath, storageUnlock{passphrase: []byte(params.Passphrase)},
	)
	if err != nil {
		d.emitError(cmd.ID, "storage_open_failed", fmt.Sprintf("failed to open storage: %v", err))
		return
	}

	if params.SaveToKeychain {
		if err := keyring.Set(
			keychainService, keychainAccount(dbPath), params.Passphrase,
		); err != nil {
			d.addLogEntry("WARN", "Failed to store passphrase in keychain: "+err.Error())
		}
	}

	d.loadIdentityAndHistory()

	d.emit(EvtResponse, cmd.ID, MapS{"status": "opened"})
}

// Shutdown gracefully shuts down the daemon
func (d *Daemon) Shutdown() {
	d.handleShutdown(Command{})
}

func (d *Daemon) handleShutdown(cmd Command) {
	d.shutdownOnce.Do(func() { d.shutdown(cmd.ID) })
}

func (d *Daemon) shutdown(cmdID ID) {
	d.cancel()

	var sessions []*liveSession
	var server *kamune.Server
	var serverDone chan struct{}
	var startCancel context.CancelFunc

	d.mu.Lock()
	startCancel = d.startCancel
	server = d.server
	d.server = nil
	serverDone = d.serverDone
	d.serverDone = nil
	sessions = append(sessions, mapValues(d.sessions)...)
	d.sessions = make(map[string]*liveSession)
	d.mu.Unlock()

	if startCancel != nil {
		startCancel()
	}
	d.stopRelayResources()
	d.stopP2PResources()
	if server != nil {
		if err := server.Close(); err != nil {
			slog.Warn("error closing server", slog.Any("error", err))
		}
	}

	for _, session := range sessions {
		transport := session.stop()
		if transport != nil {
			if err := transport.Close(); err != nil {
				slog.Warn(
					"error closing session",
					slog.String("session_id", session.ID),
					slog.Any("error", err),
				)
			}
		}
	}

	if serverDone != nil {
		select {
		case <-serverDone:
		case <-time.After(channelTimeout):
			slog.Warn("Timeout waiting for ListenAndServe")
		}
	}

	d.wg.Wait()

	d.closeStore()

	d.emit(EvtResponse, cmdID, MapS{"status": "shutdown"})

	// Close stdin so the scanner loop in Run exits
	os.Stdin.Close()
}

// --- P2: Peer management ---

// handleAddPeer adds a known peer to storage (mirrors cmd/bus/peers.go:67-101).
func (d *Daemon) handleAddPeer(cmd Command) {
	var params AddPeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, "invalid_peer_key", err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage_unavailable", "storage is not available")
		return
	}

	if _, err := store.FindPeer(pub); err == nil {
		d.emitError(cmd.ID, "peer_already_exists", fmt.Sprintf("peer already exists: %s", params.PublicKey))
		return
	}

	name := params.Name
	if name == "" {
		name = fingerprint.Pseudonym(pub)
	}

	now := time.Now()
	if err := store.StorePeer(&storage.Peer{
		Name:       name,
		PublicKey:  pub,
		FirstSeen:  now,
		LastSeen:   now,
		AppVersion: "",
	}); err != nil {
		d.emitError(cmd.ID, "peer_store_failed", fmt.Sprintf("store peer: %v", err))
		return
	}

	d.addLogEntry("INFO", "Added peer: "+name)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "added", "name": name})
}

// handleRenamePeer changes the display name of a known peer (mirrors
// cmd/bus/peers.go:129-158).
func (d *Daemon) handleRenamePeer(cmd Command) {
	var params RenamePeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, "invalid_peer_key", err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage_unavailable", "storage is not available")
		return
	}

	existing, err := store.FindPeer(pub)
	if err != nil {
		d.emitError(cmd.ID, "peer_not_found", fmt.Sprintf("peer not found: %s", params.PublicKey))
		return
	}

	name := params.Name
	if name == "" {
		name = fingerprint.Pseudonym(pub)
	}
	existing.Name = name
	if err := store.StorePeer(existing); err != nil {
		d.emitError(cmd.ID, "peer_store_failed", fmt.Sprintf("store peer: %v", err))
		return
	}

	d.addLogEntry("INFO", "Renamed peer to "+name)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "renamed", "name": name})
}

// handleGetPeer returns a single known peer by base64 public key (mirrors
// cmd/bus/peers.go:46-60).
func (d *Daemon) handleGetPeer(cmd Command) {
	var params GetPeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, "invalid_peer_key", err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage_unavailable", "storage is not available")
		return
	}

	p, err := store.FindPeer(pub)
	if err != nil {
		d.emitError(cmd.ID, "peer_not_found", fmt.Sprintf("peer not found: %s", params.PublicKey))
		return
	}

	d.emit(EvtResponse, cmd.ID, MapA{
		"name":        p.Name,
		"public_key":  fingerprint.Base64(p.PublicKey),
		"first_seen":  p.FirstSeen,
		"last_seen":   p.LastSeen,
		"app_version": p.AppVersion,
	})
}

// --- P2: Get single session info ---

// handleGetSessionInfo returns info for a single live or history session
// (mirrors cmd/bus/app.go:1237-1271).
func (d *Daemon) handleGetSessionInfo(cmd Command) {
	var params GetSessionInfoParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	var live *liveSession
	for _, s := range d.sessions {
		if s.ID == params.SessionID {
			live = s
			break
		}
	}
	var hist *historySession
	if live == nil {
		for _, hs := range d.histSessions {
			if hs.ID == params.SessionID {
				hist = hs
				break
			}
		}
	}
	d.mu.RUnlock()

	if live != nil {
		payload, err := json.Marshal(d.sessionInfo(live))
		if err != nil {
			d.emitError(cmd.ID, "marshal_failed", err.Error())
			return
		}
		var data MapA
		if err := json.Unmarshal(payload, &data); err != nil {
			d.emitError(cmd.ID, "marshal_failed", err.Error())
			return
		}
		data["type"] = "live"
		d.emit(EvtResponse, cmd.ID, data)
		return
	}

	if hist != nil {
		d.emit(EvtResponse, cmd.ID, MapA{
			"type":          "history",
			"session_id":    hist.ID,
			"name":          hist.Name,
			"msg_count":     hist.MessageCount,
			"first_message": hist.FirstMessage,
			"last_message":  hist.LastMessage,
			"loaded":        hist.Loaded,
		})
		return
	}

	d.emitError(cmd.ID, "session_not_found", fmt.Sprintf("session not found: %s", params.SessionID))
}

// --- P3: Log management ---

// handleGetLogs returns buffered log entries (mirrors cmd/bus/app.go:1030-1036).
func (d *Daemon) handleGetLogs(cmd Command) {
	d.logMu.RLock()
	entries := make([]LogEntryInfo, len(d.logEntries))
	copy(entries, d.logEntries)
	d.logMu.RUnlock()

	d.emit(EvtResponse, cmd.ID, MapA{"entries": entries})
}

// handleClearLogs clears the in-memory log buffer (mirrors cmd/bus/app.go:1038-1042).
func (d *Daemon) handleClearLogs(cmd Command) {
	d.logMu.Lock()
	d.logEntries = d.logEntries[:0]
	d.logMu.Unlock()

	d.emit(EvtResponse, cmd.ID, MapS{"status": "cleared"})
}

// handleExportLogs writes buffered log entries to a file (mirrors
// cmd/bus/app.go:1044-1082).
func (d *Daemon) handleExportLogs(cmd Command) {
	var params ExportLogsParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.logMu.RLock()
	entries := make([]LogEntryInfo, len(d.logEntries))
	copy(entries, d.logEntries)
	d.logMu.RUnlock()

	filePath := params.FilePath
	if filePath == "" {
		filePath = fmt.Sprintf("kamune-logs-%s.txt", time.Now().Format("2006-01-02_150405"))
	}

	f, err := os.Create(filePath)
	if err != nil {
		d.emitError(cmd.ID, "export_file_failed", fmt.Sprintf("create file: %v", err))
		return
	}
	defer f.Close()

	for _, e := range entries {
		if _, err := fmt.Fprintf(f, "%s [%s] %s\n",
			e.Timestamp.Format(time.RFC3339), e.Level, e.Message,
		); err != nil {
			d.emitError(cmd.ID, "export_write_failed", fmt.Sprintf("write file: %v", err))
			return
		}
	}

	d.addLogEntry("INFO", "Exported logs to "+filePath)
	d.emit(EvtResponse, cmd.ID, MapA{"status": "exported", "file_path": filePath})
}

// handleGetLogLevel returns the current log level (mirrors cmd/bus/app.go:1084-1087).
func (d *Daemon) handleGetLogLevel(cmd Command) {
	d.mu.RLock()
	level := d.logLevel
	d.mu.RUnlock()

	d.emit(EvtResponse, cmd.ID, MapS{"level": level})
}

// handleSetLogLevel sets the minimum log level (mirrors cmd/bus/app.go:1090-1097).
// Persisted to storage when available.
func (d *Daemon) handleSetLogLevel(cmd Command) {
	var params SetLogLevelParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	level := strings.ToUpper(params.Level)
	if !applySlogLevel(level) {
		d.emitError(cmd.ID, "invalid_log_level", fmt.Sprintf("invalid level: %s", params.Level))
		return
	}

	d.mu.Lock()
	d.logLevel = level
	d.mu.Unlock()

	if store := d.store(); store != nil {
		_ = store.SetSettings("daemon", "log_level", level)
	}

	d.addLogEntry("INFO", "Log level set to: "+level)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "set", "level": level})
}

// --- P3: Keychain ---

// handleHasKeychainPassphrase checks if a passphrase is stored in the system
// keychain (mirrors cmd/bus/app.go:880-886).
func (d *Daemon) handleHasKeychainPassphrase(cmd Command) {
	d.mu.RLock()
	path := d.dbPath
	d.mu.RUnlock()

	_, err := keychainGet(path)
	d.emit(EvtResponse, cmd.ID, MapA{"has_passphrase": err == nil})
}

// handleClearKeychainPassphrase removes the stored passphrase from the system
// keychain (mirrors cmd/bus/app.go:888-897).
func (d *Daemon) handleClearKeychainPassphrase(cmd Command) {
	d.mu.RLock()
	path := d.dbPath
	d.mu.RUnlock()

	if err := keychainDelete(path); err != nil {
		d.emitError(cmd.ID, "keychain_clear_failed", fmt.Sprintf("failed to clear keychain: %v", err))
		return
	}

	d.addLogEntry("INFO", "Passphrase cleared from keychain")
	d.emit(EvtResponse, cmd.ID, MapS{"status": "cleared"})
}

// --- P3: Fingerprint format ---

// handleGetFingerprintFormat returns the current fingerprint display format
// (mirrors cmd/bus/app.go:832-836).
func (d *Daemon) handleGetFingerprintFormat(cmd Command) {
	d.mu.RLock()
	fmt := d.fingerprintFmt
	d.mu.RUnlock()

	d.emit(EvtResponse, cmd.ID, MapS{"format": fmt})
}

// handleSetFingerprintFormat sets the fingerprint display format
// (mirrors cmd/bus/app.go:838-844).
func (d *Daemon) handleSetFingerprintFormat(cmd Command) {
	var params SetFingerprintFormatParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	if !validFingerprintFormat(params.Format) {
		d.emitError(
			cmd.ID,
			"invalid_fingerprint_format",
			fmt.Sprintf("invalid format: %s", params.Format),
		)
		return
	}

	d.mu.Lock()
	d.fingerprintFmt = params.Format
	d.mu.Unlock()

	if store := d.store(); store != nil {
		_ = store.SetSettings("daemon", "fingerprint_format", params.Format)
	}

	d.addLogEntry("DEBUG", "Fingerprint format set to: "+params.Format)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "set", "format": params.Format})
}
