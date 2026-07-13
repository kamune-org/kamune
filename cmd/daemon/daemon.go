package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
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

func keychainAccount(dbPath string) string {
	if dbPath == "" {
		return "default"
	}
	return filepath.Base(dbPath)
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
	verifMode     VerificationMode
	incognito     bool

	verifMu        sync.Mutex
	verifRequests  map[int64]*pendingVerification
	verifIDCounter atomic.Int64

	serverAddr      string
	serverTransport string
	serverRelayAddr string
	serverName      string
	serverPassword  string

	relayAddr       string
	relayPassword   string
	relaySessionTTL time.Duration
	relayTokens     []relayToken
	relayListeners  *multiListener

	p2pTokens     []p2pToken
	p2pListener   *p2pListener
	brokerClient  *BrokerClient

	startCtx    context.Context
	startCancel context.CancelFunc

	status    ConnectionStatus
	statusMsg string

	output   *json.Encoder
	outputMu sync.Mutex

	storeMu sync.Mutex
	db      *storage.Storage

	passphrase atomic.Value

	logEntries    []LogEntryInfo
	logMu         sync.RWMutex
	logBufferSize int
	logLevel      string

	fingerprintFmt string

	wg sync.WaitGroup
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
func (d *Daemon) emitError(correlationID ID, errMsg string) {
	d.emit(EvtError, correlationID, MapS{"error": errMsg})
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

// store returns the single shared storage instance, or nil if not open.
func (d *Daemon) store() *storage.Storage {
	d.storeMu.Lock()
	defer d.storeMu.Unlock()
	return d.db
}

// closeStore closes the shared storage if open. Safe to call multiple times.
func (d *Daemon) closeStore() {
	d.storeMu.Lock()
	defer d.storeMu.Unlock()
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			slog.Warn("error closing storage", slog.Any("error", err))
		}
		d.db = nil
	}
}

// requireStorage emits a "not opened" error and returns false if storage is
// not open. Callers should `return` immediately when this returns false.
func (d *Daemon) requireStorage(cmdID ID) bool {
	if d.store() == nil {
		d.emitError(cmdID, "storage not opened — call open_storage first")
		return false
	}
	return true
}

// openStorage closes any existing storage and opens a new one at the given
// path with the given passphrase mode. For passphrase mode, the passphrase
// is read from KAMUNE_DB_PASSPHRASE.
func (d *Daemon) openStorage(params OpenStorageParams) error {
	d.closeStore()

	var opts []storage.StorageOption
	if params.StoragePath != "" {
		opts = append(opts, storage.WithDBPath(params.StoragePath))
	}

	if params.DBNoPassphrase {
		opts = append(opts, storage.WithNoPassphrase())
	} else {
		pass := os.Getenv("KAMUNE_DB_PASSPHRASE")
		if pass == "" {
			return fmt.Errorf(
				"KAMUNE_DB_PASSPHRASE not set and db_no_passphrase is false; " +
					"use submit_passphrase to provide one",
			)
		}
		d.passphrase.Store([]byte(pass))
		opts = append(opts, storage.WithPassphraseHandler(func() ([]byte, error) {
			p, _ := d.passphrase.Load().([]byte)
			return p, nil
		}))
	}

	store, err := storage.OpenStorage(opts...)
	if err != nil {
		return err
	}

	d.storeMu.Lock()
	d.db = store
	d.storeMu.Unlock()

	d.mu.Lock()
	d.dbPath = params.StoragePath
	d.mu.Unlock()

	return nil
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
	})

	// Read commands from stdin
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for larger messages
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		var cmd Command
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			d.emitError("", fmt.Sprintf("invalid JSON: %v", err))
			continue
		}

		if cmd.Type != "cmd" {
			d.emitError(cmd.ID, fmt.Sprintf("unknown message type: %s", cmd.Type))
			continue
		}

		d.handleCommand(cmd)
	}

	if d.ctx.Err() != nil {
		d.wg.Wait()
		return
	}

	// stdin closed without a shutdown command — clean up
	d.closeStore()

	if err := scanner.Err(); err != nil {
		slog.Error("stdin scanner error", slog.Any("error", err))
	}
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
		d.Shutdown()
	default:
		d.emitError(cmd.ID, fmt.Sprintf("unknown command: %s", cmd.CMD))
	}
}

// handleOpenStorage opens the single shared storage.
func (d *Daemon) handleOpenStorage(cmd Command) {
	var params OpenStorageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}
	if params.StoragePath == "" {
		d.emitError(cmd.ID, "storage_path is required")
		return
	}
	if err := d.openStorage(params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to open storage: %v", err))
		return
	}

	d.loadIdentityAndHistory()

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "opened", "storage_path": params.StoragePath,
	})
}

// handleSubmitPassphrase re-opens storage with a new passphrase. Requires a
// prior open_storage call (so d.dbPath is set).
func (d *Daemon) handleSubmitPassphrase(cmd Command) {
	var params SubmitPassphraseParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	dbPath := d.dbPath
	d.mu.RUnlock()

	if dbPath == "" {
		d.emitError(cmd.ID, "storage not opened — call open_storage first")
		return
	}

	d.closeStore()
	d.passphrase.Store([]byte(params.Passphrase))

	store, err := storage.OpenStorage(
		storage.WithDBPath(dbPath),
		storage.WithPassphraseHandler(func() ([]byte, error) {
			p, _ := d.passphrase.Load().([]byte)
			return p, nil
		}),
	)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to open storage: %v", err))
		return
	}

	d.storeMu.Lock()
	d.db = store
	d.storeMu.Unlock()

	d.loadIdentityAndHistory()

	d.emit(EvtResponse, cmd.ID, MapS{"status": "opened"})
}

// Shutdown gracefully shuts down the daemon
func (d *Daemon) Shutdown() {
	d.cancel()

	d.mu.Lock()

	// Close relay listeners
	if d.relayListeners != nil {
		d.relayListeners.Close()
		d.relayListeners = nil
	}

	// Close server listener first so ListenAndServe returns
	if d.server != nil {
		if err := d.server.Close(); err != nil {
			slog.Warn("error closing server", slog.Any("error", err))
		}
		d.server = nil
	}

	// Close all sessions
	for id, session := range d.sessions {
		if err := session.Transport.Close(); err != nil {
			slog.Warn(
				"error closing session",
				slog.String("session_id", id),
				slog.Any("error", err),
			)
		}
	}
	d.sessions = make(map[string]*liveSession)

	if d.serverDone != nil {
		done := d.serverDone
		d.serverDone = nil
		d.mu.Unlock()
		select {
		case <-done:
		case <-time.After(channelTimeout):
			slog.Warn("Timeout waiting for ListenAndServe")
		}
	} else {
		d.mu.Unlock()
	}

	d.wg.Wait()

	d.closeStore()

	d.emit(EvtResponse, "", MapS{"status": "shutdown"})

	// Close stdin so the scanner loop in Run exits
	os.Stdin.Close()
}

// --- P2: Peer management ---

// handleAddPeer adds a known peer to storage (mirrors cmd/bus/peers.go:67-101).
func (d *Daemon) handleAddPeer(cmd Command) {
	var params AddPeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	if _, err := store.FindPeer(pub); err == nil {
		d.emitError(cmd.ID, fmt.Sprintf("peer already exists: %s", params.PublicKey))
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
		d.emitError(cmd.ID, fmt.Sprintf("store peer: %v", err))
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
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	existing, err := store.FindPeer(pub)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("peer not found: %s", params.PublicKey))
		return
	}

	name := params.Name
	if name == "" {
		name = fingerprint.Pseudonym(pub)
	}
	existing.Name = name
	if err := store.StorePeer(existing); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("store peer: %v", err))
		return
	}

	d.addLogEntry("INFO", "Renamed peer to "+params.Name)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "renamed", "name": params.Name})
}

// handleGetPeer returns a single known peer by base64 public key (mirrors
// cmd/bus/peers.go:46-60).
func (d *Daemon) handleGetPeer(cmd Command) {
	var params GetPeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	pub, err := decodePeerPubKey(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, err.Error())
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	p, err := store.FindPeer(pub)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("peer not found: %s", params.PublicKey))
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
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, s := range d.sessions {
		if s.ID == params.SessionID {
			info := d.sessionInfoLocked(s)
			d.emit(EvtResponse, cmd.ID, MapA{
				"type":           "live",
				"session_id":     info.SessionID,
				"peer_name":      info.PeerName,
				"is_server":      info.IsServer,
				"msg_count":      info.MsgCount,
				"last_activity":  info.LastActivity,
				"transport_type": info.TransportType,
				"remote_version": info.RemoteVersion,
				"session_ttl_ns": info.SessionTTL,
				"started_at":     info.SessionStartedAt,
				"remote_addr":    info.RemoteAddr,
			})
			return
		}
	}

	for _, hs := range d.histSessions {
		if hs.ID == params.SessionID {
			d.emit(EvtResponse, cmd.ID, MapA{
				"type":          "history",
				"session_id":    hs.ID,
				"name":          hs.Name,
				"msg_count":     hs.MessageCount,
				"first_message": hs.FirstMessage,
				"last_message":  hs.LastMessage,
				"loaded":        hs.Loaded,
			})
			return
		}
	}

	d.emitError(cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID))
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
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
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
		d.emitError(cmd.ID, fmt.Sprintf("create file: %v", err))
		return
	}
	defer f.Close()

	for _, e := range entries {
		if _, err := fmt.Fprintf(f, "%s [%s] %s\n",
			e.Timestamp.Format(time.RFC3339), e.Level, e.Message,
		); err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("write file: %v", err))
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
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	d.logLevel = params.Level
	d.mu.Unlock()

	if store := d.store(); store != nil {
		_ = store.SetSettings("daemon", "log_level", params.Level)
	}

	d.addLogEntry("INFO", "Log level set to: "+params.Level)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "set", "level": params.Level})
}

// --- P3: Keychain ---

// handleHasKeychainPassphrase checks if a passphrase is stored in the system
// keychain (mirrors cmd/bus/app.go:880-886).
func (d *Daemon) handleHasKeychainPassphrase(cmd Command) {
	d.mu.RLock()
	path := d.dbPath
	d.mu.RUnlock()

	_, err := keyring.Get(keychainService, keychainAccount(path))
	d.emit(EvtResponse, cmd.ID, MapA{"has_passphrase": err == nil})
}

// handleClearKeychainPassphrase removes the stored passphrase from the system
// keychain (mirrors cmd/bus/app.go:888-897).
func (d *Daemon) handleClearKeychainPassphrase(cmd Command) {
	d.mu.RLock()
	path := d.dbPath
	d.mu.RUnlock()

	if err := keyring.Delete(keychainService, keychainAccount(path)); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to clear keychain: %v", err))
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
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	d.fingerprintFmt = params.Format
	d.mu.Unlock()

	d.addLogEntry("DEBUG", "Fingerprint format set to: "+params.Format)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "set", "format": params.Format})
}
