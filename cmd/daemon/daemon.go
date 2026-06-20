package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Daemon manages the kamune server and client connections
type Daemon struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.RWMutex
	sessions      map[string]*liveSession
	server        *kamune.Server
	serverDone    chan struct{}
	serverRunning bool
	pubKey        []byte
	myName        string
	dbPath        string
	verifMode     VerificationMode

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

	startCtx    context.Context
	startCancel context.CancelFunc

	status    ConnectionStatus
	statusMsg string

	output   *json.Encoder
	outputMu sync.Mutex

	storeMu sync.Mutex
	db      *storage.Storage

	passphrase atomic.Value

	wg sync.WaitGroup
}

// NewDaemon creates a new daemon instance
func NewDaemon() *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		sessions:      make(map[string]*liveSession),
		output:        json.NewEncoder(os.Stdout),
		ctx:           ctx,
		cancel:        cancel,
		verifMode:     VerificationModeQuick,
		status:        StatusDisconnected,
		statusMsg:     "Not connected",
		verifRequests: make(map[int64]*pendingVerification),
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

// addLogEntry logs a message at the given level. The daemon has no in-app log
// buffer or Wails event surface, so this is a thin slog wrapper.
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
	case CmdGetShareInfo:
		d.handleGetShareInfo(cmd)
	case CmdVerifyResponse:
		d.handleVerifyResponse(cmd)
	case CmdSetVerificationMode:
		d.handleSetVerificationMode(cmd)
	case CmdGetVerificationMode:
		d.handleGetVerificationMode(cmd)
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

	d.loadPersistedSettings()

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "opened", "storage_path": params.StoragePath,
	})
}

// loadPersistedSettings reads daemon settings from the store and applies them.
// Called after open_storage / submit_passphrase.
func (d *Daemon) loadPersistedSettings() {
	store := d.store()
	if store == nil {
		return
	}
	if modeStr, err := store.GetSettings("daemon", "verification_mode"); err == nil && modeStr != "" {
		if mode, err := strconv.Atoi(modeStr); err == nil {
			d.mu.Lock()
			d.verifMode = VerificationMode(mode)
			d.mu.Unlock()
		}
	}
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

	d.loadPersistedSettings()

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
