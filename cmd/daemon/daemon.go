package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Daemon manages the kamune server and client connections
type Daemon struct {
	ctx      context.Context
	cancel   context.CancelFunc

	mu            sync.RWMutex
	sessions      map[string]*liveSession
	server        *kamune.Server
	serverRunning bool
	pubKey        []byte
	myName        string
	dbPath        string

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
		sessions: make(map[string]*liveSession),
		output:   json.NewEncoder(os.Stdout),
		ctx:      ctx,
		cancel:   cancel,
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

// markRelayTokenConsumed is a stub; the full implementation (updating
// relayTokens, scheduling removal, emitting relay_tokens) lands in Phase 4.
func (d *Daemon) markRelayTokenConsumed(token string) {
	slog.Debug("relay token consumed", slog.String("token", token))
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
	case CmdDial:
		d.handleDial(cmd)
	case CmdSendMessage:
		d.handleSendMessage(cmd)
	case CmdListSessions:
		d.handleListSessions(cmd)
	case CmdCloseSession:
		d.handleCloseSession(cmd)
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

	d.emit(EvtResponse, cmd.ID, MapS{"status": "opened"})
}

// handleStartServer starts a kamune server
func (d *Daemon) handleStartServer(cmd Command) {
	var params StartServerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.mu.Lock()
	if d.serverRunning {
		d.mu.Unlock()
		d.emitError(cmd.ID, "server already running")
		return
	}
	d.serverRunning = true
	d.mu.Unlock()

	srv, err := kamune.NewServer(params.Addr, d.serverHandler, d.store())
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to create server: %v", err))
		d.mu.Lock()
		d.serverRunning = false
		d.mu.Unlock()
		return
	}

	d.mu.Lock()
	d.server = srv
	d.mu.Unlock()

	d.wg.Go(func() {
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(cmd.ID, fmt.Sprintf("goroutine panic: %v", msg))
			}
		}()

		pubkey := srv.PublicKey()
		d.emit(EvtServerStarted, cmd.ID, MapA{
			"addr":       params.Addr,
			"public_key": fingerprint.Base64(pubkey),
			"emoji":      fingerprint.Emoji(pubkey),
		})

		if err := srv.ListenAndServe(); err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("listen and serve error: %v", err))
		}

		d.mu.Lock()
		d.serverRunning = false
		d.server = nil
		d.mu.Unlock()
	})
}

// serverHandler handles incoming server connections
func (d *Daemon) serverHandler(t *kamune.Transport) error {
	sessionID := t.SessionID()
	ctx, cancel := context.WithCancel(d.ctx)

	session := &liveSession{
		ID:               sessionID,
		Transport:        t,
		IsServer:         true,
		SessionStartedAt: time.Now(),
		cancelFunc:       cancel,
		ReceiveDone:      make(chan struct{}),
	}

	d.mu.Lock()
	d.sessions[sessionID] = session
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.sessions, sessionID)
		d.mu.Unlock()
		d.emit(EvtSessionClosed, "", MapS{"session_id": sessionID})
	}()

	d.emit(EvtSessionStarted, "", MapA{
		"session_id": sessionID, "is_server": true,
	})

	// Start receiving messages
	d.receiveLoop(ctx, sessionID, t)

	return nil
}

// handleDial dials a remote kamune server
func (d *Daemon) handleDial(cmd Command) {
	var params DialParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.wg.Go(func() {
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(cmd.ID, fmt.Sprintf("goroutine panic: %v", msg))
			}
		}()

		dialer, err := kamune.NewDialer(params.Addr, d.store())
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("failed to create dialer: %v", err))
			return
		}

		t, err := dialer.Dial()
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("failed to dial: %v", err))
			return
		}

		// If shutdown was requested during dial, close and bail out.
		if d.ctx.Err() != nil {
			t.Close()
			return
		}

		sessionID := t.SessionID()
		ctx, cancel := context.WithCancel(d.ctx)

		session := &liveSession{
			ID:               sessionID,
			Transport:        t,
			IsServer:         false,
			RemoteAddr:       params.Addr,
			SessionStartedAt: time.Now(),
			cancelFunc:       cancel,
			ReceiveDone:      make(chan struct{}),
		}

		d.mu.Lock()
		d.sessions[sessionID] = session
		d.mu.Unlock()

		defer func() {
			d.mu.Lock()
			delete(d.sessions, sessionID)
			d.mu.Unlock()
			d.emit(EvtSessionClosed, "", MapS{"session_id": sessionID})
		}()

		d.emit(EvtSessionStarted, cmd.ID, MapA{
			"session_id":  sessionID,
			"is_server":   false,
			"remote_addr": params.Addr,
			"public_key":  fingerprint.Base64(dialer.PublicKey()),
		})

		// Start receiving messages
		d.receiveLoop(ctx, sessionID, t)
	})
}

// receiveLoop continuously receives messages from a transport
func (d *Daemon) receiveLoop(
	ctx context.Context, sessionID string, t *kamune.Transport,
) {
	b := kamune.Bytes(nil)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		metadata, err := t.Receive(b)
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected):
				return
			case errors.Is(err, kamune.ErrConnClosed):
				return
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				d.emitError(
					"", fmt.Sprintf("receive error on session %s: %v", sessionID, err),
				)
				return
			}
		}

		if metadata.Route() == kamune.RoutePing {
			if err := t.Pong(b.GetValue()); err != nil {
				slog.Warn("failed to send pong",
					slog.String("session_id", sessionID),
					slog.Any("error", err),
				)
			}
			continue
		}

		d.emit(EvtMessageReceived, "", MapA{
			"session_id":  sessionID,
			"data_base64": base64.StdEncoding.EncodeToString(b.GetValue()),
			"timestamp":   metadata.Timestamp().Format(time.RFC3339Nano),
		})
	}
}

// handleSendMessage sends a message on an existing session
func (d *Daemon) handleSendMessage(cmd Command) {
	var params SendMessageParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	session, ok := d.sessions[params.SessionID]
	d.mu.RUnlock()

	if !ok {
		d.emitError(
			cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}

	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid base64 data: %v", err))
		return
	}

	metadata, err := session.Transport.Send(
		kamune.Bytes(data), kamune.RouteExchangeMessages,
	)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to send message: %v", err))
		return
	}

	d.emit(EvtMessageSent, cmd.ID, MapA{
		"session_id": params.SessionID,
		"timestamp":  metadata.Timestamp().Format(time.RFC3339Nano),
	})
}

// handleListSessions returns a list of active sessions
func (d *Daemon) handleListSessions(cmd Command) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sessions := make([]SessionInfo, 0, len(d.sessions))
	for id, s := range d.sessions {
		sessions = append(sessions, SessionInfo{
			SessionID:  id,
			RemoteAddr: s.RemoteAddr,
			IsServer:   s.IsServer,
			CreatedAt:  s.SessionStartedAt.Format(time.RFC3339),
		})
	}

	d.emit(EvtResponse, cmd.ID, MapA{"sessions": sessions})
}

// handleCloseSession closes a specific session
func (d *Daemon) handleCloseSession(cmd Command) {
	var params CloseSessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	session, ok := d.sessions[params.SessionID]
	if !ok {
		d.mu.Unlock()
		d.emitError(
			cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}
	delete(d.sessions, params.SessionID)
	d.mu.Unlock()

	session.cancelFunc()
	if err := session.Transport.Close(); err != nil {
		slog.Warn("error closing transport", slog.Any("error", err))
	}

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "closed", "session_id": params.SessionID,
	})
}

// Shutdown gracefully shuts down the daemon
func (d *Daemon) Shutdown() {
	d.cancel()

	d.mu.Lock()

	// Close server listener first so ListenAndServe returns
	if d.server != nil {
		if err := d.server.Close(); err != nil {
			slog.Warn("error closing server", slog.Any("error", err))
		}
		d.server = nil
	}

	// Close all sessions
	for id, session := range d.sessions {
		session.cancelFunc()
		if err := session.Transport.Close(); err != nil {
			slog.Warn(
				"error closing session",
				slog.String("session_id", id),
				slog.Any("error", err),
			)
		}
	}
	d.sessions = make(map[string]*liveSession)
	d.mu.Unlock()

	// Wait for all goroutines to finish before emitting the response
	d.wg.Wait()

	d.closeStore()

	d.emit(EvtResponse, "", MapS{"status": "shutdown"})

	// Close stdin so the scanner loop in Run exits
	os.Stdin.Close()
}
