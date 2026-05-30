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
	"syscall"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Daemon manages the kamune server and client connections
type Daemon struct {
	ctx           context.Context
	sessions      map[string]*Session
	server        *kamune.Server
	output        *json.Encoder
	cancel        context.CancelFunc
	mu            sync.RWMutex
	outputMu      sync.Mutex
	serverRunning bool
	wg            sync.WaitGroup
	stores        map[string]*storage.Storage
}

// NewDaemon creates a new daemon instance
func NewDaemon() *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		sessions: make(map[string]*Session),
		output:   json.NewEncoder(os.Stdout),
		stores:   make(map[string]*storage.Storage),
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

// openDaemonStorage opens or reuses a cached storage for the given path and
// no-passphrase flag.
func (d *Daemon) openDaemonStorage(
	storagePath string, noPassphrase bool,
) (*storage.Storage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := storagePath
	if noPassphrase {
		key += "?nopp"
	}
	if store, ok := d.stores[key]; ok {
		return store, nil
	}

	var opts []storage.StorageOption
	if storagePath != "" {
		opts = append(opts, storage.WithDBPath(storagePath))
	}
	if noPassphrase {
		opts = append(opts, storage.WithNoPassphrase())
	}
	store, err := storage.OpenStorage(opts...)
	if err != nil {
		return nil, err
	}
	d.stores[key] = store
	return store, nil
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

	if err := scanner.Err(); err != nil {
		slog.Error("stdin scanner error", slog.Any("error", err))
	}
}

// handleCommand processes a single command
func (d *Daemon) handleCommand(cmd Command) {
	switch cmd.CMD {
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

// handleStartServer starts a kamune server
func (d *Daemon) handleStartServer(cmd Command) {
	var params StartServerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
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

	store, err := d.openDaemonStorage(params.StoragePath, params.DBNoPassphrase)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to open storage: %v", err))
		d.mu.Lock()
		d.serverRunning = false
		d.mu.Unlock()
		return
	}

	d.wg.Go(func() {
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(cmd.ID, fmt.Sprintf("goroutine panic: %v", msg))
				d.mu.Lock()
				d.serverRunning = false
				d.server = nil
				d.mu.Unlock()
			}
		}()

		srv, err := kamune.NewServer(params.Addr, d.serverHandler, store)
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

	session := &Session{
		Transport:  t,
		IsServer:   true,
		CreatedAt:  time.Now(),
		cancelFunc: cancel,
	}

	d.mu.Lock()
	d.sessions[sessionID] = session
	d.mu.Unlock()

	d.emit(EvtSessionStarted, "", MapA{
		"session_id": sessionID, "is_server": true,
	})

	// Start receiving messages
	d.receiveLoop(ctx, sessionID, t)

	// Clean up
	d.mu.Lock()
	delete(d.sessions, sessionID)
	d.mu.Unlock()

	d.emit(EvtSessionClosed, "", MapS{"session_id": sessionID})

	return nil
}

// handleDial dials a remote kamune server
func (d *Daemon) handleDial(cmd Command) {
	var params DialParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	store, err := d.openDaemonStorage(params.StoragePath, params.DBNoPassphrase)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to open storage: %v", err))
		return
	}

	d.wg.Go(func() {
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(cmd.ID, fmt.Sprintf("goroutine panic: %v", msg))
			}
		}()

		dialer, err := kamune.NewDialer(params.Addr, store)
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("failed to create dialer: %v", err))
			return
		}

		t, err := dialer.Dial()
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("failed to dial: %v", err))
			return
		}

		sessionID := t.SessionID()
		ctx, cancel := context.WithCancel(d.ctx)

		session := &Session{
			Transport:  t,
			IsServer:   false,
			RemoteAddr: params.Addr,
			CreatedAt:  time.Now(),
			cancelFunc: cancel,
		}

		d.mu.Lock()
		d.sessions[sessionID] = session
		d.mu.Unlock()

		d.emit(EvtSessionStarted, cmd.ID, MapA{
			"session_id":  sessionID,
			"is_server":   false,
			"remote_addr": params.Addr,
			"public_key":  base64.StdEncoding.EncodeToString(dialer.PublicKey()),
		})

		// Start receiving messages
		d.receiveLoop(ctx, sessionID, t)

		// Clean up
		d.mu.Lock()
		delete(d.sessions, sessionID)
		d.mu.Unlock()

		d.emit(EvtSessionClosed, cmd.ID, MapS{"session_id": sessionID})
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
			if errors.Is(err, kamune.ErrConnClosed) {
				return
			}
			d.emitError(
				"", fmt.Sprintf("receive error on session %s: %v", sessionID, err),
			)
			return
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
			CreatedAt:  s.CreatedAt.Format(time.RFC3339),
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
	d.sessions = make(map[string]*Session)
	d.mu.Unlock()

	// Wait for all goroutines to finish before emitting the response
	d.wg.Wait()

	// Close all cached storage instances
	for path, store := range d.stores {
		if err := store.Close(); err != nil {
			slog.Warn("error closing storage", slog.String("path", path), slog.Any("error", err))
		}
	}
	d.stores = nil

	d.emit(EvtResponse, "", MapS{"status": "shutdown"})

	// Close stdin so the scanner loop in Run exits
	os.Stdin.Close()
}
