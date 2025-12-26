// Package main implements a daemon wrapper for the kamune library.
// It exposes a JSON-over-stdio protocol for integration with external applications.
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
)

// Command types
const (
	CmdStartServer  = "start_server"
	CmdDial         = "dial"
	CmdSendMessage  = "send_message"
	CmdListSessions = "list_sessions"
	CmdCloseSession = "close_session"
	CmdShutdown     = "shutdown"
)

// Event types
const (
	EvtReady           = "ready"
	EvtServerStarted   = "server_started"
	EvtSessionStarted  = "session_started"
	EvtSessionClosed   = "session_closed"
	EvtMessageReceived = "message_received"
	EvtMessageSent     = "message_sent"
	EvtError           = "error"
	EvtResponse        = "response"
)

// Command represents an incoming command from stdin
type Command struct {
	Type   string          `json:"type"` // Always "cmd"
	Cmd    string          `json:"cmd"`
	ID     string          `json:"id"`
	Params json.RawMessage `json:"params"`
}

// Event represents an outgoing event to stdout
type Event struct {
	Type string `json:"type"` // Always "evt"
	Evt  string `json:"evt"`
	ID   string `json:"id,omitempty"` // Correlation ID for responses
	Data any    `json:"data"`
}

// StartServerParams contains parameters for starting a server
type StartServerParams struct {
	Addr           string `json:"addr"`
	StoragePath    string `json:"storage_path"`
	DBNoPassphrase bool   `json:"db_no_passphrase"`
}

// DialParams contains parameters for dialing a remote server
type DialParams struct {
	Addr           string `json:"addr"`
	StoragePath    string `json:"storage_path"`
	DBNoPassphrase bool   `json:"db_no_passphrase"`
}

// SendMessageParams contains parameters for sending a message
type SendMessageParams struct {
	SessionID  string `json:"session_id"`
	DataBase64 string `json:"data_base64"`
}

// CloseSessionParams contains parameters for closing a session
type CloseSessionParams struct {
	SessionID string `json:"session_id"`
}

// SessionInfo contains information about a session
type SessionInfo struct {
	SessionID  string `json:"session_id"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	IsServer   bool   `json:"is_server"`
	CreatedAt  string `json:"created_at"`
}

// Daemon manages the kamune server and client connections
type Daemon struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
	server        *kamune.Server
	serverRunning bool
	output        *json.Encoder
	outputMu      sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// Session wraps a kamune.Transport with metadata
type Session struct {
	Transport  *kamune.Transport
	IsServer   bool
	RemoteAddr string
	CreatedAt  time.Time
	cancelFunc context.CancelFunc
}

// NewDaemon creates a new daemon instance
func NewDaemon() *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		sessions: make(map[string]*Session),
		output:   json.NewEncoder(os.Stdout),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// emit sends an event to stdout
func (d *Daemon) emit(evt string, correlationID string, data any) {
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
func (d *Daemon) emitError(correlationID string, errMsg string) {
	d.emit(EvtError, correlationID, map[string]string{"error": errMsg})
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
	d.emit(EvtReady, "", map[string]string{
		"version": "1.0.0",
		"pid":     fmt.Sprintf("%d", os.Getpid()),
	})

	// Read commands from stdin
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for larger messages
	const maxScanTokenSize = 1024 * 1024 // 1MB
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

	if err := scanner.Err(); err != nil {
		slog.Error("stdin scanner error", slog.Any("error", err))
	}
}

// handleCommand processes a single command
func (d *Daemon) handleCommand(cmd Command) {
	switch cmd.Cmd {
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
		d.emitError(cmd.ID, fmt.Sprintf("unknown command: %s", cmd.Cmd))
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

	go func() {
		var opts []kamune.StorageOption
		if params.StoragePath != "" {
			opts = append(opts, kamune.StorageWithDBPath(params.StoragePath))
		}
		if params.DBNoPassphrase {
			opts = append(opts, kamune.StorageWithNoPassphrase())
		}

		srv, err := kamune.NewServer(
			params.Addr,
			d.serverHandler,
			kamune.ServeWithStorageOpts(opts...),
		)
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

		d.emit(EvtServerStarted, cmd.ID, map[string]string{
			"addr":       params.Addr,
			"public_key": base64.StdEncoding.EncodeToString(srv.PublicKey().Marshal()),
		})

		if err := srv.ListenAndServe(); err != nil {
			d.emitError("", fmt.Sprintf("server error: %v", err))
		}

		d.mu.Lock()
		d.serverRunning = false
		d.server = nil
		d.mu.Unlock()
	}()
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

	d.emit(EvtSessionStarted, "", map[string]any{
		"session_id": sessionID,
		"is_server":  true,
	})

	// Start receiving messages
	d.receiveLoop(ctx, sessionID, t)

	// Clean up
	d.mu.Lock()
	delete(d.sessions, sessionID)
	d.mu.Unlock()

	d.emit(EvtSessionClosed, "", map[string]string{
		"session_id": sessionID,
	})

	return nil
}

// handleDial dials a remote kamune server
func (d *Daemon) handleDial(cmd Command) {
	var params DialParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	go func() {
		var opts []kamune.StorageOption
		if params.StoragePath != "" {
			opts = append(opts, kamune.StorageWithDBPath(params.StoragePath))
		}
		if params.DBNoPassphrase {
			opts = append(opts, kamune.StorageWithNoPassphrase())
		}

		dialer, err := kamune.NewDialer(
			params.Addr,
			kamune.DialWithStorageOpts(opts...),
		)
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

		d.emit(EvtSessionStarted, cmd.ID, map[string]any{
			"session_id":  sessionID,
			"is_server":   false,
			"remote_addr": params.Addr,
			"public_key":  base64.StdEncoding.EncodeToString(dialer.PublicKey().Marshal()),
		})

		// Start receiving messages
		d.receiveLoop(ctx, sessionID, t)

		// Clean up
		d.mu.Lock()
		delete(d.sessions, sessionID)
		d.mu.Unlock()

		d.emit(EvtSessionClosed, "", map[string]string{
			"session_id": sessionID,
		})
	}()
}

// receiveLoop continuously receives messages from a transport
func (d *Daemon) receiveLoop(ctx context.Context, sessionID string, t *kamune.Transport) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		b := kamune.Bytes(nil)
		metadata, err := t.Receive(b)
		if err != nil {
			if errors.Is(err, kamune.ErrConnClosed) {
				return
			}
			d.emitError("", fmt.Sprintf("receive error on session %s: %v", sessionID, err))
			return
		}

		d.emit(EvtMessageReceived, "", map[string]any{
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
		d.emitError(cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID))
		return
	}

	data, err := base64.StdEncoding.DecodeString(params.DataBase64)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid base64 data: %v", err))
		return
	}

	metadata, err := session.Transport.Send(kamune.Bytes(data), kamune.RouteExchangeMessages)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("failed to send message: %v", err))
		return
	}

	d.emit(EvtMessageSent, cmd.ID, map[string]any{
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

	d.emit(EvtResponse, cmd.ID, map[string]any{
		"sessions": sessions,
	})
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
		d.emitError(cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID))
		return
	}
	delete(d.sessions, params.SessionID)
	d.mu.Unlock()

	session.cancelFunc()
	if err := session.Transport.Close(); err != nil {
		slog.Warn("error closing transport", slog.Any("error", err))
	}

	d.emit(EvtResponse, cmd.ID, map[string]string{
		"status":     "closed",
		"session_id": params.SessionID,
	})
}

// Shutdown gracefully shuts down the daemon
func (d *Daemon) Shutdown() {
	d.cancel()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Close all sessions
	for id, session := range d.sessions {
		session.cancelFunc()
		if err := session.Transport.Close(); err != nil {
			slog.Warn("error closing session", slog.String("session_id", id), slog.Any("error", err))
		}
	}
	d.sessions = make(map[string]*Session)

	d.emit(EvtResponse, "", map[string]string{
		"status": "shutdown",
	})

	os.Exit(0)
}

func main() {
	// Configure logging to stderr to keep stdout clean for JSON protocol
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	daemon := NewDaemon()
	daemon.Run()
}
