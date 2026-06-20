// Package main implements a daemon wrapper for the kamune library.
// It exposes a JSON-over-stdio protocol for integration with external
// applications.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/kamune-org/kamune"
)

const (
	version          = "1.0.0"
	maxScanTokenSize = 1024 * 1024 // 1MB
)

type (
	MapA = map[string]any
	MapS = map[string]string
)

// ID is the correlation id
type ID string

// CMD represents commands
type CMD string

// Command types
const (
	CmdOpenStorage     CMD = "open_storage"
	CmdSubmitPassphrase CMD = "submit_passphrase"
	CmdStartServer     CMD = "start_server"
	CmdDial            CMD = "dial"
	CmdSendMessage     CMD = "send_message"
	CmdListSessions    CMD = "list_sessions"
	CmdCloseSession    CMD = "close_session"
	CmdShutdown        CMD = "shutdown"
)

// Evt represents events
type Evt string

// Event types
const (
	EvtReady           Evt = "ready"
	EvtServerStarted   Evt = "server_started"
	EvtSessionStarted  Evt = "session_started"
	EvtSessionClosed   Evt = "session_closed"
	EvtMessageReceived Evt = "message_received"
	EvtMessageSent     Evt = "message_sent"
	EvtError           Evt = "error"
	EvtResponse        Evt = "response"
)

// Command represents an incoming command from stdin
type Command struct {
	Type   string          `json:"type"` // Always "cmd"
	CMD    CMD             `json:"cmd"`
	ID     ID              `json:"id"`
	Params json.RawMessage `json:"params"`
}

// Event represents an outgoing event to stdout
type Event struct {
	Data any    `json:"data"`
	Type string `json:"type"`
	Evt  Evt    `json:"evt"`
	ID   ID     `json:"id,omitempty"`
}

// SessionInfo contains information about a session
type SessionInfo struct {
	SessionID  string `json:"session_id"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	CreatedAt  string `json:"created_at"`
	IsServer   bool   `json:"is_server"`
}

// MessageInfo is a single chat message in a session's history.
type MessageInfo struct {
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	IsLocal   bool      `json:"is_local"`
}

// liveSession wraps a kamune.Transport with metadata. Mirrors bus.liveSession
// (cmd/bus/app.go:126-138). Extra fields are added now so later phases don't
// need to touch this struct again.
type liveSession struct {
	ID               string
	PeerName         string
	RemoteVersion    string
	RemoteAddr       string
	Transport        *kamune.Transport
	Messages         []MessageInfo
	LastActivity     time.Time
	ReceiveDone      chan struct{}
	cancelFunc       context.CancelFunc
	IsServer         bool
	TransportType    string
	SessionTTL       time.Duration
	SessionStartedAt time.Time
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
