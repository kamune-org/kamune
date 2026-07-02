// Package main implements a daemon wrapper for the kamune library.
// It exposes a JSON-over-stdio protocol for integration with external
// applications.
package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/kamune-org/kamune"
)

const (
	version          = "1.0.0"
	maxScanTokenSize = 1024 * 1024 // 1MB
	channelTimeout   = 5 * time.Second
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
	CmdOpenStorage          CMD = "open_storage"
	CmdSubmitPassphrase     CMD = "submit_passphrase"
	CmdStartServer          CMD = "start_server"
	CmdStopServer           CMD = "stop_server"
	CmdRestartServer        CMD = "restart_server"
	CmdCancelStartServer    CMD = "cancel_start_server"
	CmdGetServerStatus      CMD = "get_server_status"
	CmdGetStatus            CMD = "get_status"
	CmdDial                 CMD = "dial"
	CmdSendMessage          CMD = "send_message"
	CmdListSessions         CMD = "list_sessions"
	CmdCloseSession         CMD = "close_session"
	CmdRenameSession        CMD = "rename_session"
	CmdGenerateRelayToken   CMD = "generate_relay_token"
	CmdRemoveRelayToken     CMD = "remove_relay_token"
	CmdListRelayTokens      CMD = "list_relay_tokens"
	CmdGetShareInfo         CMD = "get_share_info"
	CmdVerifyResponse       CMD = "verify_response"
	CmdSetVerificationMode  CMD = "set_verification_mode"
	CmdGetVerificationMode  CMD = "get_verification_mode"
	CmdGetHistorySessions   CMD = "get_history_sessions"
	CmdGetHistoryMessages   CMD = "get_history_messages"
	CmdLoadHistory          CMD = "load_history"
	CmdRenameHistorySession CMD = "rename_history_session"
	CmdDeleteHistorySession CMD = "delete_history_session"
	CmdRefreshHistory       CMD = "refresh_history"
	CmdListPeers            CMD = "list_peers"
	CmdDeletePeer           CMD = "delete_peer"
	CmdGetFingerprint       CMD = "get_fingerprint"
	CmdGetMyName            CMD = "get_my_name"
	CmdSetMyName            CMD = "set_my_name"
	CmdGetVersion           CMD = "get_version"
	CmdGetLibraryVersion    CMD = "get_library_version"
	CmdGetIncognito         CMD = "get_incognito"
	CmdSetIncognito         CMD = "set_incognito"
	CmdShutdown             CMD = "shutdown"
)

// Evt represents events
type Evt string

// Event types
const (
	EvtReady             Evt = "ready"
	EvtServerStarted     Evt = "server_started"
	EvtServerStopped     Evt = "server_stopped"
	EvtServerRunning     Evt = "server_running"
	EvtServerStartCancel Evt = "server_start_cancelled"
	EvtSessionStarted    Evt = "session_started"
	EvtSessionClosed     Evt = "session_closed"
	EvtSessionUpdated    Evt = "session_updated"
	EvtMessageReceived   Evt = "message_received"
	EvtMessageSent       Evt = "message_sent"
	EvtStatusChanged     Evt = "status_changed"
	EvtFingerprintChange Evt = "fingerprint_changed"
	EvtVersionWarning    Evt = "version_warning"
	EvtRelayToken        Evt = "relay_token"
	EvtRelayTokens       Evt = "relay_tokens"
	EvtVerifyPeer        Evt = "verify_peer"
	EvtHistoryUpdated    Evt = "history_updated"
	EvtHistoryLoaded     Evt = "history_loaded"
	EvtLocalNameChanged  Evt = "local_name_changed"
	EvtError             Evt = "error"
	EvtResponse          Evt = "response"
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

// VerificationMode controls peer verification behaviour.
type VerificationMode int

const (
	VerificationModeStrict     VerificationMode = 0
	VerificationModeQuick      VerificationMode = 1
	VerificationModeAutoAccept VerificationMode = 2
)

// ConnectionStatus is the daemon's high-level connection state.
type ConnectionStatus string

const (
	StatusDisconnected ConnectionStatus = "disconnected"
	StatusConnecting   ConnectionStatus = "connecting"
	StatusConnected    ConnectionStatus = "connected"
	StatusVerifying    ConnectionStatus = "verifying"
	StatusError        ConnectionStatus = "error"
)

// SessionInfo is the public session shape returned by get_sessions and
// emitted in session_started / session_closed events.
type SessionInfo struct {
	SessionID        string        `json:"session_id"`
	PeerName         string        `json:"peer_name"`
	IsServer         bool          `json:"is_server"`
	MsgCount         int           `json:"msg_count"`
	LastActivity     time.Time     `json:"last_activity,omitempty"`
	TransportType    string        `json:"transport_type,omitempty"`
	RemoteVersion    string        `json:"remote_version,omitempty"`
	SessionTTL       time.Duration `json:"session_ttl_ns"`
	SessionStartedAt time.Time     `json:"session_started_at"`
	RemoteAddr       string        `json:"remote_addr,omitempty"`
}

// HistorySessionInfo is the public history session shape.
type HistorySessionInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	MessageCount int       `json:"message_count"`
	FirstMessage time.Time `json:"first_message"`
	LastMessage  time.Time `json:"last_message"`
	Loaded       bool      `json:"loaded"`
}

// PeerInfo is the public peer shape returned by list_peers.
type PeerInfo struct {
	Name       string    `json:"name"`
	AppVersion string    `json:"app_version"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	PublicKey  string    `json:"public_key"` // base64-encoded
}

// FingerprintInfo is the public fingerprint shape returned by get_fingerprint.
type FingerprintInfo struct {
	Emoji string `json:"emoji"`
	B64   string `json:"b64"`
	Hex   string `json:"hex"`
	Sum   string `json:"sum"`
}

// MessageInfo is a single chat message in a session's history.
type MessageInfo struct {
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	IsLocal   bool      `json:"is_local"`
}

// relayToken is one active or consumed relay token.
type relayToken struct {
	Token      string        `json:"token"`
	Consumed   bool          `json:"consumed"`
	TTL        time.Duration `json:"ttl_ns"`
	SessionTTL time.Duration `json:"session_ttl_ns"`
	ExpiresAt  time.Time     `json:"expires_at"`
	listener   kamune.Listener
}

// liveSession wraps a kamune.Transport with metadata. Mirrors bus.liveSession
// (cmd/bus/app.go:126-138).
type liveSession struct {
	ID               string
	PeerName         string
	RemoteVersion    string
	RemoteAddr       string
	Transport        *kamune.Transport
	Messages         []MessageInfo
	LastActivity     time.Time
	ReceiveDone      chan struct{}
	IsServer         bool
	TransportType    string
	SessionTTL       time.Duration
	SessionStartedAt time.Time
}

// historySession is the daemon's cached view of a past chat session.
type historySession struct {
	ID           string
	Name         string
	Loaded       bool
	MessageCount int
	FirstMessage time.Time
	LastMessage  time.Time
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
