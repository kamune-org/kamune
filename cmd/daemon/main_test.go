package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandSerialization(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name     string
		wantType string
		wantCmd  string
		cmd      Command
	}{
		{
			name: "start_server command",
			cmd: Command{
				Type:   "cmd",
				Cmd:    CmdStartServer,
				ID:     "test-123",
				Params: json.RawMessage(`{"addr":"127.0.0.1:9000"}`),
			},
			wantType: "cmd",
			wantCmd:  "start_server",
		},
		{
			name: "dial command",
			cmd: Command{
				Type:   "cmd",
				Cmd:    CmdDial,
				ID:     "test-456",
				Params: json.RawMessage(`{"addr":"192.168.1.10:9000"}`),
			},
			wantType: "cmd",
			wantCmd:  "dial",
		},
		{
			name: "send_message command",
			cmd: Command{
				Type:   "cmd",
				Cmd:    CmdSendMessage,
				ID:     "test-789",
				Params: json.RawMessage(`{"session_id":"abc","data_base64":"SGVsbG8="}`),
			},
			wantType: "cmd",
			wantCmd:  "send_message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.cmd)
			a.NoError(err, "failed to marshal command")

			var decoded Command
			err = json.Unmarshal(data, &decoded)
			a.NoError(err, "failed to unmarshal command")

			a.Equal(tt.wantType, decoded.Type, "Type mismatch")
			a.Equal(tt.wantCmd, decoded.Cmd, "Cmd mismatch")
			a.Equal(tt.cmd.ID, decoded.ID, "ID mismatch")
		})
	}
}

func TestEventSerialization(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name     string
		evt      Event
		wantType string
		wantEvt  string
	}{
		{
			name: "ready event",
			evt: Event{
				Type: "evt",
				Evt:  EvtReady,
				Data: map[string]string{"version": "1.0.0"},
			},
			wantType: "evt",
			wantEvt:  "ready",
		},
		{
			name: "session_started event",
			evt: Event{
				Type: "evt",
				Evt:  EvtSessionStarted,
				ID:   "cmd-123",
				Data: map[string]any{
					"session_id": "abc123",
					"is_server":  false,
				},
			},
			wantType: "evt",
			wantEvt:  "session_started",
		},
		{
			name: "message_received event",
			evt: Event{
				Type: "evt",
				Evt:  EvtMessageReceived,
				Data: map[string]any{
					"session_id":  "xyz",
					"data_base64": base64.StdEncoding.EncodeToString([]byte("Hello")),
					"timestamp":   "2024-01-15T10:30:00Z",
				},
			},
			wantType: "evt",
			wantEvt:  "message_received",
		},
		{
			name: "error event",
			evt: Event{
				Type: "evt",
				Evt:  EvtError,
				ID:   "failed-cmd",
				Data: map[string]string{"error": "connection refused"},
			},
			wantType: "evt",
			wantEvt:  "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.evt)
			a.NoError(err, "failed to marshal event")

			var decoded Event
			err = json.Unmarshal(data, &decoded)
			a.NoError(err, "failed to unmarshal event")

			a.Equal(tt.wantType, decoded.Type, "Type mismatch")
			a.Equal(tt.wantEvt, decoded.Evt, "Evt mismatch")
		})
	}
}

func TestStartServerParams(t *testing.T) {
	a := assert.New(t)
	params := StartServerParams{
		Addr:           "127.0.0.1:9000",
		StoragePath:    "/tmp/test.db",
		DBNoPassphrase: true,
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded StartServerParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Addr, decoded.Addr, "Addr mismatch")
	a.Equal(params.StoragePath, decoded.StoragePath, "StoragePath mismatch")
	a.Equal(params.DBNoPassphrase, decoded.DBNoPassphrase, "DBNoPassphrase mismatch")
}

func TestDialParams(t *testing.T) {
	a := assert.New(t)
	params := DialParams{
		Addr:           "192.168.1.10:9000",
		StoragePath:    "/tmp/client.db",
		DBNoPassphrase: false,
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded DialParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Addr, decoded.Addr, "Addr mismatch")
	a.Equal(params.StoragePath, decoded.StoragePath, "StoragePath mismatch")
	a.Equal(params.DBNoPassphrase, decoded.DBNoPassphrase, "DBNoPassphrase mismatch")
}

func TestSendMessageParams(t *testing.T) {
	a := assert.New(t)
	message := "Hello, World!"
	params := SendMessageParams{
		SessionID:  "session-abc-123",
		DataBase64: base64.StdEncoding.EncodeToString([]byte(message)),
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded SendMessageParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.SessionID, decoded.SessionID, "SessionID mismatch")
	a.Equal(params.DataBase64, decoded.DataBase64, "DataBase64 mismatch")

	// Verify we can decode the base64
	decodedMessage, err := base64.StdEncoding.DecodeString(decoded.DataBase64)
	a.NoError(err, "failed to decode base64")
	a.Equal(message, string(decodedMessage), "decoded message mismatch")
}

func TestSessionInfo(t *testing.T) {
	a := assert.New(t)
	info := SessionInfo{
		SessionID:  "test-session-id",
		RemoteAddr: "192.168.1.10:9000",
		IsServer:   true,
		CreatedAt:  "2024-01-15T10:00:00Z",
	}

	data, err := json.Marshal(info)
	a.NoError(err, "failed to marshal session info")

	var decoded SessionInfo
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal session info")

	a.Equal(info.SessionID, decoded.SessionID, "SessionID mismatch")
	a.Equal(info.RemoteAddr, decoded.RemoteAddr, "RemoteAddr mismatch")
	a.Equal(info.IsServer, decoded.IsServer, "IsServer mismatch")
	a.Equal(info.CreatedAt, decoded.CreatedAt, "CreatedAt mismatch")
}

func TestDaemonNew(t *testing.T) {
	a := assert.New(t)
	daemon := NewDaemon()
	a.NotNil(daemon, "NewDaemon() should not return nil")

	a.NotNil(daemon.sessions, "sessions map should not be nil")
	a.NotNil(daemon.output, "output encoder should not be nil")
	a.NotNil(daemon.ctx, "context should not be nil")
	a.NotNil(daemon.cancel, "cancel function should not be nil")
}

func TestCommandConstants(t *testing.T) {
	a := assert.New(t)
	// Verify command constants are defined correctly
	expectedCommands := map[string]string{
		"start_server":  CmdStartServer,
		"dial":          CmdDial,
		"send_message":  CmdSendMessage,
		"list_sessions": CmdListSessions,
		"close_session": CmdCloseSession,
		"shutdown":      CmdShutdown,
	}

	for expected, actual := range expectedCommands {
		a.Equal(expected, actual, "Command constant mismatch")
	}
}

func TestEventConstants(t *testing.T) {
	a := assert.New(t)
	// Verify event constants are defined correctly
	expectedEvents := map[string]string{
		"ready":            EvtReady,
		"server_started":   EvtServerStarted,
		"session_started":  EvtSessionStarted,
		"session_closed":   EvtSessionClosed,
		"message_received": EvtMessageReceived,
		"message_sent":     EvtMessageSent,
		"error":            EvtError,
		"response":         EvtResponse,
	}

	for expected, actual := range expectedEvents {
		a.Equal(expected, actual, "Event constant mismatch")
	}
}

func TestParseCommand(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name      string
		input     string
		wantCmd   string
		wantID    string
		wantError bool
	}{
		{
			name:    "valid start_server",
			input:   `{"type":"cmd","cmd":"start_server","id":"123","params":{"addr":"127.0.0.1:9000"}}`,
			wantCmd: "start_server",
			wantID:  "123",
		},
		{
			name:    "valid dial",
			input:   `{"type":"cmd","cmd":"dial","id":"456","params":{"addr":"192.168.1.1:9000"}}`,
			wantCmd: "dial",
			wantID:  "456",
		},
		{
			name:    "valid shutdown",
			input:   `{"type":"cmd","cmd":"shutdown","id":"789","params":{}}`,
			wantCmd: "shutdown",
			wantID:  "789",
		},
		{
			name:      "invalid json",
			input:     `{invalid json}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmd Command
			err := json.Unmarshal([]byte(tt.input), &cmd)

			if tt.wantError {
				a.Error(err, "expected error")
				return
			}

			a.NoError(err, "unexpected error")
			a.Equal(tt.wantCmd, cmd.Cmd, "Cmd mismatch")
			a.Equal(tt.wantID, cmd.ID, "ID mismatch")
		})
	}
}
