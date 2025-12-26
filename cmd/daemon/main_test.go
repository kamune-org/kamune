package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestCommandSerialization(t *testing.T) {
	tests := []struct {
		name     string
		cmd      Command
		wantType string
		wantCmd  string
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
			if err != nil {
				t.Fatalf("failed to marshal command: %v", err)
			}

			var decoded Command
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal command: %v", err)
			}

			if decoded.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", decoded.Type, tt.wantType)
			}
			if decoded.Cmd != tt.wantCmd {
				t.Errorf("Cmd = %v, want %v", decoded.Cmd, tt.wantCmd)
			}
			if decoded.ID != tt.cmd.ID {
				t.Errorf("ID = %v, want %v", decoded.ID, tt.cmd.ID)
			}
		})
	}
}

func TestEventSerialization(t *testing.T) {
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
			if err != nil {
				t.Fatalf("failed to marshal event: %v", err)
			}

			var decoded Event
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal event: %v", err)
			}

			if decoded.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", decoded.Type, tt.wantType)
			}
			if decoded.Evt != tt.wantEvt {
				t.Errorf("Evt = %v, want %v", decoded.Evt, tt.wantEvt)
			}
		})
	}
}

func TestStartServerParams(t *testing.T) {
	params := StartServerParams{
		Addr:           "127.0.0.1:9000",
		StoragePath:    "/tmp/test.db",
		DBNoPassphrase: true,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	var decoded StartServerParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}

	if decoded.Addr != params.Addr {
		t.Errorf("Addr = %v, want %v", decoded.Addr, params.Addr)
	}
	if decoded.StoragePath != params.StoragePath {
		t.Errorf("StoragePath = %v, want %v", decoded.StoragePath, params.StoragePath)
	}
	if decoded.DBNoPassphrase != params.DBNoPassphrase {
		t.Errorf("DBNoPassphrase = %v, want %v", decoded.DBNoPassphrase, params.DBNoPassphrase)
	}
}

func TestDialParams(t *testing.T) {
	params := DialParams{
		Addr:           "192.168.1.10:9000",
		StoragePath:    "/tmp/client.db",
		DBNoPassphrase: false,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	var decoded DialParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}

	if decoded.Addr != params.Addr {
		t.Errorf("Addr = %v, want %v", decoded.Addr, params.Addr)
	}
	if decoded.StoragePath != params.StoragePath {
		t.Errorf("StoragePath = %v, want %v", decoded.StoragePath, params.StoragePath)
	}
	if decoded.DBNoPassphrase != params.DBNoPassphrase {
		t.Errorf("DBNoPassphrase = %v, want %v", decoded.DBNoPassphrase, params.DBNoPassphrase)
	}
}

func TestSendMessageParams(t *testing.T) {
	message := "Hello, World!"
	params := SendMessageParams{
		SessionID:  "session-abc-123",
		DataBase64: base64.StdEncoding.EncodeToString([]byte(message)),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	var decoded SendMessageParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}

	if decoded.SessionID != params.SessionID {
		t.Errorf("SessionID = %v, want %v", decoded.SessionID, params.SessionID)
	}
	if decoded.DataBase64 != params.DataBase64 {
		t.Errorf("DataBase64 = %v, want %v", decoded.DataBase64, params.DataBase64)
	}

	// Verify we can decode the base64
	decodedMessage, err := base64.StdEncoding.DecodeString(decoded.DataBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if string(decodedMessage) != message {
		t.Errorf("decoded message = %v, want %v", string(decodedMessage), message)
	}
}

func TestSessionInfo(t *testing.T) {
	info := SessionInfo{
		SessionID:  "test-session-id",
		RemoteAddr: "192.168.1.10:9000",
		IsServer:   true,
		CreatedAt:  "2024-01-15T10:00:00Z",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal session info: %v", err)
	}

	var decoded SessionInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal session info: %v", err)
	}

	if decoded.SessionID != info.SessionID {
		t.Errorf("SessionID = %v, want %v", decoded.SessionID, info.SessionID)
	}
	if decoded.RemoteAddr != info.RemoteAddr {
		t.Errorf("RemoteAddr = %v, want %v", decoded.RemoteAddr, info.RemoteAddr)
	}
	if decoded.IsServer != info.IsServer {
		t.Errorf("IsServer = %v, want %v", decoded.IsServer, info.IsServer)
	}
	if decoded.CreatedAt != info.CreatedAt {
		t.Errorf("CreatedAt = %v, want %v", decoded.CreatedAt, info.CreatedAt)
	}
}

func TestDaemonNew(t *testing.T) {
	daemon := NewDaemon()
	if daemon == nil {
		t.Fatal("NewDaemon() returned nil")
	}

	if daemon.sessions == nil {
		t.Error("sessions map is nil")
	}
	if daemon.output == nil {
		t.Error("output encoder is nil")
	}
	if daemon.ctx == nil {
		t.Error("context is nil")
	}
	if daemon.cancel == nil {
		t.Error("cancel function is nil")
	}
}

func TestCommandConstants(t *testing.T) {
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
		if actual != expected {
			t.Errorf("Command constant mismatch: got %v, want %v", actual, expected)
		}
	}
}

func TestEventConstants(t *testing.T) {
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
		if actual != expected {
			t.Errorf("Event constant mismatch: got %v, want %v", actual, expected)
		}
	}
}

func TestParseCommand(t *testing.T) {
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
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cmd.Cmd != tt.wantCmd {
				t.Errorf("Cmd = %v, want %v", cmd.Cmd, tt.wantCmd)
			}
			if cmd.ID != tt.wantID {
				t.Errorf("ID = %v, want %v", cmd.ID, tt.wantID)
			}
		})
	}
}
