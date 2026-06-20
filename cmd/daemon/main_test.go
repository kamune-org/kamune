package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCommandSerialization(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name     string
		wantType string
		wantCmd  CMD
		cmd      Command
	}{
		{
			name: "start_server command",
			cmd: Command{
				Type:   "cmd",
				CMD:    CmdStartServer,
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
				CMD:    CmdDial,
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
				CMD:    CmdSendMessage,
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
			a.Equal(tt.wantCmd, decoded.CMD, "Cmd mismatch")
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
		wantEvt  Evt
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
		Addr:      "127.0.0.1:9000",
		Transport: "relay",
		RelayAddr: "wss://relay.example.com:8443",
		Password:  "secret",
		Name:      "CrimsonOtter",
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded StartServerParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Addr, decoded.Addr, "Addr mismatch")
	a.Equal(params.Transport, decoded.Transport, "Transport mismatch")
	a.Equal(params.RelayAddr, decoded.RelayAddr, "RelayAddr mismatch")
	a.Equal(params.Password, decoded.Password, "Password mismatch")
	a.Equal(params.Name, decoded.Name, "Name mismatch")
}

func TestDialParams(t *testing.T) {
	a := assert.New(t)
	params := DialParams{
		Addr:      "relay.example.com:8443",
		Transport: "relay",
		RelayAddr: "wss://relay.example.com:8443",
		Token:     "deadbeef",
		Password:  "secret",
		Name:      "CrimsonOtter",
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded DialParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Addr, decoded.Addr, "Addr mismatch")
	a.Equal(params.Transport, decoded.Transport, "Transport mismatch")
	a.Equal(params.RelayAddr, decoded.RelayAddr, "RelayAddr mismatch")
	a.Equal(params.Token, decoded.Token, "Token mismatch")
	a.Equal(params.Password, decoded.Password, "Password mismatch")
	a.Equal(params.Name, decoded.Name, "Name mismatch")
}

func TestOpenStorageParams(t *testing.T) {
	a := assert.New(t)
	params := OpenStorageParams{
		StoragePath:    "/tmp/test.db",
		DBNoPassphrase: true,
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded OpenStorageParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.StoragePath, decoded.StoragePath, "StoragePath mismatch")
	a.Equal(params.DBNoPassphrase, decoded.DBNoPassphrase, "DBNoPassphrase mismatch")
}

func TestSubmitPassphraseParams(t *testing.T) {
	a := assert.New(t)
	params := SubmitPassphraseParams{
		Passphrase: "correct horse battery staple",
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded SubmitPassphraseParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Passphrase, decoded.Passphrase, "Passphrase mismatch")
}

func TestMessageInfo(t *testing.T) {
	a := assert.New(t)
	ts := time.Date(2026, 6, 21, 10, 30, 0, 0, time.UTC)
	msg := MessageInfo{
		Text:      "Hello, World!",
		Timestamp: ts,
		IsLocal:   true,
	}

	data, err := json.Marshal(msg)
	a.NoError(err, "failed to marshal MessageInfo")

	var decoded MessageInfo
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal MessageInfo")

	a.Equal(msg.Text, decoded.Text, "Text mismatch")
	a.True(msg.Timestamp.Equal(decoded.Timestamp), "Timestamp mismatch")
	a.Equal(msg.IsLocal, decoded.IsLocal, "IsLocal mismatch")
}

func TestRenameSessionParams(t *testing.T) {
	a := assert.New(t)
	params := RenameSessionParams{
		SessionID: "abc123",
		Name:      "Alice",
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded RenameSessionParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.SessionID, decoded.SessionID, "SessionID mismatch")
	a.Equal(params.Name, decoded.Name, "Name mismatch")
}

func TestRemoveRelayTokenParams(t *testing.T) {
	a := assert.New(t)
	params := RemoveRelayTokenParams{
		Token: "deadbeefcafebabe",
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded RemoveRelayTokenParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Token, decoded.Token, "Token mismatch")
}

func TestVerifyResponseParams(t *testing.T) {
	a := assert.New(t)
	params := VerifyResponseParams{
		RequestID: 42,
		Accepted:  true,
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded VerifyResponseParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.RequestID, decoded.RequestID, "RequestID mismatch")
	a.Equal(params.Accepted, decoded.Accepted, "Accepted mismatch")
}

func TestSetVerificationModeParams(t *testing.T) {
	a := assert.New(t)
	params := SetVerificationModeParams{
		Mode: int(VerificationModeStrict),
	}

	data, err := json.Marshal(params)
	a.NoError(err, "failed to marshal params")

	var decoded SetVerificationModeParams
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal params")

	a.Equal(params.Mode, decoded.Mode, "Mode mismatch")
}

func TestGetHistoryMessagesParams(t *testing.T) {
	a := assert.New(t)
	params := GetHistoryMessagesParams{SessionID: "abc123"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded GetHistoryMessagesParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.SessionID, decoded.SessionID)
}

func TestLoadHistoryParams(t *testing.T) {
	a := assert.New(t)
	params := LoadHistoryParams{SessionID: "abc123"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded LoadHistoryParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.SessionID, decoded.SessionID)
}

func TestRenameHistorySessionParams(t *testing.T) {
	a := assert.New(t)
	params := RenameHistorySessionParams{SessionID: "abc123", Name: "Alice"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded RenameHistorySessionParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.SessionID, decoded.SessionID)
	a.Equal(params.Name, decoded.Name)
}

func TestDeleteHistorySessionParams(t *testing.T) {
	a := assert.New(t)
	params := DeleteHistorySessionParams{SessionID: "abc123"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded DeleteHistorySessionParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.SessionID, decoded.SessionID)
}

func TestDeletePeerParams(t *testing.T) {
	a := assert.New(t)
	params := DeletePeerParams{PublicKey: "deadbeef"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded DeletePeerParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.PublicKey, decoded.PublicKey)
}

func TestSetMyNameParams(t *testing.T) {
	a := assert.New(t)
	params := SetMyNameParams{Name: "CrimsonOtter"}
	data, err := json.Marshal(params)
	a.NoError(err)
	var decoded SetMyNameParams
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(params.Name, decoded.Name)
}

func TestHistorySessionInfo(t *testing.T) {
	a := assert.New(t)
	ts := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	info := HistorySessionInfo{
		ID: "abc123", Name: "Alice", MessageCount: 10,
		FirstMessage: ts, LastMessage: ts, Loaded: true,
	}
	data, err := json.Marshal(info)
	a.NoError(err)
	var decoded HistorySessionInfo
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(info.ID, decoded.ID)
	a.Equal(info.Name, decoded.Name)
	a.Equal(info.MessageCount, decoded.MessageCount)
	a.Equal(info.Loaded, decoded.Loaded)
	a.True(info.FirstMessage.Equal(decoded.FirstMessage))
}

func TestPeerInfo(t *testing.T) {
	a := assert.New(t)
	ts := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	info := PeerInfo{
		Name: "Bob", AppVersion: "0.5.0",
		FirstSeen: ts, LastSeen: ts, PublicKey: "deadbeef",
	}
	data, err := json.Marshal(info)
	a.NoError(err)
	var decoded PeerInfo
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(info.Name, decoded.Name)
	a.Equal(info.AppVersion, decoded.AppVersion)
	a.Equal(info.PublicKey, decoded.PublicKey)
}

func TestFingerprintInfo(t *testing.T) {
	a := assert.New(t)
	info := FingerprintInfo{
		Emoji: "🦊 • 🐱", B64: "abc", Hex: "def", Sum: "ghi",
	}
	data, err := json.Marshal(info)
	a.NoError(err)
	var decoded FingerprintInfo
	a.NoError(json.Unmarshal(data, &decoded))
	a.Equal(info.Emoji, decoded.Emoji)
	a.Equal(info.B64, decoded.B64)
	a.Equal(info.Hex, decoded.Hex)
	a.Equal(info.Sum, decoded.Sum)
}

func TestVerificationModeConstants(t *testing.T) {
	a := assert.New(t)
	a.Equal(VerificationMode(0), VerificationModeStrict, "Strict mismatch")
	a.Equal(VerificationMode(1), VerificationModeQuick, "Quick mismatch")
	a.Equal(VerificationMode(2), VerificationModeAutoAccept, "AutoAccept mismatch")
}

func TestConnectionStatusConstants(t *testing.T) {
	a := assert.New(t)
	a.Equal(ConnectionStatus("disconnected"), StatusDisconnected)
	a.Equal(ConnectionStatus("connecting"), StatusConnecting)
	a.Equal(ConnectionStatus("connected"), StatusConnected)
	a.Equal(ConnectionStatus("verifying"), StatusVerifying)
	a.Equal(ConnectionStatus("error"), StatusError)
}

func TestRelayToken(t *testing.T) {
	a := assert.New(t)
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	tok := relayToken{
		Token:      "deadbeef",
		Consumed:   false,
		TTL:        time.Hour,
		SessionTTL: 30 * time.Minute,
		ExpiresAt:  expires,
	}

	data, err := json.Marshal(tok)
	a.NoError(err, "failed to marshal relayToken")

	var decoded relayToken
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal relayToken")

	a.Equal(tok.Token, decoded.Token, "Token mismatch")
	a.Equal(tok.Consumed, decoded.Consumed, "Consumed mismatch")
	a.Equal(tok.TTL, decoded.TTL, "TTL mismatch")
	a.Equal(tok.SessionTTL, decoded.SessionTTL, "SessionTTL mismatch")
	a.True(tok.ExpiresAt.Equal(decoded.ExpiresAt), "ExpiresAt mismatch")
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
	ts := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	info := SessionInfo{
		SessionID:        "test-session-id",
		PeerName:         "CrimsonOtter",
		IsServer:         true,
		MsgCount:         42,
		LastActivity:     ts,
		TransportType:    "relay",
		RemoteVersion:    "0.5.0",
		SessionTTL:       time.Hour,
		SessionStartedAt: ts,
		RemoteAddr:       "192.168.1.10:9000",
	}

	data, err := json.Marshal(info)
	a.NoError(err, "failed to marshal session info")

	var decoded SessionInfo
	err = json.Unmarshal(data, &decoded)
	a.NoError(err, "failed to unmarshal session info")

	a.Equal(info.SessionID, decoded.SessionID, "SessionID mismatch")
	a.Equal(info.PeerName, decoded.PeerName, "PeerName mismatch")
	a.Equal(info.IsServer, decoded.IsServer, "IsServer mismatch")
	a.Equal(info.MsgCount, decoded.MsgCount, "MsgCount mismatch")
	a.True(info.LastActivity.Equal(decoded.LastActivity), "LastActivity mismatch")
	a.Equal(info.TransportType, decoded.TransportType, "TransportType mismatch")
	a.Equal(info.RemoteVersion, decoded.RemoteVersion, "RemoteVersion mismatch")
	a.Equal(info.SessionTTL, decoded.SessionTTL, "SessionTTL mismatch")
	a.True(info.SessionStartedAt.Equal(decoded.SessionStartedAt), "SessionStartedAt mismatch")
	a.Equal(info.RemoteAddr, decoded.RemoteAddr, "RemoteAddr mismatch")
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
	expectedCommands := map[string]CMD{
		"open_storage":           CmdOpenStorage,
		"submit_passphrase":      CmdSubmitPassphrase,
		"start_server":           CmdStartServer,
		"stop_server":            CmdStopServer,
		"restart_server":         CmdRestartServer,
		"cancel_start_server":    CmdCancelStartServer,
		"get_server_status":      CmdGetServerStatus,
		"get_status":             CmdGetStatus,
		"dial":                   CmdDial,
		"send_message":           CmdSendMessage,
		"list_sessions":          CmdListSessions,
		"close_session":          CmdCloseSession,
		"rename_session":         CmdRenameSession,
		"generate_relay_token":   CmdGenerateRelayToken,
		"remove_relay_token":     CmdRemoveRelayToken,
		"list_relay_tokens":      CmdListRelayTokens,
		"get_share_info":         CmdGetShareInfo,
		"verify_response":        CmdVerifyResponse,
		"set_verification_mode":  CmdSetVerificationMode,
		"get_verification_mode":  CmdGetVerificationMode,
		"get_history_sessions":   CmdGetHistorySessions,
		"get_history_messages":   CmdGetHistoryMessages,
		"load_history":           CmdLoadHistory,
		"rename_history_session": CmdRenameHistorySession,
		"delete_history_session": CmdDeleteHistorySession,
		"refresh_history":        CmdRefreshHistory,
		"list_peers":             CmdListPeers,
		"delete_peer":            CmdDeletePeer,
		"get_fingerprint":        CmdGetFingerprint,
		"get_my_name":            CmdGetMyName,
		"set_my_name":            CmdSetMyName,
		"get_version":            CmdGetVersion,
		"get_library_version":    CmdGetLibraryVersion,
		"shutdown":               CmdShutdown,
	}

	for expected, actual := range expectedCommands {
		a.Equal(expected, string(actual), "Command constant mismatch")
	}
}

func TestEventConstants(t *testing.T) {
	a := assert.New(t)
	expectedEvents := map[string]Evt{
		"ready":                  EvtReady,
		"server_started":         EvtServerStarted,
		"server_stopped":         EvtServerStopped,
		"server_running":         EvtServerRunning,
		"server_start_cancelled": EvtServerStartCancel,
		"session_started":        EvtSessionStarted,
		"session_closed":         EvtSessionClosed,
		"session_updated":        EvtSessionUpdated,
		"message_received":       EvtMessageReceived,
		"message_sent":           EvtMessageSent,
		"status_changed":         EvtStatusChanged,
		"fingerprint_changed":    EvtFingerprintChange,
		"version_warning":        EvtVersionWarning,
		"relay_token":            EvtRelayToken,
		"relay_tokens":           EvtRelayTokens,
		"verify_peer":            EvtVerifyPeer,
		"history_updated":        EvtHistoryUpdated,
		"history_loaded":         EvtHistoryLoaded,
		"local_name_changed":     EvtLocalNameChanged,
		"error":                  EvtError,
		"response":               EvtResponse,
	}

	for expected, actual := range expectedEvents {
		a.Equal(expected, string(actual), "Event constant mismatch")
	}
}

func TestParseCommand(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name      string
		input     string
		wantCmd   CMD
		wantID    ID
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
			a.Equal(tt.wantCmd, cmd.CMD, "Cmd mismatch")
			a.Equal(tt.wantID, cmd.ID, "ID mismatch")
		})
	}
}

func TestTruncateSessionID(t *testing.T) {
	a := assert.New(t)
	a.Equal("short", truncateSessionID("short"), "short ID should be unchanged")
	a.Equal(
		"abcdefgh...wxyz",
		truncateSessionID("abcdefghijklmnopqrstuvwxyz"),
		"long ID should be truncated to first8...last4",
	)
}
