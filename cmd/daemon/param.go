package main

// OpenStorageParams contains parameters for opening the single shared storage.
type OpenStorageParams struct {
	StoragePath    string `json:"storage_path"`
	DBNoPassphrase bool   `json:"db_no_passphrase"`
}

// SubmitPassphraseParams contains parameters for re-opening storage with a
// new passphrase. Requires a prior open_storage call.
type SubmitPassphraseParams struct {
	Passphrase string `json:"passphrase"`
}

// StartServerParams contains parameters for starting a server.
type StartServerParams struct {
	Addr      string `json:"addr"`
	Transport string `json:"transport,omitempty"` // "tcp" (default), "udp", "relay"
	RelayAddr string `json:"relay_addr,omitempty"`
	Password  string `json:"password,omitempty"`
	Name      string `json:"name,omitempty"`
}

// DialParams contains parameters for dialing a remote server.
type DialParams struct {
	Addr      string `json:"addr"`
	Transport string `json:"transport,omitempty"` // "tcp" (default), "udp", "relay"
	RelayAddr string `json:"relay_addr,omitempty"`
	Token     string `json:"token,omitempty"`
	Password  string `json:"password,omitempty"`
	Name      string `json:"name,omitempty"`
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

// RenameSessionParams renames a live session in memory.
type RenameSessionParams struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
}

// RemoveRelayTokenParams removes an active relay token.
type RemoveRelayTokenParams struct {
	Token string `json:"token"`
}

// VerifyResponseParams answers a pending verify_peer event.
type VerifyResponseParams struct {
	RequestID int64 `json:"request_id"`
	Accepted  bool  `json:"accepted"`
}

// SetVerificationModeParams sets the peer verification mode.
type SetVerificationModeParams struct {
	Mode int `json:"mode"`
}

// GetHistoryMessagesParams fetches messages for a history session.
type GetHistoryMessagesParams struct {
	SessionID string `json:"session_id"`
}

// LoadHistoryParams marks a history session as loaded.
type LoadHistoryParams struct {
	SessionID string `json:"session_id"`
}

// RenameHistorySessionParams renames a history session.
type RenameHistorySessionParams struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name"`
}

// DeleteHistorySessionParams deletes a history session.
type DeleteHistorySessionParams struct {
	SessionID string `json:"session_id"`
}

// DeletePeerParams removes a known peer by its public key.
type DeletePeerParams struct {
	PublicKey string `json:"public_key"` // base64-encoded
}

// SetMyNameParams sets the local display name.
type SetMyNameParams struct {
	Name string `json:"name"`
}
