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
	Addr string `json:"addr"`
}

// DialParams contains parameters for dialing a remote server.
type DialParams struct {
	Addr string `json:"addr"`
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
