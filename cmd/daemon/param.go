package main

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
