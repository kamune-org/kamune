package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) StartServer(addr string) (string, error) {
	a.setStatus(StatusConnecting, "Starting server...")

	store := a.store()
	if store == nil {
		return "", fmt.Errorf("storage is not available")
	}

	svr, err := kamune.NewServer(
		addr,
		a.serverHandler,
		store,
		kamune.ServeWithRemoteVerifier(a.getVerifier()),
	)
	if err != nil {
		a.setStatus(StatusError, "Failed to create server")
		a.addLogEntry("ERROR", "Failed to create server: "+err.Error())
		return "", fmt.Errorf("create server: %w", err)
	}

	pubKey := svr.PublicKey()
	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	hex := fingerprint.Hex(pubKey)

	done := make(chan struct{})
	a.mu.Lock()
	a.emojiFP = emoji
	a.hexFP = hex
	a.server = svr
	a.serverDone = done
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "fingerprint-changed", emoji, hex)

	go func() {
		defer close(done)
		err := svr.ListenAndServe()
		if err != nil {
			a.addLogEntry("ERROR", "Server stopped: "+err.Error())
		}
		a.mu.Lock()
		a.emojiFP = ""
		a.hexFP = ""
		a.server = nil
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "")
		a.setStatus(StatusDisconnected, "Server stopped")
	}()

	a.setStatus(StatusConnected, "Server running on "+addr)
	a.addLogEntry("INFO", "Server started on "+addr)
	a.loadHistorySessions(store)

	return emoji, nil
}

func (a *App) StopServer() error {
	a.setStatus(StatusDisconnected, "Stopping server...")
	a.addLogEntry("INFO", "Stopping server...")

	var serverDone chan struct{}
	a.mu.Lock()
	for _, s := range a.sessions {
		s.Transport.Close()
	}
	for _, s := range a.sessions {
		<-s.ReceiveDone
	}
	a.sessions = nil
	if a.server != nil {
		a.server.Close()
		a.server = nil
	}
	a.emojiFP = ""
	a.hexFP = ""
	serverDone = a.serverDone
	a.serverDone = nil
	a.mu.Unlock()

	if serverDone != nil {
		<-serverDone
	}

	runtime.EventsEmit(a.ctx, "fingerprint-changed", "", "")
	a.setStatus(StatusDisconnected, "Server stopped")
	a.addLogEntry("INFO", "Server stopped")
	return nil
}

func (a *App) ConnectToServer(addr string) (string, error) {
	a.setStatus(StatusConnecting, "Connecting to "+addr+"...")

	store := a.store()
	if store == nil {
		return "", fmt.Errorf("storage is not available")
	}

	dialer, err := kamune.NewDialer(addr, store,
		kamune.DialWithRemoteVerifier(a.getVerifier()),
	)
	if err != nil {
		a.setStatus(StatusError, "Failed to create dialer")
		return "", fmt.Errorf("create dialer: %w", err)
	}

	t, err := dialer.Dial()
	if err != nil {
		a.setStatus(StatusError, "Connection failed")
		return "", fmt.Errorf("dial: %w", err)
	}

	sessionID := t.SessionID()
	session := &liveSession{
		ID:           sessionID,
		PeerName:     fingerprint.Base64(t.RemotePublicKey()),
		Transport:    t,
		Messages:     make([]MessageInfo, 0),
		LastActivity: time.Now(),
		ReceiveDone:  make(chan struct{}),
	}

	a.loadChatHistory(session)

	a.mu.Lock()
	a.sessions = append(a.sessions, session)
	a.mu.Unlock()

	info := SessionInfo{
		ID:           session.ID,
		PeerName:     session.PeerName,
		IsServer:     false,
		MsgCount:     len(session.Messages),
		LastActivity: session.LastActivity,
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)

	a.setStatus(StatusConnected, "Connected to "+addr)
	a.addLogEntry("INFO", "Connected to "+addr+" (session: "+sessionID+")")

	go a.receiveMessages(session)

	return sessionID, nil
}

func (a *App) DisconnectSession(sessionID string) error {
	a.mu.Lock()
	var session *liveSession
	var remaining int
	for i, s := range a.sessions {
		if s.ID == sessionID {
			session = s
			a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
		}
	}
	remaining = len(a.sessions)
	a.mu.Unlock()

	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Transport.Close()
	<-session.ReceiveDone

	runtime.EventsEmit(a.ctx, "session-closed", sessionID)
	a.addLogEntry("INFO", "Disconnected session: "+sessionID)

	if remaining == 0 {
		a.setStatus(StatusDisconnected, "Not connected")
	}

	return nil
}

func (a *App) serverHandler(t *kamune.Transport) error {
	sessionID := t.SessionID()
	session := &liveSession{
		ID:           sessionID,
		PeerName:     fingerprint.Base64(t.RemotePublicKey()),
		Transport:    t,
		Messages:     make([]MessageInfo, 0),
		LastActivity: time.Now(),
		ReceiveDone:  make(chan struct{}),
		IsServer:     true,
	}

	a.loadChatHistory(session)

	a.mu.Lock()
	a.sessions = append(a.sessions, session)
	a.mu.Unlock()

	info := SessionInfo{
		ID:           session.ID,
		PeerName:     session.PeerName,
		IsServer:     true,
		MsgCount:     len(session.Messages),
		LastActivity: session.LastActivity,
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)
	a.addLogEntry("INFO", "New incoming connection: "+sessionID)

	a.receiveMessagesBlocking(session)

	a.mu.Lock()
	for i, s := range a.sessions {
		if s.ID == sessionID {
			a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
			break
		}
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "session-closed", sessionID)
	a.addLogEntry("INFO", "Peer disconnected: "+sessionID)
	return nil
}

func (a *App) loadChatHistory(session *liveSession) {
	store := a.store()
	if store == nil {
		return
	}

	entries, err := store.GetChatHistory(session.ID)
	if err != nil {
		a.addLogEntry("DEBUG", "No history for session: "+session.ID)
		return
	}

	session.Messages = make([]MessageInfo, 0, len(entries))
	for _, e := range entries {
		session.Messages = append(session.Messages, MessageInfo{
			Text:      string(e.Data),
			Timestamp: e.Timestamp,
			IsLocal:   e.Sender == storage.SenderLocal,
		})
		if e.Timestamp.After(session.LastActivity) {
			session.LastActivity = e.Timestamp
		}
	}
}
