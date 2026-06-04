package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) StartServer(
	addr, transport, relayAddr, name, password string,
) (string, string, error) {
	a.mu.Lock()
	if a.server != nil {
		a.mu.Unlock()
		return "", "", fmt.Errorf("server is already running")
	}
	a.mu.Unlock()

	a.setStatus(StatusConnecting, "Starting server...")

	a.mu.Lock()
	a.serverAddr = addr
	a.serverTransport = transport
	a.serverRelayAddr = relayAddr
	a.serverName = name
	a.serverPassword = password
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	if a.startCancel != nil {
		a.startCancel()
	}
	a.startCtx = ctx
	a.startCancel = cancel
	a.mu.Unlock()

	cleanupStart := func() {
		a.mu.Lock()
		a.startCancel = nil
		a.startCtx = nil
		a.mu.Unlock()
	}
	defer cleanupStart()

	store := a.store()
	if store == nil {
		return "", "", fmt.Errorf("storage is not available")
	}

	if name == "" {
		pubKey, err := store.PublicKey()
		if err != nil {
			return "", "", fmt.Errorf("getting identity: %w", err)
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	a.mu.Lock()
	a.myName = name
	a.mu.Unlock()
	_ = store.SetSettings("bus", "local_name", name)

	var firstToken string
	var opts []kamune.ServerOptions
	opts = append(opts, kamune.ServeWithRemoteVerifier(a.getVerifier()))
	opts = append(opts, kamune.ServeWithServerName(name))

	switch transport {
	case "relay":
		a.mu.RLock()
		cancelled := a.startCancel == nil
		a.mu.RUnlock()
		if cancelled {
			a.setStatus(StatusDisconnected, "Cancelled")
			a.addLogEntry("INFO", "Server start cancelled")
			return "", "", fmt.Errorf("cancelled")
		}
		ml := newMultiListener()
		listener, token, ttl, err := listenRelayTracked(context.Background(), a, relayAddr, password, a.insecureTLS)
		if err != nil {
			a.mu.RLock()
			cancelled := a.startCancel == nil
			a.mu.RUnlock()
			if cancelled {
				a.setStatus(StatusDisconnected, "Cancelled")
				a.addLogEntry("INFO", "Server start cancelled")
				return "", "", fmt.Errorf("cancelled")
			}
			a.setStatus(StatusError, "Failed to connect to relay")
			a.addLogEntry("ERROR", "Relay listen failed: "+err.Error())
			return "", "", fmt.Errorf("relay listen: %w", err)
		}
		if err := ml.Add(listener); err != nil {
			return "", "", fmt.Errorf("add listener: %w", err)
		}
		firstToken = token
		opts = append(opts, kamune.ServeWithListener(ml))
		addr = "" // addr is unused with ServeWithListener
		a.relayAddr = relayAddr
		a.relayPassword = password
		a.relayListeners = ml
		a.relayTokens = []relayToken{{Token: token, TTL: ttl, ExpiresAt: time.Now().Add(ttl), listener: listener}}
	case "udp":
		opts = append(opts, kamune.ServeWithUDP())
	default:
		opts = append(opts, kamune.ServeWithTCP())
	}

	svr, err := kamune.NewServer(addr, a.serverHandler, store, opts...)
	if err != nil {
		a.setStatus(StatusError, "Failed to create server")
		a.addLogEntry("ERROR", "Failed to create server: "+err.Error())
		return "", "", fmt.Errorf("create server: %w", err)
	}

	pubKey := svr.PublicKey()
	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	b64 := fingerprint.Base64(pubKey)
	hex := fingerprint.Hex(pubKey)
	sum := fingerprint.Sum(pubKey)

	done := make(chan struct{})
	a.mu.Lock()
	a.pubKey = pubKey
	a.server = svr
	a.serverDone = done
	a.serverTransportType = transport
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "fingerprint-changed", emoji, b64, hex, sum)
	runtime.EventsEmit(a.ctx, "server-running", true, transport)

	go func() {
		defer close(done)
		err := svr.ListenAndServe()
		if err != nil {
			a.addLogEntry("ERROR", "Server stopped: "+err.Error())
		}
		a.mu.Lock()
		a.relayTokens = nil
		a.relayAddr = ""
		a.relayPassword = ""
		a.relayListeners = nil
		a.server = nil
		a.serverTransportType = ""
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "server-running", false, transport)
		a.setStatus(StatusDisconnected, "Server stopped")
		a.addLogEntry("INFO", "Server stopped")
	}()

	var statusMsg string
	if transport == "relay" {
		statusMsg = "Server (relay) — connected to " + relayAddr
	} else {
		statusMsg = "Server running on " + addr
	}
	a.setStatus(StatusConnected, statusMsg)
	a.addLogEntry("INFO", "Server started: "+statusMsg)
	a.loadHistorySessions(store)

	if firstToken != "" {
		tokens := a.getRelayTokens()
		runtime.EventsEmit(a.ctx, "relay-token", firstToken)
		runtime.EventsEmit(a.ctx, "relay-tokens", tokens)
		a.addLogEntry("INFO", "Relay token: "+firstToken)
	}

	return emoji, firstToken, nil
}

func (a *App) ConfirmStopServer() bool {
	a.mu.RLock()
	sessionCount := len(a.sessions)
	a.mu.RUnlock()

	if sessionCount == 0 {
		return true
	}

	msg := fmt.Sprintf("Stop the server? This will disconnect %d active session", sessionCount)
	if sessionCount > 1 {
		msg += "s"
	}
	msg += "."

	result, err := runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Title:         "Stop Server",
		Message:       msg,
		Type:          runtime.QuestionDialog,
		Buttons:       []string{"Stop", "Cancel"},
		DefaultButton: "Cancel",
		CancelButton:  "Cancel",
	})
	if err != nil || result == "Cancel" || result == "" {
		return false
	}
	return true
}

func (a *App) StopServer() error {
	a.setStatus(StatusDisconnected, "Stopping server...")
	a.addLogEntry("INFO", "Stopping server...")

	var sessions []*liveSession
	var serverDone chan struct{}

	a.mu.Lock()
	if a.relayListeners != nil {
		a.relayListeners.Close()
		a.relayListeners = nil
	}
	if a.server != nil {
		a.server.Close()
		a.server = nil
	}
	sessions = append([]*liveSession(nil), a.sessions...)
	a.sessions = nil
	a.relayTokens = nil
	a.relayAddr = ""
	a.relayPassword = ""
	serverDone = a.serverDone
	a.serverDone = nil
	a.mu.Unlock()

	for _, s := range sessions {
		s.Transport.Close()
	}
	for _, s := range sessions {
		waitOrTimeout(s.ReceiveDone, "session receive: "+s.ID)
	}

	if serverDone != nil {
		waitOrTimeout(serverDone, "ListenAndServe")
	}

	return nil
}

func (a *App) restartServer() error {
	a.mu.RLock()
	addr := a.serverAddr
	transport := a.serverTransport
	relayAddr := a.serverRelayAddr
	name := a.serverName
	password := a.serverPassword
	a.mu.RUnlock()

	a.addLogEntry("INFO", "Restarting server to apply verification mode change")

	if err := a.StopServer(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	_, _, err := a.StartServer(addr, transport, relayAddr, name, password)
	return err
}

func (a *App) CancelStartServer() {
	a.mu.Lock()
	if a.startCancel != nil {
		a.startCancel()
		a.startCancel = nil
		a.startCtx = nil
	}
	a.mu.Unlock()
	a.setStatus(StatusDisconnected, "Cancelled")
	a.addLogEntry("INFO", "Server start cancelled by user")
}

func (a *App) GenerateRelayToken() (string, error) {
	a.mu.Lock()
	if a.relayListeners == nil {
		a.mu.Unlock()
		return "", fmt.Errorf("relay is not configured — start a relay server first")
	}
	relayAddr := a.relayAddr
	password := a.relayPassword
	a.mu.Unlock()

	listener, token, ttl, err := listenRelayTracked(context.Background(), a, relayAddr, password, a.insecureTLS)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	if a.relayListeners == nil {
		a.mu.Unlock()
		listener.Close()
		return "", fmt.Errorf("server stopped while generating token")
	}
	if err := a.relayListeners.Add(listener); err != nil {
		a.mu.Unlock()
		return "", fmt.Errorf("add listener: %w", err)
	}
	a.relayTokens = append(a.relayTokens, relayToken{Token: token, TTL: ttl, ExpiresAt: time.Now().Add(ttl), listener: listener})
	tokens := make([]relayToken, len(a.relayTokens))
	copy(tokens, a.relayTokens)
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "relay-tokens", tokens)
	a.addLogEntry("INFO", "Generated relay token: "+token)
	return token, nil
}

func (a *App) RemoveRelayToken(token string) error {
	a.mu.Lock()
	idx := -1
	for i, t := range a.relayTokens {
		if t.Token == token {
			idx = i
			break
		}
	}
	if idx == -1 {
		a.mu.Unlock()
		return fmt.Errorf("token not found")
	}

	rt := a.relayTokens[idx]
	a.relayTokens = append(a.relayTokens[:idx], a.relayTokens[idx+1:]...)
	a.mu.Unlock()

	rt.listener.Close()

	tokens := a.getRelayTokens()
	runtime.EventsEmit(a.ctx, "relay-tokens", tokens)
	a.addLogEntry("INFO", "Removed relay token: "+token)
	return nil
}

func (a *App) GetRelayTokens() []relayToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getRelayTokens()
}

func (a *App) ConnectToServer(
	addr, transport, relayAddr, token, name, password string,
) (string, error) {
	a.setStatus(StatusConnecting, "Connecting to "+addr+"...")

	store := a.store()
	if store == nil {
		return "", fmt.Errorf("storage is not available")
	}

	var opts []kamune.DialOption
	opts = append(opts, kamune.DialWithRemoteVerifier(a.getVerifier()))

	if name == "" {
		pubKey, err := store.PublicKey()
		if err != nil {
			return "", fmt.Errorf("getting identity: %w", err)
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	a.mu.Lock()
	a.myName = name
	a.mu.Unlock()
	_ = store.SetSettings("bus", "local_name", name)

	opts = append(opts, kamune.DialWithClientName(name))

	switch transport {
	case "relay":
		fn, err := dialRelayFunc(relayAddr, token, password, a.insecureTLS)
		if err != nil {
			a.setStatus(StatusError, "Failed to prepare relay dial")
			a.addLogEntry("ERROR", "Relay dial preparation failed: "+err.Error())
			return "", fmt.Errorf("relay dial func: %w", err)
		}
		opts = append(opts, kamune.DialWithFunc(fn))
		addr = relayAddr
	case "udp":
		opts = append(opts, kamune.DialWithUDP())
	default:
		opts = append(opts, kamune.DialWithTCP())
	}

	dialer, err := kamune.NewDialer(addr, store, opts...)
	if err != nil {
		a.setStatus(StatusError, "Failed to create dialer")
		a.addLogEntry("ERROR", "Failed to create dialer: "+err.Error())
		return "", fmt.Errorf("create dialer: %w", err)
	}

	t, err := dialer.Dial()
	if err != nil {
		a.setStatus(StatusError, "Connection failed")
		a.addLogEntry("ERROR", "Dial failed: "+err.Error())
		return "", fmt.Errorf("dial: %w", err)
	}

	sessionID := t.SessionID()
	peer := t.RemotePeer()
	session := &liveSession{
		ID:            sessionID,
		PeerName:      peer.Name,
		RemoteVersion: peer.AppVersion,
		Transport:     t,
		Messages:      make([]MessageInfo, 0),
		LastActivity:  time.Now(),
		ReceiveDone:   make(chan struct{}),
		TransportType: transport,
	}

	a.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		a.addLogEntry("WARN", msg)
		runtime.EventsEmit(a.ctx, "version-warning", sessionID, msg)
	}

	a.mu.Lock()
	a.sessions = append(a.sessions, session)
	a.mu.Unlock()

	info := SessionInfo{
		ID:            session.ID,
		PeerName:      session.PeerName,
		IsServer:      false,
		MsgCount:      len(session.Messages),
		LastActivity:  session.LastActivity,
		TransportType: session.TransportType,
		RemoteVersion: peer.AppVersion,
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)

	a.setStatus(StatusConnected, "Connected to "+addr)
	a.addLogEntry("INFO", "Connected to "+addr+" (session: "+sessionID+")")

	go a.receiveMessages(session)

	return sessionID, nil
}

func (a *App) DisconnectSession(sessionID string) error {
	var session *liveSession

	func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		for i, s := range a.sessions {
			if s.ID == sessionID {
				session = s
				a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
				break
			}
		}
	}()

	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Transport.Close()
	waitOrTimeout(session.ReceiveDone, "DisconnectSession: "+sessionID)

	if store := a.store(); store != nil {
		a.loadHistorySessions(store)
	}

	runtime.EventsEmit(a.ctx, "session-closed", sessionID)
	a.addLogEntry("INFO", "Disconnected session: "+sessionID)
	return nil
}

func (a *App) serverHandler(t *kamune.Transport) error {
	a.mu.RLock()
	transport := a.serverTransportType
	a.mu.RUnlock()
	if transport == "" {
		transport = "tcp"
	}

	sessionID := t.SessionID()
	peer := t.RemotePeer()
	session := &liveSession{
		ID:            sessionID,
		PeerName:      peer.Name,
		RemoteVersion: peer.AppVersion,
		Transport:     t,
		Messages:      make([]MessageInfo, 0),
		LastActivity:  time.Now(),
		ReceiveDone:   make(chan struct{}),
		IsServer:      true,
		TransportType: transport,
	}

	a.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		a.addLogEntry("WARN", msg)
		runtime.EventsEmit(a.ctx, "version-warning", sessionID, msg)
	}

	a.mu.Lock()
	a.sessions = append(a.sessions, session)
	a.mu.Unlock()

	info := SessionInfo{
		ID:            session.ID,
		PeerName:      session.PeerName,
		IsServer:      true,
		MsgCount:      len(session.Messages),
		LastActivity:  session.LastActivity,
		TransportType: session.TransportType,
		RemoteVersion: peer.AppVersion,
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)
	a.addLogEntry("INFO", "New incoming connection: "+sessionID)

	defer close(session.ReceiveDone)
	a.receiveMessagesBlocking(session)

	a.removeSession(sessionID)

	if store := a.store(); store != nil {
		a.loadHistorySessions(store)
	}

	runtime.EventsEmit(a.ctx, "session-closed", sessionID)

	a.mu.Lock()
	sessionsRemaining := len(a.sessions)
	a.mu.Unlock()
	if sessionsRemaining == 0 {
		a.setStatus(StatusDisconnected, "Not connected")
		a.addLogEntry("INFO", "All sessions disconnected")
	}
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

	a.mu.Lock()
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
	a.mu.Unlock()
}

func (a *App) removeSession(sessionID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, s := range a.sessions {
		if s.ID == sessionID {
			a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
			break
		}
	}
	return len(a.sessions)
}

func (a *App) GetShareInfo() (*ShareInfo, error) {
	a.mu.RLock()
	if a.server == nil {
		a.mu.RUnlock()
		return nil, fmt.Errorf("server is not running")
	}
	transport := a.serverTransportType
	serverAddr := a.serverAddr
	pubKey := a.pubKey
	relayAddr := a.relayAddr
	relayPassword := a.relayPassword
	insecureTLS := a.insecureTLS
	a.mu.RUnlock()

	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	hexFP := fingerprint.Hex(pubKey)

	var (
		address   string
		port      string
		relayInfo *ShareRelayInfo
		urlStr    string
	)

	switch transport {
	case "tcp", "udp":
		host, p, autoDetect := parseServerAddr(serverAddr)
		port = p
		if autoDetect {
			ip, err := detectLocalIP()
			if err != nil {
				return nil, fmt.Errorf("detect local IP: %w", err)
			}
			address = ip
		} else {
			address = host
		}
		urlStr = fmt.Sprintf("%s://%s:%s", transport, address, port)

	case "relay":
		listener, token, ttl, err := listenRelayTracked(context.Background(), a, relayAddr, relayPassword, insecureTLS)
		if err != nil {
			return nil, fmt.Errorf("generate relay token: %w", err)
		}

		a.mu.Lock()
		if a.relayListeners == nil {
			a.mu.Unlock()
			listener.Close()
			return nil, fmt.Errorf("server stopped while generating token")
		}
		if err := a.relayListeners.Add(listener); err != nil {
			a.mu.Unlock()
			listener.Close()
			return nil, fmt.Errorf("add listener: %w", err)
		}
		a.relayTokens = append(a.relayTokens, relayToken{Token: token, TTL: ttl, ExpiresAt: time.Now().Add(ttl), listener: listener})
		tokens := make([]relayToken, len(a.relayTokens))
		copy(tokens, a.relayTokens)
		a.mu.Unlock()

		runtime.EventsEmit(a.ctx, "relay-tokens", tokens)
		a.addLogEntry("INFO", "Share card: generated relay token: "+token)

		scheme, host, _ := parseRelayAddr(relayAddr)
		relayInfo = &ShareRelayInfo{
			Address:  host,
			Scheme:   scheme,
			Token:    token,
			Password: relayPassword != "",
		}
		urlStr = fmt.Sprintf("relay://%s?token=%s&scheme=%s", host, token, scheme)
		if relayPassword != "" {
			urlStr += "&password=1"
		}

	default:
		return nil, fmt.Errorf("unknown transport: %s", transport)
	}

	return &ShareInfo{
		URL:              urlStr,
		Transport:        transport,
		Address:          address,
		Port:             port,
		FingerprintEmoji: emoji,
		FingerprintHex:   hexFP,
		RelayInfo:        relayInfo,
	}, nil
}

func parseServerAddr(addr string) (host, port string, autoDetect bool) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", false
	}
	if h == "" || h == "0.0.0.0" {
		return "", p, true
	}
	return h, p, false
}

func detectLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 address found")
}
