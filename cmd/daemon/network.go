package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// handleStartServer starts a kamune server. Supports tcp, udp, and relay
// transports (mirrors cmd/bus/network.go:16-179).
func (d *Daemon) handleStartServer(cmd Command) {
	var params StartServerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.setStatus(StatusConnecting, "Starting server...")

	d.mu.Lock()
	d.serverAddr = params.Addr
	d.serverTransport = params.Transport
	d.serverRelayAddr = params.RelayAddr
	d.serverName = params.Name
	d.serverPassword = params.Password
	d.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	if d.startCancel != nil {
		d.startCancel()
	}
	d.startCtx = ctx
	d.startCancel = cancel
	d.mu.Unlock()

	cleanupStart := func() {
		d.mu.Lock()
		d.startCancel = nil
		d.startCtx = nil
		d.mu.Unlock()
	}
	defer cleanupStart()

	store := d.store()
	if store == nil {
		d.setStatus(StatusError, "Storage is not available")
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	name := params.Name
	if name == "" || d.incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			d.setStatus(StatusError, "Failed to get identity")
			d.emitError(cmd.ID, fmt.Sprintf("getting identity: %v", err))
			return
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	d.mu.Lock()
	d.myName = name
	d.mu.Unlock()
	if !d.incognito {
		_ = store.SetSettings("daemon", "local_name", name)
	}

	var firstToken string
	var opts []kamune.ServerOptions
	opts = append(opts, kamune.ServeWithRemoteVerifier(d.getVerifier()))
	opts = append(opts, kamune.ServeWithServerName(name))

	switch params.Transport {
	case "relay":
		d.mu.RLock()
		cancelled := d.startCancel == nil
		d.mu.RUnlock()
		if cancelled {
			d.setStatus(StatusDisconnected, "Cancelled")
			d.emit(EvtServerStartCancel, "", MapS{})
			return
		}
		ml := newMultiListener()
		listener, token, ttl, sessionTTL, err := listenRelayTracked(
			context.Background(), d, params.RelayAddr, params.Password, false, nil,
		)
		if err != nil {
			d.mu.RLock()
			cancelled := d.startCancel == nil
			d.mu.RUnlock()
			if cancelled {
				d.setStatus(StatusDisconnected, "Cancelled")
				d.emit(EvtServerStartCancel, "", MapS{})
				return
			}
			d.setStatus(StatusError, "Failed to connect to relay")
			d.addLogEntry("ERROR", "Relay listen failed: "+err.Error())
			d.emitError(cmd.ID, fmt.Sprintf("relay listen: %v", err))
			return
		}
		if err := ml.Add(listener); err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("add listener: %v", err))
			return
		}
		firstToken = token
		opts = append(opts, kamune.ServeWithListener(ml))
		params.Addr = ""
		d.mu.Lock()
		d.relayAddr = params.RelayAddr
		d.relayPassword = params.Password
		d.relaySessionTTL = sessionTTL
		d.relayListeners = ml
		d.relayTokens = []relayToken{{
			Token: token, TTL: ttl, SessionTTL: sessionTTL,
			ExpiresAt: time.Now().Add(ttl), Mode: "random",
			listener: listener,
		}}
		d.mu.Unlock()
		d.wg.Go(func() {
			d.relayReconnectLoop(context.Background(), ml)
		})
	case "p2p":
		d.mu.Lock()
		if d.brokerClient == nil {
			bc, err := NewBrokerClient()
			if err != nil {
				d.mu.Unlock()
				d.setStatus(StatusError, "Failed to create broker client")
				d.emitError(cmd.ID, fmt.Sprintf("broker client: %v", err))
				return
			}
			d.brokerClient = bc
		}
		d.mu.Unlock()

		tokenHex, err := d.GenerateP2PToken(
			params.BrokerAddr, params.PeerPubB64,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to create p2p token")
			d.emitError(cmd.ID, fmt.Sprintf("p2p token: %v", err))
			return
		}

		tokenBytes, err := hex.DecodeString(tokenHex)
		if err != nil {
			d.setStatus(StatusError, "Failed to decode p2p token")
			d.emitError(cmd.ID, fmt.Sprintf("decode token: %v", err))
			return
		}
		pl, err := newP2PListener(
			d.brokerClient, params.BrokerAddr, tokenBytes, params.Addr,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to create p2p listener")
			d.emitError(cmd.ID, fmt.Sprintf("p2p listener: %v", err))
			return
		}
		opts = append(opts, kamune.ServeWithUDP())
		d.mu.Lock()
		d.p2pListener = pl
		d.mu.Unlock()
	case "direct-p2p":
		pl, err := newDirectP2PListener(
			params.Addr, params.DirectPeerAddr,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to create direct p2p listener")
			d.emitError(cmd.ID, fmt.Sprintf("direct p2p listener: %v", err))
			return
		}
		opts = append(opts, kamune.ServeWithListener(pl))
		params.Addr = pl.Addr().String()
	case "udp":
		opts = append(opts, kamune.ServeWithUDP())
	default:
		opts = append(opts, kamune.ServeWithTCP())
	}

	srv, err := kamune.NewServer(params.Addr, d.serverHandler, store, opts...)
	if err != nil {
		d.setStatus(StatusError, "Failed to create server")
		d.addLogEntry("ERROR", "Failed to create server: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("create server: %v", err))
		return
	}

	pubKey := srv.PublicKey()
	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	b64 := fingerprint.Base64(pubKey)
	hexFP := fingerprint.Hex(pubKey)
	sum := fingerprint.Sum(pubKey)

	done := make(chan struct{})
	d.mu.Lock()
	d.pubKey = pubKey
	d.server = srv
	d.serverDone = done
	serverTransport := params.Transport
	d.mu.Unlock()

	d.emit(EvtFingerprintChange, "", MapA{
		"emoji": emoji, "b64": b64, "hex": hexFP, "sum": sum,
	})
	d.emit(EvtServerRunning, "", MapA{
		"running": true, "transport": serverTransport,
	})

	d.wg.Go(func() {
		defer close(done)
		if err := srv.ListenAndServe(); err != nil {
			d.addLogEntry("ERROR", "Server stopped: "+err.Error())
		}
		d.mu.Lock()
		d.relayTokens = nil
		d.relayAddr = ""
		d.relayPassword = ""
		d.relayListeners = nil
		d.server = nil
		d.mu.Unlock()
		d.emit(EvtServerRunning, "", MapA{
			"running": false, "transport": serverTransport,
		})
		d.setStatus(StatusDisconnected, "Server stopped")
		d.addLogEntry("INFO", "Server stopped")
	})

	var statusMsg string
	if params.Transport == "relay" {
		statusMsg = "Server (relay) — connected to " + params.RelayAddr
	} else {
		statusMsg = "Server running on " + params.Addr
	}
	d.setStatus(StatusConnected, statusMsg)
	d.addLogEntry("INFO", "Server started: "+statusMsg)
	d.loadHistorySessions()

	if firstToken != "" {
		d.mu.RLock()
		tokens := make([]relayToken, len(d.relayTokens))
		copy(tokens, d.relayTokens)
		d.mu.RUnlock()
		d.emit(EvtRelayToken, "", MapA{
			"token": firstToken, "ttl_ns": tokens[0].TTL,
			"session_ttl_ns": tokens[0].SessionTTL,
			"expires_at":     tokens[0].ExpiresAt,
		})
		d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
		d.addLogEntry("INFO", "Relay token: "+firstToken)
	}

	d.emit(EvtServerStarted, cmd.ID, MapA{
		"addr":            params.Addr,
		"transport":       serverTransport,
		"name":            name,
		"public_key":      b64,
		"emoji":           fingerprint.Emoji(pubKey),
		"fingerprint_hex": hexFP,
		"fingerprint_sum": sum,
	})
}

// handleStopServer closes the running server and all sessions, without
// exiting the daemon.
func (d *Daemon) handleStopServer(cmd Command) {
	d.setStatus(StatusDisconnected, "Stopping server...")
	d.addLogEntry("INFO", "Stopping server...")

	var sessions []*liveSession
	var serverDone chan struct{}

	d.mu.Lock()
	if d.relayListeners != nil {
		d.relayListeners.Close()
		d.relayListeners = nil
	}
	if d.server != nil {
		d.server.Close()
		d.server = nil
	}
	sessions = append([]*liveSession(nil), mapValues(d.sessions)...)
	d.sessions = make(map[string]*liveSession)
	d.relayTokens = nil
	d.relayAddr = ""
	d.relayPassword = ""
	serverDone = d.serverDone
	d.serverDone = nil
	d.mu.Unlock()

	for _, s := range sessions {
		s.Transport.Close()
	}
	for _, s := range sessions {
		waitOrTimeout(s.ReceiveDone, "session receive: "+s.ID)
	}

	if serverDone != nil {
		waitOrTimeout(serverDone, "ListenAndServe")
	}

	d.emit(EvtServerStopped, "", MapA{"running": false})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "stopped"})
}

// handleRestartServer stops the server and starts it again with the last used
// params. Used after set_verification_mode to apply the new mode to incoming
// server connections.
func (d *Daemon) handleRestartServer(cmd Command) {
	d.mu.RLock()
	addr := d.serverAddr
	transport := d.serverTransport
	relayAddr := d.serverRelayAddr
	name := d.serverName
	password := d.serverPassword
	d.mu.RUnlock()

	d.addLogEntry("INFO", "Restarting server to apply settings change")

	d.handleStopServer(Command{ID: cmd.ID})
	d.handleStartServer(Command{
		ID: cmd.ID,
		Params: mustJSON(StartServerParams{
			Addr: addr, Transport: transport,
			RelayAddr: relayAddr, Password: password, Name: name,
		}),
	})
}

// handleCancelStartServer cancels an in-flight server start.
func (d *Daemon) handleCancelStartServer(cmd Command) {
	d.mu.Lock()
	if d.startCancel != nil {
		d.startCancel()
		d.startCancel = nil
		d.startCtx = nil
	}
	d.mu.Unlock()
	d.setStatus(StatusDisconnected, "Cancelled")
	d.addLogEntry("INFO", "Server start cancelled by user")
	d.emit(EvtServerStartCancel, "", MapS{})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "cancelled"})
}

// handleGetServerStatus returns the current server state.
func (d *Daemon) handleGetServerStatus(cmd Command) {
	d.mu.RLock()
	running := d.server != nil
	transport := d.serverTransport
	addr := d.serverAddr
	relayAddr := d.serverRelayAddr
	name := d.serverName
	var startedAt time.Time
	if running {
		for _, s := range d.sessions {
			if s.IsServer && !startedAt.After(s.SessionStartedAt) {
				startedAt = s.SessionStartedAt
			}
		}
	}
	d.mu.RUnlock()

	var startedAtStr string
	if !startedAt.IsZero() {
		startedAtStr = startedAt.Format(time.RFC3339)
	}
	d.emit(EvtResponse, cmd.ID, MapA{
		"running":    running,
		"transport":  transport,
		"addr":       addr,
		"relay_addr": relayAddr,
		"name":       name,
		"started_at": startedAtStr,
	})
}

// handleGetStatus returns the current connection status.
func (d *Daemon) handleGetStatus(cmd Command) {
	d.mu.RLock()
	status := d.status
	msg := d.statusMsg
	d.mu.RUnlock()
	d.emit(EvtResponse, cmd.ID, MapS{
		"status": string(status), "message": msg,
	})
}

// handleDial connects to a remote kamune server. Supports tcp, udp, and
// relay transports.
func (d *Daemon) handleDial(cmd Command) {
	var params DialParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.setStatus(StatusConnecting, "Connecting to "+params.Addr+"...")

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	var opts []kamune.DialOption
	opts = append(opts, kamune.DialWithRemoteVerifier(d.getVerifier()))

	name := params.Name
	if name == "" || d.incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("getting identity: %v", err))
			return
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	d.mu.Lock()
	d.myName = name
	d.mu.Unlock()
	if !d.incognito {
		_ = store.SetSettings("daemon", "local_name", name)
	}

	opts = append(opts, kamune.DialWithClientName(name))

	var sessionTTL time.Duration
	switch params.Transport {
	case "relay":
		fn, err := dialRelayFuncWithSessionTTL(
			params.RelayAddr, params.Token, params.Password, false, &sessionTTL,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to prepare relay dial")
			d.addLogEntry("ERROR", "Relay dial preparation failed: "+err.Error())
			d.emitError(cmd.ID, fmt.Sprintf("relay dial func: %v", err))
			return
		}
		opts = append(opts, kamune.DialWithFunc(fn))
		params.Addr = params.RelayAddr
	case "p2p":
		if d.brokerClient == nil {
			d.mu.Lock()
			if d.brokerClient == nil {
				bc, err := NewBrokerClient()
				if err != nil {
					d.mu.Unlock()
					d.emitError(cmd.ID, fmt.Sprintf("broker client: %v", err))
					return
				}
				d.brokerClient = bc
			}
			d.mu.Unlock()
		}
		punchConn, payload, err := d.brokerClient.WaitMatch(
			context.Background(), params.BrokerAddr,
			[]byte(params.P2PToken),
		)
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("wait match: %v", err))
			return
		}
		conn, err := d.brokerClient.HolePunch(
			context.Background(), punchConn,
			payload.IP, payload.Port, DefaultHolePunchTimeout,
		)
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("hole punch: %v", err))
			return
		}
		opts = append(opts, kamune.DialWithFunc(
			func(_ string) (kamune.Conn, error) {
				return kamune.NewConn(conn), nil
			},
		))
		params.Addr = "p2p"
	case "direct-p2p":
		conn, err := directP2PDial(params.DirectPeerAddr)
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("direct p2p dial: %v", err))
			return
		}
		opts = append(opts, kamune.DialWithFunc(
			func(_ string) (kamune.Conn, error) {
				return conn, nil
			},
		))
		params.Addr = params.DirectPeerAddr
	case "udp":
		opts = append(opts, kamune.DialWithUDP())
	default:
		opts = append(opts, kamune.DialWithTCP())
	}

	d.wg.Go(func() {
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(cmd.ID, fmt.Sprintf("goroutine panic: %v", msg))
			}
		}()

		dialer, err := kamune.NewDialer(params.Addr, store, opts...)
		if err != nil {
			d.setStatus(StatusError, "Failed to create dialer")
			d.addLogEntry("ERROR", "Failed to create dialer: "+err.Error())
			d.emitError(cmd.ID, fmt.Sprintf("create dialer: %v", err))
			return
		}

		t, err := dialer.Dial()
		if err != nil {
			d.setStatus(StatusError, "Connection failed")
			d.addLogEntry("ERROR", "Dial failed: "+err.Error())
			d.emitError(cmd.ID, fmt.Sprintf("dial: %v", err))
			return
		}

		if d.ctx.Err() != nil {
			t.Close()
			return
		}

		sessionID := t.SessionID()
		peer := t.RemotePeer()

		session := &liveSession{
			ID:               sessionID,
			PeerName:         peer.Name,
			RemoteVersion:    peer.AppVersion,
			RemoteAddr:       params.Addr,
			Transport:        t,
			Messages:         make([]MessageInfo, 0),
			LastActivity:     time.Now(),
			ReceiveDone:      make(chan struct{}),
			IsServer:         false,
			TransportType:    params.Transport,
			SessionTTL:       sessionTTL,
			SessionStartedAt: time.Now(),
			pongCh:           make(chan []byte, 1),
			keepAliveDone:    make(chan struct{}),
		}

		var store *storage.Storage
		if s := d.store(); s != nil && !d.incognito {
			store = s
			if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
				d.addLogEntry("WARN", "Failed to create session record: "+err.Error())
			}
			d.deriveAndStoreRelayTokens(t, sessionID)
		}

		// Store dial params for transparent resumption on involuntary
		// disconnect.
		reconnectCtx, reconnectCancel := context.WithCancel(d.ctx)
		session.reconnectCtx = reconnectCtx
		session.reconnectCancel = reconnectCancel
		session.reconnectFn = d.makeReconnectFn(sessionID, &params, store, opts)

		d.loadChatHistory(session)

		if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
			d.addLogEntry("WARN", msg)
			d.emit(EvtVersionWarning, "", MapA{
				"session_id": sessionID, "message": msg,
			})
		}

		d.mu.Lock()
		d.sessions[sessionID] = session
		d.mu.Unlock()

		info := d.sessionInfoLocked(session)
		d.emit(EvtSessionStarted, cmd.ID, info)

		d.setStatus(StatusConnected, "Connected to "+params.Addr)
		d.addLogEntry("INFO", "Connected to "+params.Addr+" (session: "+sessionID+")")

		go d.keepAliveLoop(session)
		d.receiveMessages(session)
		d.loadHistorySessions()
	})
}

// serverHandler handles incoming server connections.
func (d *Daemon) serverHandler(t *kamune.Transport) error {
	d.mu.RLock()
	transport := d.serverTransport
	if transport == "" {
		transport = "tcp"
	}
	relaySessionTTL := d.relaySessionTTL
	d.mu.RUnlock()

	sessionID := t.SessionID()
	peer := t.RemotePeer()

	session := &liveSession{
		ID:               sessionID,
		PeerName:         peer.Name,
		RemoteVersion:    peer.AppVersion,
		Transport:        t,
		Messages:         make([]MessageInfo, 0),
		LastActivity:     time.Now(),
		ReceiveDone:      make(chan struct{}),
		IsServer:         true,
		TransportType:    transport,
		SessionTTL:       relaySessionTTL,
		SessionStartedAt: time.Now(),
		pongCh:           make(chan []byte, 1),
		keepAliveDone:    make(chan struct{}),
	}

	var store *storage.Storage
	if s := d.store(); s != nil && !d.incognito {
		store = s
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			d.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
		d.deriveAndStoreRelayTokens(t, sessionID)
	}

	// Link the session ID to the consumed relay token so the
	// reconnect loop can look up stored tokens from BoltDB.
	if store != nil && transport == "relay" {
		d.mu.Lock()
		for i := range d.relayTokens {
			if d.relayTokens[i].Consumed {
				d.relayTokens[i].sessionID = sessionID
				if tt, ok := d.relayTokens[i].listener.(*tokenTracker); ok {
					tt.sessionID = sessionID
				}
				break
			}
		}
		d.mu.Unlock()
	}

	d.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		d.addLogEntry("WARN", msg)
		d.emit(EvtVersionWarning, "", MapA{
			"session_id": sessionID, "message": msg,
		})
	}

	d.mu.Lock()
	d.sessions[sessionID] = session
	d.mu.Unlock()

	info := d.sessionInfoLocked(session)
	d.emit(EvtSessionStarted, "", info)
	d.addLogEntry("INFO", "New incoming connection: "+sessionID)

	defer close(session.ReceiveDone)
	d.receiveMessagesBlocking(session)

	d.removeSession(sessionID)
	d.setStatusIfEmpty(StatusDisconnected, "Not connected")
	d.loadHistorySessions()
	d.addLogEntry("INFO", "All sessions disconnected")
	return nil
}

// handleCloseSession closes a specific session.
func (d *Daemon) handleCloseSession(cmd Command) {
	var params CloseSessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	session, ok := d.sessions[params.SessionID]
	if !ok {
		d.mu.Unlock()
		d.emitError(
			cmd.ID, fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}
	delete(d.sessions, params.SessionID)
	d.mu.Unlock()

	if err := session.Transport.Close(); err != nil {
		slog.Warn("error closing transport", slog.Any("error", err))
	}

	d.emit(EvtSessionClosed, "", d.sessionInfo(session))
	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "closed", "session_id": params.SessionID,
	})
	d.setStatusIfEmpty(StatusDisconnected, "Not connected")
}

// handleListSessions returns a list of active sessions.
func (d *Daemon) handleListSessions(cmd Command) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sessions := make([]SessionInfo, 0, len(d.sessions))
	for _, s := range d.sessions {
		sessions = append(sessions, d.sessionInfoLocked(s))
	}
	d.emit(EvtResponse, cmd.ID, MapA{"sessions": sessions})
}

// handleRenameSession renames a live session in memory.
func (d *Daemon) handleRenameSession(cmd Command) {
	var params RenameSessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	for _, s := range d.sessions {
		if s.ID == params.SessionID {
			s.PeerName = params.Name
			break
		}
	}
	d.mu.Unlock()

	d.emit(EvtSessionUpdated, "", MapS{"session_id": params.SessionID})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "ok"})
}

// handleGenerateP2PToken creates a new p2p token for the running server.
func (d *Daemon) handleGenerateP2PToken(cmd Command) {
	var params struct {
		BrokerAddr string `json:"broker_addr"`
		PeerPubB64 string `json:"peer_pub_b64,omitempty"`
	}
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	if d.brokerClient == nil {
		d.mu.Lock()
		bc, err := NewBrokerClient()
		if err != nil {
			d.mu.Unlock()
			d.emitError(cmd.ID, fmt.Sprintf("broker client: %v", err))
			return
		}
		d.brokerClient = bc
		d.mu.Unlock()
	}

	tokenHex, err := d.GenerateP2PToken(params.BrokerAddr, params.PeerPubB64)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("generate p2p token: %v", err))
		return
	}
	d.emit(EvtResponse, cmd.ID, MapA{
		"token": tokenHex, "broker_addr": params.BrokerAddr,
		"peer_pub_b64": params.PeerPubB64,
	})
}

// handleRemoveP2PToken removes an active p2p token.
func (d *Daemon) handleRemoveP2PToken(cmd Command) {
	var params struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}
	if err := d.RemoveP2PToken(params.Token); err != nil {
		d.emitError(cmd.ID, err.Error())
		return
	}
	d.emit(EvtResponse, cmd.ID, MapS{"status": "removed"})
}

// handleListP2PTokens returns all active p2p tokens.
func (d *Daemon) handleListP2PTokens(cmd Command) {
	tokens := d.GetP2PTokens()
	d.emit(EvtResponse, cmd.ID, MapA{"tokens": tokens})
}

// deriveAndStoreRelayTokens performs an ECDH exchange over the transport to
// derive relay reconnect tokens and stores them in the session's meta bucket
// (mirrors cmd/bus/network.go:924-945).
func (d *Daemon) deriveAndStoreRelayTokens(t *kamune.Transport, sessionID string) {
	tokens, err := relayconn.DeriveRelayTokens(t)
	if err != nil {
		d.addLogEntry("WARN", "Failed to derive relay tokens: "+err.Error())
		return
	}
	slices := make([][]byte, len(tokens))
	for i := range tokens {
		slices[i] = tokens[i][:]
	}
	store := d.store()
	if store == nil {
		return
	}
	if err := store.SetMeta(sessionID,
		storage.NewByteSlicesMeta(storage.RelayTokensKey, slices),
	); err != nil {
		d.addLogEntry("WARN", "Failed to store relay tokens: "+err.Error())
	}
}

// deriveAndStoreRelayTokensForPeers derives relay tokens for existing sessions
// using static peer keys and stores them.
func (d *Daemon) deriveAndStoreRelayTokensForPeers(peerPubB64 ...string) error {
	store := d.store()
	if store == nil {
		return errors.New("storage is not available")
	}
	myPubPKIX, err := store.PublicKey()
	if err != nil {
		return fmt.Errorf("get identity: %w", err)
	}
	myPubB64 := fingerprint.Base64(myPubPKIX)
	myPubRaw, err := parsePeerPubB64ToRaw(myPubB64)
	if err != nil {
		return fmt.Errorf("parse local key: %w", err)
	}
	for _, pubB64 := range peerPubB64 {
		if pubB64 == "" {
			continue
		}
		peerPubRaw, err := parsePeerPubB64ToRaw(pubB64)
		if err != nil {
			d.addLogEntry("WARN", "Skipping peer (bad key): "+err.Error())
			continue
		}
		t, err := relayconn.TokenFromKeys(myPubRaw, peerPubRaw)
		if err != nil {
			d.addLogEntry("WARN",
				"Derive token for "+pubB64+": "+err.Error())
			continue
		}
		pubPKIX, err := decodePeerPubKey(pubB64)
		if err != nil {
			d.addLogEntry("WARN", "Skipping peer (bad key): "+err.Error())
			continue
		}
		sessionID, err := store.FindSessionByPeer(pubPKIX)
		if err != nil {
			d.addLogEntry("WARN",
				"Find session for peer: "+err.Error())
			continue
		}
		if sessionID == "" {
			continue
		}
		existing, err := store.GetMeta(sessionID, storage.RelayTokensKey)
		if err != nil || existing.Value() == nil {
			d.addLogEntry("INFO",
				"Storing derived relay token for session: "+sessionID)
			if err := store.SetMeta(
				sessionID,
				storage.NewByteSlicesMeta(storage.RelayTokensKey, [][]byte{t}),
			); err != nil {
				d.addLogEntry("WARN",
					"Store token for "+sessionID+": "+err.Error())
			}
		}
	}
	return nil
}

// makeReconnectFn returns a reconnect function that re-dials with resumption
// tokens, trying stored ECDH tokens for relay connections (mirrors
// cmd/bus/network.go:687-723).
func (d *Daemon) makeReconnectFn(sessionID string, params *DialParams, store *storage.Storage, opts []kamune.DialOption) func(string) (*kamune.Transport, error) {
	addr := params.Addr
	relayAddr := params.RelayAddr
	password := params.Password
	return func(sessionID string) (*kamune.Transport, error) {
		resumeOpts := append(
			[]kamune.DialOption{kamune.DialWithResume(sessionID)}, opts...,
		)
		if store != nil && relayAddr != "" {
			if m, err := store.GetMeta(
				sessionID, storage.RelayTokensKey,
			); err == nil && m.Value() != nil {
				if tokens := decodeTokenList(m.Value()); len(tokens) > 1 {
					fn, err := dialRelayFuncMultiToken(
						relayAddr, password, false, tokens,
					)
					if err == nil {
						resumeOpts = append(
							resumeOpts, kamune.DialWithFunc(fn),
						)
					}
				}
			}
		}
		dl, err := kamune.NewDialer(addr, store, resumeOpts...)
		if err != nil {
			return nil, err
		}
		t, err := dl.Dial()
		if err != nil {
			return nil, err
		}
		d.deriveAndStoreRelayTokens(t, sessionID)
		return t, nil
	}
}

// relayReconnectLoop monitors the relay listener for death and automatically
// re-registers with the next available token from the stored pool (mirrors
// cmd/bus/relay.go:299-442).
func (d *Daemon) relayReconnectLoop(ctx context.Context, ml *multiListener) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 5 * time.Second
	)

	d.mu.RLock()
	var currentDead <-chan struct{}
	var sessionID string
	for i := len(d.relayTokens) - 1; i >= 0; i-- {
		if tt, ok := d.relayTokens[i].listener.(*tokenTracker); ok {
			currentDead = tt.Dead()
			sessionID = tt.sessionID
			break
		}
	}
	d.mu.RUnlock()

	if currentDead == nil {
		slog.Warn("relay reconnect: no tracker found")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-currentDead:
		}

		jitter := time.Duration(rand.Int63n(int64(maxBackoff - minBackoff)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(minBackoff + jitter):
		}

		d.mu.RLock()
		server := d.server
		d.mu.RUnlock()
		if server == nil {
			return
		}

		st := d.store()
		if st == nil {
			return
		}
		m, err := st.GetMeta(sessionID, storage.RelayTokensKey)
		if err != nil || m.Value() == nil {
			slog.Warn("relay reconnect: no stored tokens, cold start required", "session", sessionID)
			return
		}
		tokens := decodeTokenList(m.Value())
		if len(tokens) == 0 {
			slog.Warn("relay reconnect: empty token pool, cold start required", "session", sessionID)
			return
		}

		d.mu.RLock()
		relayAddr := d.relayAddr
		password := d.relayPassword
		d.mu.RUnlock()

		var registered bool
		for _, token := range tokens {
			listener, tokenHex, ttl, sessTTL, listenErr :=
				listenRelayTracked(ctx, d, relayAddr, password, false, token)
			if listenErr != nil {
				slog.Warn("relay reconnect: attempt failed", "err", listenErr)
				continue
			}
			if addErr := ml.Add(listener); addErr != nil {
				listener.Close()
				slog.Warn("relay reconnect: add to multi-listener failed", "err", addErr)
				continue
			}
			d.mu.Lock()
			d.relayTokens = append(d.relayTokens, relayToken{
				Token: tokenHex, TTL: ttl, SessionTTL: sessTTL,
				ExpiresAt: time.Now().Add(ttl), Mode: "ecdh",
				sessionID: sessionID, listener: listener,
			})
			d.mu.Unlock()
			slog.Info("relay reconnect: listener re-registered", "token_prefix", tokenHex[:8])
			if tt, ok := listener.(*tokenTracker); ok {
				currentDead = tt.Dead()
				tt.sessionID = sessionID
			}
			registered = true
			break
		}

		if !registered {
			slog.Warn("relay reconnect: all tokens exhausted, cold start required", "session", sessionID, "pool_size", len(tokens))
			return
		}
	}
}

// handleGenerateRelayToken creates a new relay token for the running server.
// When peer_pub_b64 is provided, it derives a deterministic (static) token
// using ECDH (mirrors cmd/bus/network.go:427-466).
func (d *Daemon) handleGenerateRelayToken(cmd Command) {
	var params struct {
		PeerPubB64 string `json:"peer_pub_b64,omitempty"`
	}
	if cmd.Params != nil {
		_ = json.Unmarshal(cmd.Params, &params)
	}

	d.mu.Lock()
	if d.relayListeners == nil {
		d.mu.Unlock()
		d.emitError(cmd.ID, "relay is not configured — start a relay server first")
		return
	}
	relayAddr := d.relayAddr
	relayPassword := d.relayPassword
	d.mu.Unlock()

	var staticToken []byte
	relayMode := "random"
	if params.PeerPubB64 != "" {
		tok, err := d.deriveP2PToken(params.PeerPubB64)
		if err == nil {
			staticToken = tok
			relayMode = "static"
		}
	}

	listener, token, ttl, sessionTTL, err := listenRelayTracked(
		context.Background(), d, relayAddr, relayPassword, false, staticToken,
	)
	if err != nil {
		d.emitError(cmd.ID, err.Error())
		return
	}

	d.mu.Lock()
	if d.relayListeners == nil {
		d.mu.Unlock()
		listener.Close()
		d.emitError(cmd.ID, "server stopped while generating token")
		return
	}
	if err := d.relayListeners.Add(listener); err != nil {
		d.mu.Unlock()
		d.emitError(cmd.ID, fmt.Sprintf("add listener: %v", err))
		return
	}
	d.relayTokens = append(d.relayTokens, relayToken{
		Token: token, TTL: ttl, SessionTTL: sessionTTL,
		ExpiresAt: time.Now().Add(ttl), Mode: relayMode,
		listener: listener,
	})
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.Unlock()

	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
	d.addLogEntry("INFO", "Generated relay token: "+token)
	d.emit(EvtResponse, cmd.ID, MapA{
		"token": token, "ttl_ns": ttl, "session_ttl_ns": sessionTTL,
		"expires_at": time.Now().Add(ttl),
	})
}

// handleRemoveRelayToken removes an active relay token.
func (d *Daemon) handleRemoveRelayToken(cmd Command) {
	var params RemoveRelayTokenParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	idx := -1
	for i, t := range d.relayTokens {
		if t.Token == params.Token {
			idx = i
			break
		}
	}
	if idx == -1 {
		d.mu.Unlock()
		d.emitError(cmd.ID, "token not found")
		return
	}
	rt := d.relayTokens[idx]
	d.relayTokens = append(d.relayTokens[:idx], d.relayTokens[idx+1:]...)
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.Unlock()

	rt.listener.Close()

	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
	d.addLogEntry("INFO", "Removed relay token: "+params.Token)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "removed"})
}

// handleListRelayTokens returns all active relay tokens.
func (d *Daemon) handleListRelayTokens(cmd Command) {
	d.mu.RLock()
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.RUnlock()
	d.emit(EvtResponse, cmd.ID, MapA{"tokens": tokens})
}

// handleGetShareInfo returns a share card for the running server.
func (d *Daemon) handleGetShareInfo(cmd Command) {
	d.mu.RLock()
	if d.server == nil {
		d.mu.RUnlock()
		d.emitError(cmd.ID, "server is not running")
		return
	}
	transport := d.serverTransport
	serverAddr := d.serverAddr
	pubKey := d.pubKey
	relayAddr := d.relayAddr
	relayPassword := d.relayPassword
	d.mu.RUnlock()

	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	hexFP := fingerprint.Hex(pubKey)

	var (
		address   string
		port      string
		relayInfo *relayShareInfo
		urlStr    string
	)

	switch transport {
	case "tcp", "udp", "":
		host, p, autoDetect := parseServerAddr(serverAddr)
		port = p
		if autoDetect {
			ip, err := detectLocalIP()
			if err != nil {
				d.emitError(cmd.ID, fmt.Sprintf("detect local IP: %v", err))
				return
			}
			address = ip
		} else {
			address = host
		}
		scheme := transport
		if scheme == "" {
			scheme = "tcp"
		}
		urlStr = fmt.Sprintf("%s://%s:%s", scheme, address, port)
	case "relay":
		listener, token, ttl, sessionTTL, err := listenRelayTracked(
			context.Background(), d, relayAddr, relayPassword, false, nil,
		)
		if err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("generate relay token: %v", err))
			return
		}

		d.mu.Lock()
		if d.relayListeners == nil {
			d.mu.Unlock()
			listener.Close()
			d.emitError(cmd.ID, "server stopped while generating token")
			return
		}
		if err := d.relayListeners.Add(listener); err != nil {
			d.mu.Unlock()
			listener.Close()
			d.emitError(cmd.ID, fmt.Sprintf("add listener: %v", err))
			return
		}
		d.relayTokens = append(d.relayTokens, relayToken{
			Token: token, TTL: ttl, SessionTTL: sessionTTL,
			ExpiresAt: time.Now().Add(ttl), listener: listener,
		})
		tokens := make([]relayToken, len(d.relayTokens))
		copy(tokens, d.relayTokens)
		d.mu.Unlock()

		d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
		d.addLogEntry("INFO", "Share card: generated relay token: "+token)

		scheme, host, _ := parseRelayAddr(relayAddr)
		relayInfo = &relayShareInfo{
			Address: host, Scheme: scheme, Token: token,
			Password: relayPassword != "",
		}
		urlStr = fmt.Sprintf("relay://%s?token=%s&scheme=%s", host, token, scheme)
		if relayPassword != "" {
			urlStr += "&password=1"
		}
	default:
		d.emitError(cmd.ID, fmt.Sprintf("unknown transport: %s", transport))
		return
	}

	d.emit(EvtResponse, cmd.ID, MapA{
		"url":               urlStr,
		"transport":         transport,
		"address":           address,
		"port":              port,
		"fingerprint_emoji": emoji,
		"fingerprint_hex":   hexFP,
		"relay_info":        relayInfo,
	})
}

// loadChatHistory pre-populates session.Messages from the store.
func (d *Daemon) loadChatHistory(session *liveSession) {
	if d.incognito {
		return
	}
	store := d.store()
	if store == nil {
		return
	}

	entries, err := store.GetChatHistory(session.ID)
	if err != nil {
		d.addLogEntry("DEBUG", "No history for session: "+session.ID)
		return
	}

	d.mu.Lock()
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
	d.mu.Unlock()
}

// removeSession removes a session from the map and returns the remaining
// session count.
func (d *Daemon) removeSession(sessionID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, sessionID)
	return len(d.sessions)
}

// sessionInfo returns a SessionInfo for a live session (caller does not hold lock).
func (d *Daemon) sessionInfo(s *liveSession) SessionInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sessionInfoLocked(s)
}

// sessionInfoLocked returns a SessionInfo; caller must hold d.mu.
func (d *Daemon) sessionInfoLocked(s *liveSession) SessionInfo {
	return SessionInfo{
		SessionID:        s.ID,
		PeerName:         s.PeerName,
		IsServer:         s.IsServer,
		MsgCount:         len(s.Messages),
		LastActivity:     s.LastActivity,
		TransportType:    s.TransportType,
		RemoteVersion:    s.RemoteVersion,
		SessionTTL:       s.SessionTTL,
		SessionStartedAt: s.SessionStartedAt,
		RemoteAddr:       s.RemoteAddr,
	}
}

// setStatusIfEmpty sets the status only if there are no live sessions.
func (d *Daemon) setStatusIfEmpty(status ConnectionStatus, msg string) {
	d.mu.RLock()
	count := len(d.sessions)
	d.mu.RUnlock()
	if count == 0 {
		d.setStatus(status, msg)
	}
}

// markRelayTokenConsumed flips the consumed flag and schedules removal after
// a brief grace period. The full bus implementation.
func (d *Daemon) markRelayTokenConsumed(token string) {
	d.mu.Lock()
	for i := range d.relayTokens {
		if d.relayTokens[i].Token == token && !d.relayTokens[i].Consumed {
			d.relayTokens[i].Consumed = true
			break
		}
	}
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.Unlock()
	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})

	go func() {
		time.Sleep(4 * time.Second)
		d.mu.Lock()
		idx := -1
		for i, t := range d.relayTokens {
			if t.Token == token {
				idx = i
				break
			}
		}
		if idx == -1 {
			d.mu.Unlock()
			return
		}
		rt := d.relayTokens[idx]
		d.relayTokens = append(d.relayTokens[:idx], d.relayTokens[idx+1:]...)
		tokens := make([]relayToken, len(d.relayTokens))
		copy(tokens, d.relayTokens)
		d.mu.Unlock()
		if s, ok := rt.listener.(interface{ Stop() }); ok {
			s.Stop()
		}
		d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
		d.addLogEntry("INFO", "Discarded consumed relay token")
	}()
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

// relayShareInfo is the share-info payload for relay transports.
type relayShareInfo struct {
	Address  string `json:"address"`
	Scheme   string `json:"scheme"`
	Token    string `json:"token"`
	Password bool   `json:"password"`
}

// waitOrTimeout waits for ch or returns after channelTimeout.
func waitOrTimeout[T any](ch <-chan T, label string) {
	select {
	case <-ch:
	case <-time.After(channelTimeout):
		slog.Warn("Timeout waiting for " + label)
	}
}

// mapValues returns the values of a map (helper for session iteration).
func mapValues(m map[string]*liveSession) []*liveSession {
	out := make([]*liveSession, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// mustJSON marshals v or panics. Used for internal command construction.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// checkMinorMismatch returns a warning message if the major versions match but
// minor versions differ.
func checkMinorMismatch(local, remote string) (string, bool) {
	if remote == "" {
		return "", false
	}
	lv, ok := parseVer(local)
	if !ok {
		return "", false
	}
	rv, ok := parseVer(remote)
	if !ok {
		return "", false
	}
	if lv.major == rv.major && lv.minor != rv.minor {
		return fmt.Sprintf(
			"Minor version mismatch (v%s vs v%s): things may not work as expected",
			remote, local,
		), true
	}
	return "", false
}

type ver struct {
	major, minor int
}

func parseVer(v string) (ver, bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return ver{}, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ver{}, false
	}
	return ver{major: maj, minor: min}, true
}
