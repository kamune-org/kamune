package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// hexDecodeString is a thin wrapper around encoding/hex that returns the
// raw bytes; named so callers can use it without importing encoding/hex.
func hexDecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (a *App) StartServer(
	addr, transport, relayAddr, name, password, brokerAddr, peerPubB64 string,
	useP2P bool, useBroker bool,
	directPeerAddr string,
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
	a.serverBrokerAddr = brokerAddr
	a.serverPeerPubB64 = peerPubB64
	a.serverDirectPeerAddr = directPeerAddr
	a.serverUseP2P = useP2P
	a.serverUseBroker = useBroker
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

	if name == "" || a.incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			return "", "", fmt.Errorf("getting identity: %w", err)
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	// P2P modes: default to ":0" (random port) when no address given.
	// The dialer discovers the port out-of-band (direct) or via broker.
	if transport == "udp" && useP2P && addr == "" {
		addr = ":0"
	}

	a.mu.Lock()
	a.myName = name
	a.mu.Unlock()
	if !a.incognito {
		_ = store.SetSettings("bus", "local_name", name)
	}

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
		relayStaticToken, _ := a.deriveP2PToken(peerPubB64)
		relayMode := "random"
		if len(relayStaticToken) > 0 {
			relayMode = "static"
		}
		listener, token, ttl, sessionTTL, err := listenRelayTracked(context.Background(), a, relayAddr, password, false, relayStaticToken)
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
		a.relaySessionTTL = sessionTTL
		a.relayListeners = ml
		a.relayTokens = []relayToken{{Token: token, TTL: ttl, SessionTTL: sessionTTL, ExpiresAt: time.Now().Add(ttl), Mode: relayMode, PeerPubB64: peerPubB64, listener: listener}}
	case "udp":
		if useP2P && useBroker && brokerAddr != "" {
			// P2P mode: build a p2pListener that registers on the
			// broker and yields punched KCP sessions. The
			// p2pListener owns the punch socket and the kcp-go
			// listener; we just hand it to the kamune server.
			token, err := a.deriveP2PToken(peerPubB64)
			if err != nil {
				a.setStatus(StatusError, "Failed to derive p2p token")
				a.addLogEntry("ERROR",
					"Failed to derive p2p token: "+err.Error())
				return "", "", fmt.Errorf("derive p2p token: %w", err)
			}
			listener, err := newP2PListener(
				a.brokerClient, brokerAddr, token, addr,
			)
			if err != nil {
				a.setStatus(StatusError, "Failed to start p2p listener")
				a.addLogEntry("ERROR",
					"p2p listener failed: "+err.Error())
				return "", "", fmt.Errorf("p2p listener: %w", err)
			}
			ml := newMultiListener()
			if err := ml.Add(listener); err != nil {
				_ = listener.Close()
				return "", "", fmt.Errorf("add p2p listener: %w", err)
			}
			a.p2pListener = listener
			opts = append(opts, kamune.ServeWithListener(ml))

			// Register the p2pListener's token in a.p2pTokens so the
			// sidebar can display it. The token was either precomputed
			// (static mode) or captured from the broker (random mode).
			ptCtx, ptCancel := context.WithCancel(context.Background())
			mode := "random"
			if peerPubB64 != "" {
				mode = "static"
			}
			a.mu.Lock()
			a.p2pTokens = append(a.p2pTokens, p2pToken{
				Token:      listener.Token(),
				Mode:       mode,
				PeerPubB64: peerPubB64,
				Consumed:   false,
				TTL:        p2pTokenRefreshInterval,
				ExpiresAt:  time.Now().Add(p2pTokenRefreshInterval),
				brokerAddr: brokerAddr,
				ctx:        ptCtx,
				cancel:     ptCancel,
			})
			snapshot := a.p2pTokensSnapshot()
			a.mu.Unlock()
			a.emitEvent("p2p-tokens", snapshot)
		} else if useP2P && directPeerAddr != "" {
			// Direct P2P: both peers know each other's addresses
			// upfront. The listener sends NAT-kick packets to the
			// dialer and waits for its KCP SYN on the punch socket.
			listener, err := newDirectP2PListener(addr, directPeerAddr)
			if err != nil {
				a.setStatus(StatusError, "Failed to start direct p2p listener")
				a.addLogEntry("ERROR",
					"direct p2p listener failed: "+err.Error())
				return "", "", fmt.Errorf("direct p2p listener: %w", err)
			}
			ml := newMultiListener()
			if err := ml.Add(listener); err != nil {
				_ = listener.Close()
				return "", "", fmt.Errorf("add direct p2p listener: %w", err)
			}
			a.p2pListener = listener
			opts = append(opts, kamune.ServeWithListener(ml))
		} else {
			opts = append(opts, kamune.ServeWithUDP())
		}
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
	if transport == "udp" && useP2P {
		a.serverTransportType = "p2p"
	} else {
		a.serverTransportType = transport
	}
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "fingerprint-changed", emoji, b64, hex, sum)
	serverLabel := transport
	if transport == "udp" && useP2P {
		serverLabel = "p2p"
	}
	runtime.EventsEmit(a.ctx, "server-running", true, serverLabel)

	// Auto-register a P2P token on the broker for broker-synced mode.
	// When p2pListener is active it already registered, so skip.
	if transport == "udp" && a.serverUseP2P && a.serverUseBroker &&
		a.serverBrokerAddr != "" && a.p2pListener == nil {
		if _, err := a.GenerateP2PToken(
			a.serverBrokerAddr, a.serverPeerPubB64); err != nil {
			a.addLogEntry("ERROR",
				"Failed to register p2p token: "+err.Error())
		}
	}

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
		p2pL := a.p2pListener
		a.p2pListener = nil
		a.server = nil
		a.serverTransportType = ""
		a.serverBrokerAddr = ""
		a.serverPeerPubB64 = ""
		a.serverDirectPeerAddr = ""
		a.serverUseP2P = false
		a.serverUseBroker = false
		p2pToCancel := a.p2pTokens
		a.p2pTokens = make([]p2pToken, 0)
		a.mu.Unlock()
		if p2pL != nil {
			_ = p2pL.Close()
		}
		for _, pt := range p2pToCancel {
			pt.cancel()
		}
		a.emitEvent("p2p-tokens", []p2pToken{})
		stopLabel := a.serverTransportType
		runtime.EventsEmit(a.ctx, "server-running", false, stopLabel)
		a.setStatus(StatusDisconnected, "Server stopped")
		a.addLogEntry("INFO", "Server stopped")
	}()

	var statusMsg string
	switch {
	case transport == "relay":
		statusMsg = "Server (relay) — connected to " + relayAddr
	case transport == "udp" && a.p2pListener != nil:
		statusMsg = "Server (udp+p2p) — listening on " +
			a.p2pListener.Addr().String()
	default:
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
	brokerAddr := a.serverBrokerAddr
	peerPubB64 := a.serverPeerPubB64
	directPeerAddr := a.serverDirectPeerAddr
	useP2P := a.serverUseP2P
	useBroker := a.serverUseBroker
	a.mu.RUnlock()

	a.addLogEntry("INFO", "Restarting server to apply verification mode change")

	if err := a.StopServer(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	_, _, err := a.StartServer(addr, transport, relayAddr, name, password, brokerAddr, peerPubB64, useP2P, useBroker, directPeerAddr)
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

func (a *App) GenerateRelayToken(peerPubB64 string) (string, error) {
	a.mu.Lock()
	if a.relayListeners == nil {
		a.mu.Unlock()
		return "", fmt.Errorf("relay is not configured — start a relay server first")
	}
	relayAddr := a.relayAddr
	password := a.relayPassword
	a.mu.Unlock()

	staticToken, _ := a.deriveP2PToken(peerPubB64)
	listener, token, ttl, sessionTTL, err := listenRelayTracked(context.Background(), a, relayAddr, password, false, staticToken)
	if err != nil {
		return "", err
	}

	relayMode := "random"
	if len(staticToken) > 0 {
		relayMode = "static"
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
	a.relayTokens = append(a.relayTokens, relayToken{Token: token, TTL: ttl, SessionTTL: sessionTTL, ExpiresAt: time.Now().Add(ttl), Mode: relayMode, PeerPubB64: peerPubB64, listener: listener})
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
	addr, transport, relayAddr, token, name, password,
	brokerAddr, peerPubB64, p2pToken string,
	useP2P bool, useBroker bool,
) (ConnectResult, error) {
	a.setStatus(StatusConnecting, "Connecting to "+addr+"...")

	store := a.store()
	if store == nil {
		return ConnectResult{ErrorCode: "storage_unavailable"},
			fmt.Errorf("storage is not available")
	}

	var opts []kamune.DialOption
	opts = append(opts, kamune.DialWithRemoteVerifier(a.getVerifier()))

	// P2P: hole-punch the peer via the broker, then run the kamune
	// handshake on the punched KCP session. The dialer opens a single
	// punch socket that's used for both the broker REGISTER/NOTIFY
	// exchange and the KCP session — the broker sends NOTIFYs to the
	// same port the peer will punch to, so NAT mappings line up.
	if transport == "udp" && useP2P && useBroker {
		if peerPubB64 == "" && p2pToken == "" {
			return ConnectResult{ErrorCode: "missing_peer_or_token"},
				fmt.Errorf(
					"P2P via broker requires either a known peer or a shared token")
		}

		token, err := a.resolveP2PDialerToken(peerPubB64, p2pToken)
		if err != nil {
			return ConnectResult{ErrorCode: "invalid_token"}, err
		}

		baseCtx := a.ctx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		matchCtx, matchCancel := context.WithTimeout(
			baseCtx, 30*time.Second,
		)
		punchConn, payload, err := a.brokerClient.WaitMatch(
			matchCtx, brokerAddr, token,
		)
		matchCancel()
		if err != nil {
			return ConnectResult{ErrorCode: "match_timeout"},
				fmt.Errorf("wait for match: %w", err)
		}
		a.addLogEntry("INFO",
			"P2P match: peer at "+payload.IP.String()+
				fmt.Sprintf(":%d", payload.Port))

		kcpSess, err := a.brokerClient.HolePunch(
			baseCtx, punchConn,
			payload.IP, payload.Port, 0,
		)
		if err != nil {
			punchConn.Close()
			return ConnectResult{ErrorCode: "hole_punch_failed"},
				fmt.Errorf("hole-punch: %w", err)
		}
		a.addLogEntry("INFO", "Hole-punch succeeded")

		// Wrap the KCP session in a kamune.Conn and pass it to
		// NewDialer via DialWithFunc. The kamune handshake runs on
		// the punched UDP socket.
		punchedConn := kamune.NewConn(kcpSess)
		opts = append(opts, kamune.DialWithFunc(
			func(string) (kamune.Conn, error) {
				return punchedConn, nil
			},
		))
		addr = "p2p://" + payload.IP.String() +
			fmt.Sprintf(":%d", payload.Port)
	} else if transport == "udp" && useP2P && addr != "" {
		// Direct P2P: both peers know each other's addresses upfront.
		// Send NAT-kick packets to the server and create a KCP
		// session on the punched socket.
		a.addLogEntry("INFO",
			"Direct P2P: punching "+addr)
		punchedConn, err := directP2PDial(addr)
		if err != nil {
			return ConnectResult{ErrorCode: "hole_punch_failed"},
				fmt.Errorf("direct p2p dial: %w", err)
		}
		a.addLogEntry("INFO", "Direct P2P: hole-punch succeeded")
		opts = append(opts, kamune.DialWithFunc(
			func(string) (kamune.Conn, error) {
				return punchedConn, nil
			},
		))
		addr = "p2p://" + addr
	} else if name == "" || a.incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			return ConnectResult{ErrorCode: "identity_unavailable"},
				fmt.Errorf("getting identity: %w", err)
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	a.mu.Lock()
	a.myName = name
	a.mu.Unlock()
	if !a.incognito {
		_ = store.SetSettings("bus", "local_name", name)
	}

	opts = append(opts, kamune.DialWithClientName(name))

	var sessionTTL time.Duration
	if !(transport == "udp" && useP2P) {
		switch transport {
		case "relay":
			relayTokenHex := token
			if peerPubB64 != "" {
				staticTokenRaw, err := a.deriveP2PToken(peerPubB64)
				if err != nil {
					return ConnectResult{ErrorCode: "invalid_peer_key"},
						fmt.Errorf("derive static token: %w", err)
				}
				relayTokenHex = hex.EncodeToString(staticTokenRaw)
			}
			fn, err := dialRelayFuncWithSessionTTL(
				relayAddr, relayTokenHex, password, false, &sessionTTL,
			)
			if err != nil {
				a.setStatus(StatusError, "Failed to prepare relay dial")
				a.addLogEntry("ERROR",
					"Relay dial preparation failed: "+err.Error())
				return ConnectResult{ErrorCode: "relay_dial_failed"},
					fmt.Errorf("relay dial func: %w", err)
			}
			opts = append(opts, kamune.DialWithFunc(fn))
			addr = relayAddr
		case "udp":
			opts = append(opts, kamune.DialWithUDP())
		default:
			opts = append(opts, kamune.DialWithTCP())
		}
	}

	dialer, err := kamune.NewDialer(addr, store, opts...)
	if err != nil {
		a.setStatus(StatusError, "Failed to create dialer")
		a.addLogEntry("ERROR", "Failed to create dialer: "+err.Error())
		return ConnectResult{ErrorCode: "dialer_init_failed"},
			fmt.Errorf("create dialer: %w", err)
	}

	t, err := dialer.Dial()
	if err != nil {
		a.setStatus(StatusError, "Connection failed")
		a.addLogEntry("ERROR", "Dial failed: "+err.Error())
		return ConnectResult{ErrorCode: "dial_failed"},
			fmt.Errorf("dial: %w", err)
	}

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
		TransportType:    transportTypeFor(transport, useP2P),
		SessionTTL:       sessionTTL,
		SessionStartedAt: time.Now(),
		pongCh:           make(chan []byte, 1),
		keepAliveDone:    make(chan struct{}),
	}

	if store := a.store(); store != nil && !a.incognito {
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			a.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
	}

	// Store dial params for transparent resumption on involuntary
	// disconnect.
	reconnectCtx, reconnectCancel := context.WithCancel(a.ctx)
	session.reconnectCtx = reconnectCtx
	session.reconnectCancel = reconnectCancel
	session.reconnectFn = func(sessionID string) (*kamune.Transport, error) {
		resumeOpts := append(
			[]kamune.DialOption{kamune.DialWithResume(sessionID)}, opts...,
		)
		d, err := kamune.NewDialer(addr, store, resumeOpts...)
		if err != nil {
			return nil, err
		}
		return d.Dial()
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
		ID:               session.ID,
		PeerName:         session.PeerName,
		IsServer:         false,
		MsgCount:         len(session.Messages),
		LastActivity:     session.LastActivity,
		TransportType:    session.TransportType,
		RemoteVersion:    peer.AppVersion,
		SessionTTL:       sessionTTL,
		SessionStartedAt: time.Now(),
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)

	a.setStatus(StatusConnected, "Connected to "+addr)
	a.addLogEntry("INFO", "Connected | addr="+addr+" session_id="+sessionID)

	go a.receiveMessages(session)
	go a.keepAliveLoop(session)

	return ConnectResult{SessionID: sessionID}, nil
}

// transportTypeFor returns the label used for SessionInfo.TransportType.
// P2P sessions are labeled "p2p" so the sidebar can render a distinct
// badge even when the underlying transport is UDP.
func transportTypeFor(transport string, useP2P bool) string {
	if transport == "udp" && useP2P {
		return "p2p"
	}
	return transport
}

// resolveP2PDialerToken returns the broker registration token for the
// dialer: the static token derived from the peer's public key (when
// peerPubB64 is set), or the user-shared random token (tokenHex).
// Exactly one of the two must be non-empty; supplying both is an error.
func (a *App) resolveP2PDialerToken(peerPubB64, tokenHex string) ([]byte, error) {
	if peerPubB64 != "" && tokenHex != "" {
		return nil, fmt.Errorf(
			"peer and token are mutually exclusive")
	}
	if peerPubB64 != "" {
		return a.deriveP2PToken(peerPubB64)
	}
	if tokenHex == "" {
		return nil, fmt.Errorf(
			"either a peer or a token is required")
	}
	raw, err := hexDecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	return raw, nil
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

	// Invalidate resumption tokens so this explicitly closed
	// session cannot be resumed later.
	if store := a.store(); store != nil {
		if err := store.StoreResumptionTokens(sessionID, nil); err != nil {
			a.addLogEntry("WARN", "Failed to clear resumption tokens: "+err.Error())
		}
	}

	// Cancel any active reconnect loop.
	if session.reconnectCancel != nil {
		session.reconnectCancel()
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

	a.mu.RLock()
	relaySessionTTL := a.relaySessionTTL
	a.mu.RUnlock()

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

	if store := a.store(); store != nil && !a.incognito {
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			a.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
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
		ID:               session.ID,
		PeerName:         session.PeerName,
		IsServer:         true,
		MsgCount:         len(session.Messages),
		LastActivity:     session.LastActivity,
		TransportType:    session.TransportType,
		RemoteVersion:    peer.AppVersion,
		SessionTTL:       relaySessionTTL,
		SessionStartedAt: time.Now(),
	}
	runtime.EventsEmit(a.ctx, "session-new", info)
	runtime.EventsEmit(a.ctx, "session-messages", session.ID, session.Messages)
	a.addLogEntry("INFO", "New incoming connection: "+sessionID)

	go a.keepAliveLoop(session)
	a.receiveMessages(session)
	return nil
}

func (a *App) loadChatHistory(session *liveSession) {
	if a.incognito {
		return
	}
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
		listener, token, ttl, sessionTTL, err := listenRelayTracked(context.Background(), a, relayAddr, relayPassword, false, nil)
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
		a.relayTokens = append(a.relayTokens, relayToken{Token: token, TTL: ttl, SessionTTL: sessionTTL, ExpiresAt: time.Now().Add(ttl), Mode: "random", listener: listener})
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
