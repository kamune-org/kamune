package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// hexDecodeString is a thin wrapper around encoding/hex that returns the
// raw bytes; named so callers can use it without importing encoding/hex.
func hexDecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// ErrServerStarting is returned by StartServer while another start is in
// progress, even one that CancelStartServer has cancelled but that has
// not returned yet.
var ErrServerStarting = errors.New("a server is already starting")

// ErrStartCancelled is returned by StartServer when CancelStartServer
// cancelled the start before the server was up.
var ErrStartCancelled = errors.New("the server start was cancelled")

// StartServer starts the server. Only one start may run at a time.
// CancelStartServer ends the wait for the relay, and a start cancelled
// before the server is up closes what it set up and returns
// ErrStartCancelled.
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
	if a.starting > 0 {
		a.mu.Unlock()
		return "", "", ErrServerStarting
	}
	// The server and its listeners keep the store, so the database must
	// not change until the server is in a.server or the start has failed,
	// even after CancelStartServer.
	a.starting++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.starting--
		a.mu.Unlock()
	}()

	started := false
	cancelled := false
	defer func() {
		if !started && !cancelled {
			a.setStatus(StatusError, "Failed to start server")
		}
	}()

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

	ctx, cancel := context.WithCancel(a.lifeCtx())
	a.mu.Lock()
	a.startCtx = ctx
	a.startCancel = cancel
	a.mu.Unlock()

	cleanupStart := func() {
		a.mu.Lock()
		if a.startCtx == ctx {
			a.startCancel = nil
			a.startCtx = nil
		}
		a.mu.Unlock()
		cancel()
	}
	defer cleanupStart()

	// stopCancelled closes what a cancelled start set up.
	stopCancelled := func() (string, string, error) {
		cancelled = true
		a.dropStartListeners()
		a.setStatus(StatusDisconnected, "Cancelled")
		a.addLogEntry("INFO", "Server start cancelled")
		return "", "", ErrStartCancelled
	}

	store := a.store()
	if store == nil {
		return "", "", fmt.Errorf("storage is not available")
	}

	incognito := a.GetIncognito()
	if name == "" || incognito {
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
	if !incognito {
		_ = store.SetSettings("bus", "local_name", name)
	}

	// p2pL is the P2P listener the server uses, if any.
	var p2pL p2pListenerI
	var firstToken string
	var opts []kamune.ServerOptions
	opts = append(opts, kamune.ServeWithServerName(name))

	if ctx.Err() != nil {
		return stopCancelled()
	}
	switch transport {
	case "relay":
		// A peer was chosen: a token it cannot derive must not be
		// replaced by a random one it never learns.
		relayStaticToken, err := a.deriveP2PToken(peerPubB64)
		if err != nil {
			a.addLogEntry("ERROR",
				"Failed to derive the relay token: "+err.Error())
			return "", "", fmt.Errorf("derive static relay token: %w", err)
		}
		ml := newMultiListener()
		relayMode := "random"
		if len(relayStaticToken) > 0 {
			relayMode = "static"
		}
		// The relay registration ends with ctx, but not the listener
		// that it yields.
		listener, token, ttl, sessionTTL, err := listenRelayTracked(
			ctx, a, relayAddr, password, false, relayStaticToken,
		)
		if err != nil {
			if ctx.Err() != nil {
				return stopCancelled()
			}
			a.setStatus(StatusError, "Failed to connect to relay")
			a.addLogEntry("ERROR", "Relay listen failed: "+err.Error())
			return "", "", fmt.Errorf("relay listen: %w", err)
		}
		pinRelayListener(
			listener, staticPeerKey(peerPubB64, relayStaticToken),
		)
		if err := ml.Add(listener); err != nil {
			_ = listener.Close()
			return "", "", fmt.Errorf("add listener: %w", err)
		}
		firstToken = token
		opts = append(opts, kamune.ServeWithListener(ml))
		addr = "" // addr is unused with ServeWithListener
		a.mu.Lock()
		a.relayAddr = relayAddr
		a.relayPassword = password
		a.relaySessionTTL = sessionTTL
		a.relayListeners = ml
		a.relayResumes = new(sync.WaitGroup)
		a.relayTokens = []relayToken{{Token: token, TTL: ttl, SessionTTL: sessionTTL, ExpiresAt: time.Now().Add(ttl), Mode: relayMode, PeerPubB64: peerPubB64, listener: listener}}
		a.mu.Unlock()
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
			// A nil peer key, for a random token, opens the
			// listener to any peer.
			listener, err := newP2PListener(
				a.brokerClient, brokerAddr, token,
				staticPeerKey(peerPubB64, token), addr,
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
			p2pL = listener
			a.mu.Lock()
			a.p2pListener = listener
			a.mu.Unlock()
			opts = append(opts, kamune.ServeWithListener(ml))

			// Register the p2pListener's token in a.p2pTokens so the
			// sidebar can display it. The token was either precomputed
			// (static mode) or captured from the broker (random mode).
			mode := "random"
			if peerPubB64 != "" {
				mode = "static"
			}
			a.mu.Lock()
			a.p2pTokens = append(a.p2pTokens, p2pToken{
				Token:      listener.Token(),
				Mode:       mode,
				PeerPubB64: peerPubB64,
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
			p2pL = listener
			a.mu.Lock()
			a.p2pListener = listener
			a.mu.Unlock()
			opts = append(opts, kamune.ServeWithListener(ml))
		} else {
			opts = append(opts, kamune.ServeWithUDP())
		}
	default:
		opts = append(opts, kamune.ServeWithTCP())
	}

	if incognito {
		// Sessions of an incognito server leave no session record in
		// storage, and no session stored earlier may be resumed.
		opts = append(opts,
			kamune.ServeWithoutPersistence(),
			kamune.ServeWithResumeEnabled(false),
		)
	}

	verifMode := a.currentVerifMode()
	// The verification prompts for the server's peers close when it
	// stops.
	serverCtx, serverCancel := context.WithCancel(a.lifeCtx())
	// svr is set before ListenAndServe starts, so before any handler runs.
	var svr *kamune.Server
	handler := func(t *kamune.Transport) error {
		return a.serverHandler(svr, t)
	}
	svr, err := kamune.NewServer(
		addr, handler, store, a.verifierWithin(serverCtx, verifMode),
		opts...,
	)
	if err != nil {
		serverCancel()
		a.dropStartListeners()
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
	if ctx.Err() != nil {
		// CancelStartServer came while the listeners were set up, and
		// the user was told that the start was cancelled.
		a.mu.Unlock()
		_ = svr.Close()
		serverCancel()
		return stopCancelled()
	}
	// From here on the start cannot be cancelled.
	a.startCancel = nil
	a.startCtx = nil
	a.pubKey = pubKey
	a.server = svr
	a.serverCancel = serverCancel
	a.serverVerifMode = verifMode
	a.serverIncognito = incognito
	a.serverDone = done
	if transport == "udp" && useP2P {
		a.serverTransportType = "p2p"
	} else {
		a.serverTransportType = transport
	}
	a.mu.Unlock()

	a.emitEvent("fingerprint-changed", emoji, b64, hex, sum)
	serverLabel := transport
	if transport == "udp" && useP2P {
		serverLabel = "p2p"
	}
	a.emitEvent("server-running", true, serverLabel)

	go func() {
		defer close(done)
		err := svr.ListenAndServe()
		serverCancel()
		if err != nil {
			a.addLogEntry("ERROR", "Server stopped: "+err.Error())
		}
		a.mu.Lock()
		stopLabel := a.serverTransportType
		a.relayTokens = nil
		a.relayAddr = ""
		a.relayPassword = ""
		a.relayListeners = nil
		a.relayResumes = nil
		p2pL := a.p2pListener
		a.p2pListener = nil
		a.server = nil
		a.serverTransportType = ""
		a.serverBrokerAddr = ""
		a.serverPeerPubB64 = ""
		a.serverDirectPeerAddr = ""
		a.serverUseP2P = false
		a.serverUseBroker = false
		a.p2pTokens = make([]p2pToken, 0)
		a.mu.Unlock()
		if p2pL != nil {
			_ = p2pL.Close()
		}
		a.emitEvent("p2p-tokens", []p2pToken{})
		a.emitEvent("server-running", false, stopLabel)
		a.setStatus(StatusDisconnected, "Server stopped")
		a.addLogEntry("INFO", "Server stopped")
	}()

	var statusMsg string
	switch {
	case transport == "relay":
		statusMsg = "Server (relay) — connected to " + relayAddr
	case transport == "udp" && p2pL != nil:
		statusMsg = "Server (udp+p2p) — listening on " +
			p2pL.Addr().String()
	default:
		statusMsg = "Server running on " + addr
	}
	a.setStatus(StatusConnected, statusMsg)
	a.addLogEntry("INFO", "Server started: "+statusMsg)
	a.loadHistorySessions(store)

	if firstToken != "" {
		tokens := a.getRelayTokens()
		a.emitEvent("relay-token", firstToken)
		a.emitEvent("relay-tokens", tokens)
		a.addLogEntry("INFO", "Relay token: "+logToken(firstToken))
	}

	started = true
	return emoji, firstToken, nil
}

// dropStartListeners closes the relay and P2P listeners, and drops the
// P2P tokens, that a StartServer which then failed set up, so that they
// neither run on nor keep the database in use (see storageBusyLocked).
func (a *App) dropStartListeners() {
	a.mu.Lock()
	ml := a.relayListeners
	p2pL := a.p2pListener
	hadP2PTokens := len(a.p2pTokens) > 0
	a.relayListeners = nil
	a.relayResumes = nil
	a.relayTokens = nil
	a.relayAddr = ""
	a.relayPassword = ""
	a.p2pListener = nil
	a.p2pTokens = make([]p2pToken, 0)
	a.mu.Unlock()

	if ml != nil {
		_ = ml.Close()
	}
	if p2pL != nil {
		_ = p2pL.Close()
	}
	if hadP2PTokens {
		a.emitEvent("p2p-tokens", []p2pToken{})
	}
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

	return a.confirm("Stop Server", msg, "Stop", "Cancel")
}

func (a *App) StopServer() error {
	a.setStatus(StatusDisconnected, "Stopping server...")
	a.addLogEntry("INFO", "Stopping server...")

	var sessions []*liveSession
	var serverDone chan struct{}

	a.mu.Lock()
	if a.relayListeners != nil {
		// This also ends the relay resumes; see awaitRelayResume.
		a.relayListeners.Close()
		a.relayListeners = nil
	}
	resumes := a.relayResumes
	a.relayResumes = nil
	svr := a.server
	if svr != nil {
		svr.Close()
		a.server = nil
	}
	// This closes the verification prompts for the server's peers, so
	// that their handshakes end and none is admitted after the stop.
	if a.serverCancel != nil {
		a.serverCancel()
		a.serverCancel = nil
	}
	sessions = append([]*liveSession(nil), a.sessions...)
	a.sessions = nil
	a.relayTokens = nil
	a.relayAddr = ""
	a.relayPassword = ""
	serverDone = a.serverDone
	a.serverDone = nil
	// Closing the sessions, and the handshakes and handlers still in
	// progress, uses the database, so it stays in use until they end.
	a.closing++
	a.mu.Unlock()
	defer a.doneClosing()

	for _, s := range sessions {
		// A closed session must not reconnect.
		if s.reconnectCancel != nil {
			s.reconnectCancel()
		}
		s.mu.Lock()
		t := s.Transport
		s.mu.Unlock()
		t.Close()
		if !s.incognito {
			a.dropRelayPool(s.ID)
		}
	}
	for _, s := range sessions {
		waitOrTimeout(s.ReceiveDone, "session receive: "+s.ID)
	}

	if svr != nil {
		// Wait for the handshakes and handlers still in progress. A
		// handler that has not added its session yet drops it, since the
		// server is no longer a.server (see serverHandler).
		ctx, cancel := context.WithTimeout(
			context.Background(), channelTimeout,
		)
		if err := svr.Shutdown(ctx); err != nil {
			a.addLogEntry("WARN", "Timed out waiting for the server's "+
				"handshakes and handlers to end")
		}
		cancel()
	}
	if resumes != nil {
		// The relay resumes drop the reconnect tokens of their sessions
		// as they end. No handler starts another one now.
		resumesDone := make(chan struct{})
		go func() {
			resumes.Wait()
			close(resumesDone)
		}()
		waitOrTimeout(resumesDone, "relay resumes")
	}
	if serverDone != nil {
		waitOrTimeout(serverDone, "ListenAndServe")
	}

	return nil
}

// restartServer stops the server and starts it again with the settings
// it was started with, so that it picks up the current verification and
// incognito modes. reason ends the log line.
func (a *App) restartServer(reason string) error {
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

	a.addLogEntry("INFO", "Restarting server to "+reason)

	if err := a.StopServer(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	_, _, err := a.StartServer(addr, transport, relayAddr, name, password, brokerAddr, peerPubB64, useP2P, useBroker, directPeerAddr)
	return err
}

// CancelStartServer cancels the server start in progress, if any. A
// start that has already brought its server up is not cancelled: the
// server runs, and StopServer stops it.
func (a *App) CancelStartServer() {
	a.mu.Lock()
	cancel := a.startCancel
	a.startCancel = nil
	a.startCtx = nil
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	a.setStatus(StatusDisconnected, "Cancelled")
	a.addLogEntry("INFO", "Server start cancelled by user")
}

func (a *App) GenerateRelayToken(peerPubB64 string) (string, error) {
	target, ok := a.currentRelayTarget()
	if !ok {
		return "", fmt.Errorf("relay is not configured — start a relay server first")
	}

	staticToken, err := a.deriveP2PToken(peerPubB64)
	if err != nil {
		return "", fmt.Errorf("derive static relay token: %w", err)
	}
	relayMode := "random"
	if len(staticToken) > 0 {
		relayMode = "static"
	}
	rt, err := a.addRelayToken(
		a.lifeCtx(), target, staticToken,
		relayToken{Mode: relayMode, PeerPubB64: peerPubB64}, "",
	)
	if err != nil {
		return "", err
	}

	a.addLogEntry("INFO", "Generated relay token: "+logToken(rt.Token))
	return rt.Token, nil
}

// RemoveRelayToken takes token off the relay token list and ends its
// registration with the relay. A peer that already joined it keeps its
// session.
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
	if tt, ok := rt.listener.(*tokenTracker); ok {
		// A resume listener must not be registered again.
		tt.removed.Store(true)
	}
	a.mu.Unlock()

	// Stop rather than Close: the relay drops the token, while a peer
	// that already joined it, in the moments before a used token leaves
	// the list, keeps its session.
	if s, ok := rt.listener.(interface{ Stop() }); ok {
		s.Stop()
	} else {
		_ = rt.listener.Close()
	}

	tokens := a.getRelayTokens()
	a.emitEvent("relay-tokens", tokens)
	a.addLogEntry("INFO", "Removed relay token: "+logToken(token))
	return nil
}

func (a *App) GetRelayTokens() []relayToken {
	return a.getRelayTokens()
}

func (a *App) ConnectToServer(
	addr, transport, relayAddr, token, name, password,
	brokerAddr, peerPubB64, p2pToken string,
	useP2P bool, useBroker bool,
) (ConnectResult, error) {
	// The dialer and the session keep the store, so the database must not
	// change until the session is in a.sessions or the dial has failed.
	a.mu.Lock()
	a.dialOps++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.dialOps--
		a.mu.Unlock()
	}()

	connected := false
	defer func() {
		if !connected {
			a.setStatus(StatusError, "Connection failed")
		}
	}()

	a.setStatus(StatusConnecting, "Connecting to "+addr+"...")

	store := a.store()
	if store == nil {
		return ConnectResult{ErrorCode: "storage_unavailable"},
			fmt.Errorf("storage is not available")
	}

	incognito := a.GetIncognito()
	if name == "" || incognito {
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
	if !incognito {
		_ = store.SetSettings("bus", "local_name", name)
	}

	// A connection to a selected peer must reach that peer's key. The
	// static relay and broker tokens are derived from both public keys,
	// so anyone who knows them can answer, and a relay or broker picks
	// who does; the pin makes the handshake reject any other key.
	var wantKey []byte
	if peerPubB64 != "" {
		k, err := decodePeerPubKey(peerPubB64)
		if err != nil {
			return ConnectResult{ErrorCode: "invalid_peer_key"},
				fmt.Errorf("decode peer key: %w", err)
		}
		wantKey = k
	}

	var opts []kamune.DialOption
	opts = append(opts, kamune.DialWithClientName(name))
	if incognito {
		// An incognito session leaves no session record in storage.
		opts = append(opts, kamune.DialWithoutPersistence())
	}
	relayTokenHex := token

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

		baseCtx := a.lifeCtx()
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
	}

	var sessionTTL time.Duration
	if !(transport == "udp" && useP2P) {
		switch transport {
		case "relay":
			tok, err := a.relayDialToken(relayTokenHex, peerPubB64)
			if err != nil {
				return ConnectResult{ErrorCode: "invalid_peer_key"},
					fmt.Errorf("derive static token: %w", err)
			}
			relayTokenHex = tok
			fn, err := dialRelayFuncWithSessionTTL(
				a.lifeCtx(), relayAddr, relayTokenHex, password, false,
				&sessionTTL,
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

	verifMode := a.currentVerifMode()
	dialer, err := kamune.NewDialer(
		addr, store, a.pinPeer(wantKey, a.verifierFor(verifMode)), opts...,
	)
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
		errCode := "dial_failed"
		switch {
		case errors.Is(err, ErrPeerKeyMismatch):
			errCode = "peer_key_mismatch"
		case useP2P:
			errCode = "hole_punch_failed"
		}
		return ConnectResult{ErrorCode: errCode},
			fmt.Errorf("dial: %w", err)
	}

	sessionID := t.SessionID()
	peer := t.RemotePeer()
	a.rememberPeer(store, peer, verifMode, incognito)
	identity := a.identifyPeer(store, peer)
	session := &liveSession{
		ID:               sessionID,
		PeerName:         identity.Label,
		Identity:         identity,
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
		incognito:        incognito,
	}

	if !incognito {
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			a.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
		a.deriveAndStoreRelayTokens(t, session)
	}

	// Store dial params for transparent resumption on involuntary disconnect.
	// For broker P2P, transparent resumption is not possible because the NAT
	// mapping is gone and the remote peer is not listening on the broker.
	// An incognito session stores no resumption tokens, so it cannot be
	// resumed either.
	if !(transport == "udp" && useP2P && useBroker) && !incognito {
		reconnectCtx, reconnectCancel := context.WithCancel(a.lifeCtx())
		session.reconnectCtx = reconnectCtx
		session.reconnectCancel = reconnectCancel

		targetAddr := addr
		peerKey := peer.PublicKey
		isDirectP2P := transport == "udp" && useP2P && !useBroker
		directAddr := strings.TrimPrefix(addr, "p2p://")

		session.reconnectFn = func(sessionID string) (*kamune.Transport, error) {
			resumeOpts := append(
				[]kamune.DialOption{kamune.DialWithResume(sessionID)}, opts...,
			)

			if isDirectP2P {
				pConn, err := directP2PDial(directAddr)
				if err != nil {
					return nil, fmt.Errorf("direct p2p redial: %w", err)
				}
				resumeOpts = append(resumeOpts, kamune.DialWithFunc(
					func(string) (kamune.Conn, error) {
						return pConn, nil
					},
				))
			} else if relayAddr != "" {
				// Always replace the original dial func. It closed over
				// lifeCtx, which disconnect does not cancel. More than
				// one stored token tries the pool; otherwise the single
				// token is dialed with the session context.
				var fn func(string) (kamune.Conn, error)
				var fnErr error
				if store != nil {
					if m, err := store.GetMeta(
						sessionID, storage.RelayTokensKey,
					); err == nil && m.Value() != nil {
						if tokens := decodeTokenList(m.Value()); len(tokens) > 1 {
							fn, fnErr = dialRelayFuncMultiToken(
								reconnectCtx, relayAddr, password,
								false, tokens,
							)
						}
					}
				}
				if fn == nil && fnErr == nil {
					fn, fnErr = dialRelayFunc(
						reconnectCtx, relayAddr, relayTokenHex,
						password, false,
					)
				}
				if fnErr == nil && fn != nil {
					resumeOpts = append(
						resumeOpts, kamune.DialWithFunc(fn),
					)
				}
			}

			// A reconnect must reach the same peer.
			d, err := kamune.NewDialer(
				targetAddr, store,
				a.pinPeer(peerKey, a.getVerifier()), resumeOpts...,
			)
			if err != nil {
				return nil, err
			}
			t, err := d.Dial()
			if err != nil {
				return nil, err
			}
			// Fresh ECDH exchange over the new transport so the local
			// token pool stays in sync with the listener's.
			a.deriveAndStoreRelayTokens(t, session)
			return t, nil
		}
	}

	a.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		a.addLogEntry("WARN", msg)
		a.emitEvent("version-warning", sessionID, msg)
	}

	a.mu.Lock()
	a.sessions = append(a.sessions, session)
	info := session.info()
	a.mu.Unlock()

	a.emitEvent("session-new", info)
	a.emitEvent("session-messages", session.ID, session.Messages)

	a.setStatus(StatusConnected, "Connected to "+addr)
	a.addLogEntry("INFO", "Connected | addr="+addr+" session_id="+sessionID)

	go a.receiveMessages(session)
	go a.keepAliveLoop(session, session.keepAliveDone)

	connected = true
	return ConnectResult{SessionID: sessionID}, nil
}

// staticPeerKey returns the key of the peer a static relay or broker
// token was derived for, or nil for a random token.
func staticPeerKey(peerPubB64 string, staticToken []byte) []byte {
	if len(staticToken) == 0 {
		return nil
	}
	key, err := decodePeerPubKey(peerPubB64)
	if err != nil {
		return nil
	}
	return key
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

// relayDialToken returns the relay token that ConnectToServer dials:
// tokenHex when the user gave one, or else the static token derived for
// the peer. A peer given along with a token does not change the token,
// but ConnectToServer pins its key, so that only that peer can answer on
// the token.
func (a *App) relayDialToken(tokenHex, peerPubB64 string) (string, error) {
	if tokenHex != "" || peerPubB64 == "" {
		return tokenHex, nil
	}
	raw, err := a.deriveP2PToken(peerPubB64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
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
				// Closing the session uses the database, so it stays
				// in use until the session has ended.
				a.closing++
				break
			}
		}
	}()

	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	defer a.doneClosing()

	// Invalidate resumption tokens so this explicitly closed
	// session cannot be resumed later.
	if store := a.store(); store != nil {
		if err := store.SetMeta(sessionID,
			storage.NewByteSlicesMeta(storage.ResumptionTokensKey, nil),
		); err != nil {
			a.addLogEntry("WARN", "Failed to clear resumption tokens: "+err.Error())
		}
	}
	// Nor through the relay.
	if !session.incognito {
		a.dropRelayPool(sessionID)
	}

	// Cancel any active reconnect loop.
	if session.reconnectCancel != nil {
		session.reconnectCancel()
	}

	session.mu.Lock()
	transport := session.Transport
	session.mu.Unlock()
	transport.Close()
	waitOrTimeout(session.ReceiveDone, "DisconnectSession: "+sessionID)

	if store := a.store(); store != nil {
		a.loadHistorySessions(store)
	}

	a.emitEvent("session-closed", sessionID)
	a.addLogEntry("INFO", "Disconnected session: "+sessionID)
	return nil
}

// serverHandler runs a session that svr established. A session that
// reaches it after StopServer has taken svr out of a.server is closed,
// since StopServer has already closed the sessions it knew about and
// waits for this handler to return.
func (a *App) serverHandler(svr *kamune.Server, t *kamune.Transport) error {
	a.mu.RLock()
	current := a.server == svr
	transport := a.serverTransportType
	verifMode := a.serverVerifMode
	incognito := a.serverIncognito
	a.mu.RUnlock()
	if !current {
		return a.dropStoppedSession(t)
	}
	if transport == "" {
		transport = "tcp"
	}

	sessionID := t.SessionID()
	peer := t.RemotePeer()
	if !admittedBy(t.AcceptedMeta(), peer.PublicKey) {
		a.addLogEntry("WARN", "Rejected incoming session from "+
			a.identifyPeer(a.store(), peer).logName()+
			": the token it used was made for another peer")
		_ = t.Close()
		return ErrPeerKeyMismatch
	}
	if !admitsSession(t.AcceptedMeta(), sessionID) {
		a.addLogEntry("WARN", "Rejected incoming session from "+
			a.identifyPeer(a.store(), peer).logName()+
			": it used the relay reconnect token of another session")
		_ = t.Close()
		return ErrNotResumed
	}
	a.mu.Lock()
	stampRelaySession(t.AcceptedMeta(), sessionID)
	a.mu.Unlock()

	a.mu.RLock()
	relaySessionTTL := a.relaySessionTTL
	a.mu.RUnlock()

	store := a.store()
	a.rememberPeer(store, peer, verifMode, incognito)
	identity := a.identifyPeer(store, peer)
	session := &liveSession{
		ID:               sessionID,
		PeerName:         identity.Label,
		Identity:         identity,
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
		incognito:        incognito,
	}

	if store != nil && !incognito {
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			a.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
		a.deriveAndStoreRelayTokens(t, session)
	}

	a.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		a.addLogEntry("WARN", msg)
		a.emitEvent("version-warning", sessionID, msg)
	}

	a.mu.Lock()
	if a.server != svr {
		a.mu.Unlock()
		return a.dropStoppedSession(t)
	}
	stale := a.addServerSessionLocked(session)
	info := session.info()
	a.mu.Unlock()

	if stale != nil {
		// The old connection is gone, but the session goes on: closing
		// it must neither tell the peer nor drop the resumption tokens.
		stale.mu.Lock()
		staleTransport := stale.Transport
		stale.mu.Unlock()
		_ = staleTransport.CloseAbort()
		a.addLogEntry("INFO", "Resumed session "+sessionID+
			" on a new connection; closed its old connection")
		a.emitEvent("session-updated", sessionID)
	} else {
		a.emitEvent("session-new", info)
		a.addLogEntry("INFO", "New incoming connection: "+sessionID)
	}
	a.emitEvent("session-messages", session.ID, session.Messages)

	go a.keepAliveLoop(session, session.keepAliveDone)
	dropped, removed := a.receiveMessages(session)
	if !removed {
		// DisconnectSession or StopServer, which drop its relay reconnect
		// tokens, took it out, or a resumed session that keeps them
		// replaced it.
		return nil
	}
	// Only a session whose connection dropped may be resumed, here
	// through the relay. Any other has no use for its reconnect tokens.
	resuming := dropped && a.resumeRelaySession(t.AcceptedMeta(), session)
	if !resuming && !session.incognito {
		a.dropRelayPool(sessionID)
	}
	return nil
}

// dropStoppedSession closes t, a session that a server handed over after
// it was stopped.
func (a *App) dropStoppedSession(t *kamune.Transport) error {
	a.addLogEntry("INFO", "Closed incoming session "+t.SessionID()+
		": the server has stopped")
	_ = t.Close()
	return kamune.ErrClosedServer
}

// deriveAndStoreRelayTokens sends this side's relay-token key and keeps
// the pending exchange on the session. The receive loop finishes it when
// the peer's SessionData arrives. Failures are logged and non-fatal.
func (a *App) deriveAndStoreRelayTokens(
	t *kamune.Transport, session *liveSession,
) {
	pending, err := relayconn.BeginRelayTokenExchange(t)
	if err != nil {
		a.addLogEntry("WARN", "Failed to derive relay tokens: "+err.Error())
		return
	}
	session.mu.Lock()
	session.relayToken = pending
	session.mu.Unlock()
}

// finishRelayToken completes a pending exchange from a SessionData
// payload and stores the pool. A second SessionData is ignored.
func (a *App) finishRelayToken(session *liveSession, payload []byte) {
	session.mu.Lock()
	pending := session.relayToken
	session.mu.Unlock()
	if pending == nil {
		return
	}
	tokens, err := relayconn.CompleteRelayTokenPayload(pending, payload)
	if err != nil {
		a.addLogEntry("WARN", "Failed to derive relay tokens: "+err.Error())
		return
	}
	slices := make([][]byte, len(tokens))
	for i := range tokens {
		slices[i] = tokens[i][:]
	}
	store := a.store()
	if store == nil {
		return
	}
	if err := store.SetMeta(
		session.ID,
		storage.NewByteSlicesMeta(storage.RelayTokensKey, slices),
	); err != nil {
		a.addLogEntry("WARN", "Failed to store relay tokens: "+err.Error())
		return
	}
	session.mu.Lock()
	if session.relayToken == pending {
		session.relayToken = nil
	}
	session.mu.Unlock()
}

func (a *App) loadChatHistory(session *liveSession) {
	if session.incognito {
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

// removeSession takes session out of the app and reports how many
// sessions remain and whether it was there. It compares pointers, so a
// session that a resumed one with the same ID replaced does not take the
// new one out.
func (a *App) removeSession(session *liveSession) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := slices.Index(a.sessions, session)
	if i < 0 {
		return len(a.sessions), false
	}
	a.sessions = slices.Delete(a.sessions, i, i+1)
	return len(a.sessions), true
}

// addServerSessionLocked adds session, which a server established, to
// the app. A server session with the same ID is one that its peer has
// resumed on a new connection while the old one still looked open, as a
// connection does for a while after its network drops: session takes
// its place in the list, and addServerSessionLocked returns it so that
// the caller closes it. The caller holds a.mu.
func (a *App) addServerSessionLocked(session *liveSession) *liveSession {
	i := slices.IndexFunc(a.sessions, func(s *liveSession) bool {
		return s.IsServer && s.ID == session.ID
	})
	if i < 0 {
		a.sessions = append(a.sessions, session)
		return nil
	}
	old := a.sessions[i]
	a.sessions[i] = session
	return old
}

// ErrNoShareCard is returned by GetShareInfo for a P2P server, which has
// no connection card: a peer needs the broker's address and a token from
// the signaling tokens panel, or the server's address for direct P2P.
var ErrNoShareCard = errors.New(
	"P2P servers have no share card; share the broker address and a " +
		"signaling token, or your address for direct P2P",
)

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
		token, err := a.shareRelayToken()
		if err != nil {
			return nil, err
		}

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

	case "p2p":
		return nil, ErrNoShareCard
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

// shareTokenMinLife is how long a share card's relay token must still be
// valid for a new card to show it again; one closer to its expiry is
// replaced.
const shareTokenMinLife = time.Minute

// shareRelayToken returns the relay token for a share card: the last one
// made for a share card while no peer has used it, its listener is up and
// it is valid for shareTokenMinLife yet, or else a new one. Opening the
// card again does not give out another token; to replace one, remove it
// first.
func (a *App) shareRelayToken() (string, error) {
	// Cards opened at once must not each make a token.
	a.shareMu.Lock()
	defer a.shareMu.Unlock()
	a.mu.RLock()
	for _, rt := range slices.Backward(a.relayTokens) {
		if rt.share && !rt.Consumed && relayListenerUp(rt.listener) &&
			time.Until(rt.ExpiresAt) > shareTokenMinLife {
			a.mu.RUnlock()
			return rt.Token, nil
		}
	}
	a.mu.RUnlock()

	target, ok := a.currentRelayTarget()
	if !ok {
		return "", fmt.Errorf("server is not running")
	}
	rt, err := a.addRelayToken(
		a.lifeCtx(), target, nil,
		relayToken{Mode: "random", share: true}, "",
	)
	if err != nil {
		return "", fmt.Errorf("generate relay token: %w", err)
	}
	a.addLogEntry("INFO",
		"Share card: generated relay token "+logToken(rt.Token))
	return rt.Token, nil
}

// relayListenerUp reports whether the relay listener l is still
// registered: its tracker has not ended.
func relayListenerUp(l kamune.Listener) bool {
	tt, ok := l.(*tokenTracker)
	if !ok {
		return false
	}
	select {
	case <-tt.Dead():
		return false
	default:
		return true
	}
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

// decodeTokenList decodes the packed list format
// (uint32(count) || elem_0 || ... || elem_N) used for stored relay tokens.
func decodeTokenList(data []byte) [][]byte {
	if len(data) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint32(data[:4]))
	if count == 0 || len(data) < 4+count*storage.ElemSize {
		return nil
	}
	tokens := make([][]byte, count)
	for i := range tokens {
		off := 4 + i*storage.ElemSize
		tokens[i] = data[off : off+storage.ElemSize]
	}
	return tokens
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
