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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/xtaci/kcp-go/v5"
)

// transports are the transports that start_server and dial take. An
// empty transport is tcp.
var transports = []string{"tcp", "udp", "relay", "p2p", "direct-p2p"}

// checkTransport returns the transport that a start_server or dial
// command asks for, with an empty one read as tcp, and emits
// invalid_transport or addr_required and returns false when the daemon
// cannot use it. It never falls back to tcp for a transport it does not
// know: a mistyped "relay" would then listen on every interface. A tcp
// or udp transport needs an address, since an empty one too would
// listen on every interface.
func (d *Daemon) checkTransport(
	id ID, transport, addr string,
) (string, bool) {
	if transport == "" {
		transport = "tcp"
	}
	if !slices.Contains(transports, transport) {
		d.emitError(id, "invalid_transport", fmt.Sprintf(
			"invalid transport %q: must be one of %s",
			transport, strings.Join(transports, ", "),
		))
		return "", false
	}
	if addr == "" && (transport == "tcp" || transport == "udp") {
		d.emitError(id, "addr_required",
			"addr is required for transport "+transport)
		return "", false
	}
	return transport, true
}

// checkRelayPin emits invalid_relay_pin and returns false when pin, the
// relay_pin of a start_server or dial command with transport, is not one
// that parseRelayPin takes for relayAddr. Other transports ignore it.
func (d *Daemon) checkRelayPin(
	id ID, transport, relayAddr, pin string,
) bool {
	if transport != "relay" {
		return true
	}
	if _, err := parseRelayPin(relayAddr, pin); err != nil {
		d.emitError(id, "invalid_relay_pin", err.Error())
		return false
	}
	return true
}

// handleStartServer starts a kamune server. Supports tcp, udp, and relay
// transports (mirrors cmd/bus/network.go:16-179).
func (d *Daemon) handleStartServer(cmd Command) {
	var params StartServerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if !d.checkName(cmd.ID, params.Name) {
		return
	}
	transport, ok := d.checkTransport(cmd.ID, params.Transport, params.Addr)
	if !ok {
		return
	}
	params.Transport = transport
	if !d.checkRelayPin(cmd.ID, transport, params.RelayAddr, params.RelayPin) {
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.mu.Lock()
	if d.server != nil {
		d.mu.Unlock()
		d.emitError(cmd.ID, "server_already_running", "server is already running")
		return
	}
	if d.startCancel != nil {
		d.mu.Unlock()
		d.emitError(
			cmd.ID,
			"server_start_in_progress",
			"server start is already in progress",
		)
		return
	}
	ctx, cancel := context.WithCancel(d.ctx)
	done := make(chan struct{})
	d.startCtx = ctx
	d.startCancel = cancel
	d.startDone = done
	d.serverAddr = params.Addr
	d.serverTransport = params.Transport
	d.serverRelayAddr = params.RelayAddr
	d.serverRelayPin = params.RelayPin
	d.serverName = params.Name
	d.serverPassword = params.Password
	d.serverBrokerAddr = params.BrokerAddr
	d.serverPeerPubB64 = params.PeerPubB64
	d.serverDirectPeerAddr = params.DirectPeerAddr
	d.mu.Unlock()

	d.setStatus(StatusConnecting, "Starting server...")
	d.wg.Go(func() {
		d.startServer(ctx, done, cmd, params)
	})
}

func (d *Daemon) startServer(
	ctx context.Context,
	startDone chan struct{},
	cmd Command,
	params StartServerParams,
) {
	defer close(startDone)
	defer func() {
		d.mu.Lock()
		if d.startCtx == ctx {
			d.startCancel = nil
			d.startCtx = nil
			d.startDone = nil
		}
		d.mu.Unlock()
	}()

	store := d.store()
	if store == nil {
		d.setStatus(StatusError, "Storage is not available")
		d.emitError(cmd.ID, "storage_unavailable", "storage is not available")
		return
	}

	d.mu.RLock()
	incognito := d.incognito
	d.mu.RUnlock()
	name := params.Name
	if name == "" || incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			d.setStatus(StatusError, "Failed to get identity")
			d.emitError(cmd.ID, "identity_unavailable", fmt.Sprintf("getting identity: %v", err))
			return
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	d.mu.Lock()
	d.myName = name
	d.mu.Unlock()
	if !incognito {
		_ = store.SetSettings("daemon", "local_name", name)
	}

	// firstToken is the relay token registered at start, if any.
	var firstToken relayToken
	// direct is the tcp or udp listener, if any, until NewServer owns it.
	var direct *boundListener
	var opts []kamune.ServerOptions
	opts = append(opts, kamune.ServeWithServerName(name))
	if incognito {
		// Keep incognito sessions out of storage. Without a record they
		// cannot be resumed, so refuse resumption as well.
		opts = append(opts,
			kamune.ServeWithoutPersistence(),
			kamune.ServeWithResumeEnabled(false),
		)
	}

	switch params.Transport {
	case "relay":
		if ctx.Err() != nil {
			return
		}
		d.warnRelayAddr(params.RelayAddr)
		// handleStartServer checked the pin.
		pin, _ := parseRelayPin(params.RelayAddr, params.RelayPin)
		ml := newMultiListener()
		listener, token, ttl, sessionTTL, err := listenRelayTracked(
			ctx, d, params.RelayAddr, params.Password, pin, nil,
		)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.setStatus(StatusError, "Failed to connect to relay")
			d.addLogEntry("ERROR", "Relay listen failed: "+err.Error())
			d.emitError(cmd.ID, "relay_listen_failed", fmt.Sprintf("relay listen: %v", err))
			return
		}
		if err := ml.Add(listener); err != nil {
			listener.Close()
			d.emitError(cmd.ID, "listener_failed", fmt.Sprintf("add listener: %v", err))
			return
		}
		firstToken = relayToken{
			Token: token, TTL: ttl, SessionTTL: sessionTTL,
			ExpiresAt: time.Now().Add(ttl), Mode: "random",
			listener: listener,
		}
		opts = append(opts, kamune.ServeWithListener(ml))
		params.Addr = ""
		d.mu.Lock()
		d.relayAddr = params.RelayAddr
		d.relayPassword = params.Password
		d.relayPin = pin
		d.relaySessionTTL = sessionTTL
		d.relayListeners = ml
		d.relayTokens = []relayToken{firstToken}
		d.mu.Unlock()
	case "p2p":
		broker, err := d.getOrCreateBrokerClient()
		if err != nil {
			d.setStatus(StatusError, "Failed to create broker client")
			d.emitError(
				cmd.ID,
				"broker_client_failed",
				fmt.Sprintf("broker client: %v", err),
			)
			return
		}
		tokenBytes, err := d.deriveP2PToken(params.PeerPubB64)
		if err != nil {
			d.setStatus(StatusError, "Failed to derive p2p token")
			d.emitError(
				cmd.ID,
				"p2p_token_failed",
				fmt.Sprintf("derive p2p token: %v", err),
			)
			return
		}
		pl, err := newP2PListener(
			broker, params.BrokerAddr, tokenBytes, params.Addr,
			d.p2pRefreshed,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to create p2p listener")
			d.emitError(cmd.ID, "p2p_listener_failed", fmt.Sprintf("p2p listener: %v", err))
			return
		}
		if ctx.Err() != nil {
			pl.Close()
			return
		}
		opts = append(opts, kamune.ServeWithListener(pl))
		params.Addr = pl.Addr().String()
		mode := "random"
		if len(tokenBytes) > 0 {
			mode = "static"
		}
		pt := p2pToken{
			Token:      pl.Token(),
			Mode:       mode,
			PeerPubB64: params.PeerPubB64,
			TTL:        p2pTokenTTL,
			ExpiresAt:  time.Now().Add(p2pTokenTTL),
			brokerAddr: params.BrokerAddr,
		}
		d.mu.Lock()
		d.p2pListener = pl
		d.p2pTokens = append(d.p2pTokens, pt)
		p2pSnapshot := d.p2pTokensSnapshot()
		d.mu.Unlock()
		d.emit(EvtP2PTokens, "", MapA{"tokens": p2pSnapshot})
	case "direct-p2p":
		pl, err := newDirectP2PListener(
			params.Addr, params.DirectPeerAddr,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to create direct p2p listener")
			d.emitError(cmd.ID, "direct_p2p_failed", fmt.Sprintf("direct p2p listener: %v", err))
			return
		}
		opts = append(opts, kamune.ServeWithListener(pl))
		params.Addr = pl.Addr().String()
		d.mu.Lock()
		d.p2pListener = pl
		d.mu.Unlock()
	case "tcp", "udp":
		// Bind here, not in NewServer, to learn the bound address: the
		// one asked for may have port 0.
		l, err := listenDirect(params.Transport, params.Addr)
		if err != nil {
			d.setStatus(StatusError, "Failed to create server")
			d.addLogEntry("ERROR", "Failed to create server: "+err.Error())
			d.emitError(
				cmd.ID,
				"create_server_failed",
				fmt.Sprintf("create server: %v", err),
			)
			return
		}
		direct = l
		opts = append(opts, kamune.ServeWithListener(l))
		params.Addr = l.Addr().String()
	default:
		// handleStartServer checked the transport.
		d.setStatus(StatusError, "Failed to create server")
		d.emitError(cmd.ID, "invalid_transport",
			"invalid transport "+strconv.Quote(params.Transport))
		return
	}

	srv, err := kamune.NewServer(
		params.Addr, d.serverHandler, store, d.inboundVerifier(), opts...,
	)
	if err != nil {
		if direct != nil {
			_ = direct.Close()
		}
		d.stopP2PResources()
		d.stopRelayResources()
		d.setStatus(StatusError, "Failed to create server")
		d.addLogEntry("ERROR", "Failed to create server: "+err.Error())
		d.emitError(cmd.ID, "create_server_failed", fmt.Sprintf("create server: %v", err))
		return
	}
	if ctx.Err() != nil {
		_ = srv.Close()
		d.stopP2PResources()
		d.stopRelayResources()
		return
	}

	pubKey := srv.PublicKey()
	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	b64 := fingerprint.Base64(pubKey)
	hexFP := fingerprint.Hex(pubKey)
	sum := fingerprint.Sum(pubKey)

	done := make(chan struct{})
	d.mu.Lock()
	if ctx.Err() != nil {
		d.mu.Unlock()
		_ = srv.Close()
		d.stopP2PResources()
		d.stopRelayResources()
		return
	}
	d.pubKey = pubKey
	d.server = srv
	d.serverDone = done
	d.serverBoundAddr = params.Addr
	serverTransport := params.Transport
	d.mu.Unlock()

	if ctx.Err() != nil {
		d.mu.Lock()
		same := d.server == srv
		if same {
			d.server = nil
			d.serverDone = nil
		}
		d.mu.Unlock()
		if same {
			_ = srv.Close()
			d.stopP2PResources()
			d.stopRelayResources()
		}
		return
	}

	d.emit(EvtFingerprintChange, "", MapA{
		"emoji": emoji, "b64": b64, "hex": hexFP, "sum": sum,
		"numeric": fingerprint.Numeric(pubKey),
	})
	d.emit(EvtServerRunning, "", MapA{
		"running": true, "transport": serverTransport,
	})

	d.wg.Go(func() {
		defer close(done)
		if err := srv.ListenAndServe(); err != nil {
			d.addLogEntry("ERROR", "Server stopped: "+err.Error())
		}
		d.stopP2PResources()
		d.stopRelayResources()
		d.mu.Lock()
		d.serverBrokerAddr = ""
		d.serverPeerPubB64 = ""
		d.serverDirectPeerAddr = ""
		d.serverBoundAddr = ""
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

	if firstToken.Token != "" {
		d.announceRelayToken(firstToken)
	}

	d.emit(EvtServerStarted, cmd.ID, MapA{
		"addr":                params.Addr,
		"transport":           serverTransport,
		"name":                name,
		"public_key":          b64,
		"emoji":               fingerprint.Emoji(pubKey),
		"fingerprint_hex":     hexFP,
		"fingerprint_sum":     sum,
		"fingerprint_numeric": fingerprint.Numeric(pubKey),
	})
}

// announceRelayToken emits relay_token for first, the token that a relay
// server registered at start, and relay_tokens. The token may have
// expired, lost its relay link or been used since, so relay_token is
// emitted only while the token list holds it unused.
func (d *Daemon) announceRelayToken(first relayToken) {
	d.mu.RLock()
	tokens := slices.Clone(d.relayTokens)
	d.mu.RUnlock()
	live := slices.ContainsFunc(tokens, func(rt relayToken) bool {
		return rt.listener == first.listener && !rt.Consumed
	})
	if live {
		d.emit(EvtRelayToken, "", MapA{
			"token": first.Token, "ttl_ns": first.TTL,
			"session_ttl_ns": first.SessionTTL,
			"expires_at":     first.ExpiresAt,
		})
		d.addLogEntry("INFO", "Relay token: "+shortToken(first.Token))
	}
	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
}

// handleStopServer closes the running server and all sessions, without
// exiting the daemon. Each session gets session_closed.
func (d *Daemon) handleStopServer(cmd Command) {
	d.stopServer()
	d.emit(EvtServerStopped, "", MapA{"running": false})
	if cmd.ID != "" {
		d.emit(EvtResponse, cmd.ID, MapS{"status": "stopped"})
	}
}

func (d *Daemon) stopServer() {
	d.setStatus(StatusDisconnected, "Stopping server...")
	d.addLogEntry("INFO", "Stopping server...")

	var sessions []*liveSession
	var serverDone chan struct{}
	var startDone chan struct{}
	var startCancel context.CancelFunc
	var server *kamune.Server

	d.mu.Lock()
	startCancel = d.startCancel
	startDone = d.startDone
	server = d.server
	d.server = nil
	sessions = append([]*liveSession(nil), mapValues(d.sessions)...)
	d.sessions = make(map[string]*liveSession)
	serverDone = d.serverDone
	d.serverDone = nil
	d.mu.Unlock()

	if startCancel != nil {
		startCancel()
	}
	d.stopRelayResources()
	d.stopP2PResources()
	if server != nil {
		_ = server.Close()
	}
	for _, s := range sessions {
		if transport := s.stop(); transport != nil {
			_ = transport.Close()
		}
	}
	for _, s := range sessions {
		waitOrTimeout(s.ReceiveDone, "session receive: "+s.ID)
	}
	d.reportClosed(sessions)
	if len(sessions) > 0 {
		d.loadHistorySessions()
	}

	if serverDone != nil {
		waitOrTimeout(serverDone, "ListenAndServe")
	}
	if startDone != nil {
		waitOrTimeout(startDone, "server start")
	}
}

// reportClosed emits session_closed for sessions, which the daemon took
// off the live sessions and closed itself. Their receive loops then find
// them gone and do not report them; see finishSession.
func (d *Daemon) reportClosed(sessions []*liveSession) {
	for _, s := range sessions {
		d.emit(EvtSessionClosed, "", d.sessionInfo(s))
	}
}

// handleRestartServer stops the server, which closes all sessions, and
// starts it again with the last used params.
func (d *Daemon) handleRestartServer(cmd Command) {
	d.mu.RLock()
	addr := d.serverAddr
	transport := d.serverTransport
	relayAddr := d.serverRelayAddr
	relayPin := d.serverRelayPin
	name := d.serverName
	password := d.serverPassword
	brokerAddr := d.serverBrokerAddr
	peerPubB64 := d.serverPeerPubB64
	directPeerAddr := d.serverDirectPeerAddr
	d.mu.RUnlock()
	// start_server sets the transport once it accepts the command.
	if transport == "" {
		d.emitError(cmd.ID, "server_not_started",
			"no server has been started to restart")
		return
	}

	d.addLogEntry("INFO", "Restarting server to apply settings change")

	d.stopServer()
	d.emit(EvtServerStopped, "", MapA{"running": false})
	d.handleStartServer(Command{
		ID: cmd.ID,
		Params: mustJSON(StartServerParams{
			Addr: addr, Transport: transport,
			RelayAddr: relayAddr, RelayPin: relayPin,
			Password: password, Name: name,
			BrokerAddr: brokerAddr, PeerPubB64: peerPubB64,
			DirectPeerAddr: directPeerAddr,
		}),
	})
}

// handleCancelStartServer cancels an in-flight server start.
func (d *Daemon) handleCancelStartServer(cmd Command) {
	d.mu.RLock()
	cancel := d.startCancel
	startDone := d.startDone
	d.mu.RUnlock()
	if cancel == nil {
		d.emitError(
			cmd.ID,
			"server_start_not_in_progress",
			"server start is not in progress",
		)
		return
	}
	cancel()
	if startDone != nil {
		waitOrTimeout(startDone, "server start cancel")
	}
	d.mu.RLock()
	running := d.server != nil
	stillStarting := d.startCancel != nil
	d.mu.RUnlock()
	if stillStarting {
		d.emitError(
			cmd.ID,
			"cancel_timeout",
			"timed out waiting for server start to abort",
		)
		return
	}
	if running {
		d.emitError(
			cmd.ID,
			"server_already_started",
			"server start completed before cancel",
		)
		return
	}
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
	if running {
		addr = d.serverBoundAddr
	}
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
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if !d.checkName(cmd.ID, params.Name) {
		return
	}
	transport, ok := d.checkTransport(cmd.ID, params.Transport, params.Addr)
	if !ok {
		return
	}
	params.Transport = transport
	if !d.checkRelayPin(cmd.ID, transport, params.RelayAddr, params.RelayPin) {
		return
	}

	if !d.requireStorage(cmd.ID) {
		return
	}

	d.mu.Lock()
	d.dialOps++
	d.mu.Unlock()
	d.wg.Go(func() {
		defer func() {
			d.mu.Lock()
			d.dialOps--
			d.mu.Unlock()
		}()
		defer func() {
			if msg := recover(); msg != nil {
				d.emitError(
					cmd.ID,
					"goroutine_panic",
					fmt.Sprintf("goroutine panic: %v", msg),
				)
			}
		}()
		d.dial(d.ctx, cmd, params)
	})
}

func (d *Daemon) dial(ctx context.Context, cmd Command, params DialParams) {
	connected := false
	defer func() {
		if !connected {
			d.setStatus(StatusError, "Connection failed")
		}
	}()

	d.setStatus(StatusConnecting, "Connecting to "+params.Addr+"...")

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage_unavailable", "storage is not available")
		return
	}

	var opts []kamune.DialOption

	d.mu.RLock()
	incognito := d.incognito
	d.mu.RUnlock()
	name := params.Name
	if name == "" || incognito {
		pubKey, err := store.PublicKey()
		if err != nil {
			d.emitError(cmd.ID, "identity_unavailable", fmt.Sprintf("getting identity: %v", err))
			return
		}
		name = fingerprint.Pseudonym(pubKey)
	}

	d.mu.Lock()
	d.myName = name
	d.mu.Unlock()
	if !incognito {
		_ = store.SetSettings("daemon", "local_name", name)
	}

	opts = append(opts, kamune.DialWithClientName(name))
	if incognito {
		opts = append(opts, kamune.DialWithoutPersistence())
	}

	var sessionTTL time.Duration
	switch params.Transport {
	case "relay":
		d.warnRelayAddr(params.RelayAddr)
		// handleDial checked the pin.
		pin, _ := parseRelayPin(params.RelayAddr, params.RelayPin)
		fn, err := dialRelayFuncWithSessionTTL(
			ctx, d.relayTimeout, params.RelayAddr, params.Token,
			params.Password, pin, &sessionTTL,
		)
		if err != nil {
			d.setStatus(StatusError, "Failed to prepare relay dial")
			d.addLogEntry("ERROR", "Relay dial preparation failed: "+err.Error())
			d.emitError(cmd.ID, "relay_dial_failed", fmt.Sprintf("relay dial func: %v", err))
			return
		}
		opts = append(opts, kamune.DialWithFunc(fn))
		params.Addr = params.RelayAddr
	case "p2p":
		broker, err := d.getOrCreateBrokerClient()
		if err != nil {
			d.emitError(
				cmd.ID,
				"broker_client_failed",
				fmt.Sprintf("broker client: %v", err),
			)
			return
		}
		tokenBytes, err := parseP2PToken(params.P2PToken)
		if err != nil {
			d.emitError(cmd.ID, "invalid_p2p_token", err.Error())
			return
		}
		matchCtx, matchCancel := context.WithTimeout(ctx, d.matchTimeout)
		punchConn, payload, err := broker.WaitMatch(
			matchCtx, params.BrokerAddr, tokenBytes,
		)
		matchCancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf(
					"no peer matched the token within %v", d.matchTimeout,
				)
			}
			d.emitError(cmd.ID, "p2p_match_failed", fmt.Sprintf("wait match: %v", err))
			return
		}
		conn, err := broker.HolePunch(
			ctx, punchConn,
			payload.IP, payload.Port, DefaultHolePunchTimeout,
		)
		if err != nil {
			punchConn.Close()
			d.emitError(cmd.ID, "hole_punch_failed", fmt.Sprintf("hole punch: %v", err))
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
			d.emitError(cmd.ID, "direct_p2p_failed", fmt.Sprintf("direct p2p dial: %v", err))
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
	case "tcp":
		opts = append(opts, kamune.DialWithTCP())
	default:
		// handleDial checked the transport.
		d.emitError(cmd.ID, "invalid_transport",
			"invalid transport "+strconv.Quote(params.Transport))
		return
	}

	dialer, err := kamune.NewDialer(
		params.Addr, store, d.outboundVerifier(), opts...,
	)
	if err != nil {
		d.setStatus(StatusError, "Failed to create dialer")
		d.addLogEntry("ERROR", "Failed to create dialer: "+err.Error())
		d.emitError(
			cmd.ID,
			"create_dialer_failed",
			fmt.Sprintf("create dialer: %v", err),
		)
		return
	}

	t, err := dialer.Dial()
	if err != nil {
		d.setStatus(StatusError, "Connection failed")
		d.addLogEntry("ERROR", "Dial failed: "+err.Error())
		d.emitError(cmd.ID, "dial_failed", fmt.Sprintf("dial: %v", err))
		return
	}

	if ctx.Err() != nil {
		t.Close()
		return
	}

	sessionID := t.SessionID()
	peer := t.RemotePeer()
	d.rememberPeer(store, peer)

	session := &liveSession{
		ID:               sessionID,
		PeerName:         peer.Name,
		RemoteVersion:    peer.AppVersion,
		RemoteAddr:       params.Addr,
		Cause:            "dial",
		Transport:        t,
		LastActivity:     time.Now(),
		ReceiveDone:      make(chan struct{}),
		IsServer:         false,
		TransportType:    params.Transport,
		SessionTTL:       sessionTTL,
		SessionStartedAt: time.Now(),
		pongCh:           make(chan []byte, 1),
		keepAliveDone:    make(chan struct{}),
	}

	if !incognito {
		if err := store.CreateSession(
			sessionID, peer.PublicKey,
		); err != nil {
			d.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
		d.deriveAndStoreRelayTokens(t, session)
	}

	// Store dial params for transparent resumption on involuntary
	// disconnect. An incognito session has no stored resumption state, so
	// it ends when its connection drops.
	reconnectCtx, reconnectCancel := context.WithCancel(d.ctx)
	session.mu.Lock()
	session.reconnectCtx = reconnectCtx
	session.reconnectCancel = reconnectCancel
	if !incognito {
		session.reconnectFn = d.makeReconnectFn(
			reconnectCtx, session, &params, store, opts,
		)
	}
	session.mu.Unlock()

	d.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(
		kamune.AppVersion, peer.AppVersion,
	); mismatch {
		d.addLogEntry("WARN", msg)
		d.emit(EvtVersionWarning, "", MapA{
			"session_id": sessionID, "message": msg,
		})
	}

	// shutdown cancels ctx before it takes the live sessions to close
	// them, both under d.mu. A session added after that would never be
	// closed, and shutdown would wait for its receive loop for good.
	d.mu.Lock()
	if ctx.Err() != nil {
		d.mu.Unlock()
		session.stop()
		_ = t.Close()
		return
	}
	d.sessions[sessionID] = session
	d.mu.Unlock()

	info := d.sessionInfo(session)
	d.emit(EvtSessionStarted, cmd.ID, info)

	connected = true
	d.setStatus(StatusConnected, "Connected to "+params.Addr)
	d.addLogEntry("INFO", "Connected to "+params.Addr+" (session: "+sessionID+")")

	session.mu.Lock()
	keepAliveDone := session.keepAliveDone
	session.mu.Unlock()
	go d.keepAliveLoop(session, keepAliveDone)
	d.receiveMessages(session)
	d.loadHistorySessions()
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
	d.mu.Lock()
	stampRelaySession(t.AcceptedMeta(), sessionID)
	d.mu.Unlock()
	peer := t.RemotePeer()

	session := &liveSession{
		ID:               sessionID,
		PeerName:         peer.Name,
		RemoteVersion:    peer.AppVersion,
		Cause:            "incoming",
		Transport:        t,
		LastActivity:     time.Now(),
		ReceiveDone:      make(chan struct{}),
		IsServer:         true,
		TransportType:    transport,
		SessionTTL:       relaySessionTTL,
		SessionStartedAt: time.Now(),
		pongCh:           make(chan []byte, 1),
		keepAliveDone:    make(chan struct{}),
	}

	d.rememberPeer(d.store(), peer)
	var store *storage.Storage
	if s := d.store(); s != nil && !d.isIncognito() {
		store = s
		if err := store.CreateSession(sessionID, peer.PublicKey); err != nil {
			d.addLogEntry("WARN", "Failed to create session record: "+err.Error())
		}
		d.deriveAndStoreRelayTokens(t, session)
	}

	d.loadChatHistory(session)

	if msg, mismatch := checkMinorMismatch(kamune.AppVersion, peer.AppVersion); mismatch {
		d.addLogEntry("WARN", msg)
		d.emit(EvtVersionWarning, "", MapA{
			"session_id": sessionID, "message": msg,
		})
	}

	d.mu.Lock()
	if d.server == nil {
		d.mu.Unlock()
		_ = t.Close()
		return errors.New("server is stopped")
	}
	d.sessions[sessionID] = session
	d.mu.Unlock()

	info := d.sessionInfo(session)
	d.emit(EvtSessionStarted, "", info)
	d.addLogEntry("INFO", "New incoming connection: "+sessionID)

	session.mu.Lock()
	keepAliveDone := session.keepAliveDone
	session.mu.Unlock()
	go d.keepAliveLoop(session, keepAliveDone)

	defer close(session.ReceiveDone)
	err := d.receiveMessagesBlocking(session)
	// A session the daemon closed itself is no longer listed. Only a
	// session whose connection dropped may be resumed.
	if d.finishSession(session) && errors.Is(err, kamune.ErrConnClosed) {
		d.resumeRelaySession(t.AcceptedMeta(), sessionID)
	} else {
		d.dropRelayPool(sessionID)
	}
	return nil
}

// handleCloseSession closes a specific session.
func (d *Daemon) handleCloseSession(cmd Command) {
	var params CloseSessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	session, ok := d.sessions[params.SessionID]
	if !ok {
		d.mu.Unlock()
		d.emitError(
			cmd.ID,
			"session_not_found",
			fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}
	delete(d.sessions, params.SessionID)
	d.mu.Unlock()

	transport := session.stop()
	d.dropRelayPool(params.SessionID)

	// Close deletes the session's resumption tokens, so that neither side
	// can resume it, without creating a session that is not stored.
	if transport != nil {
		if err := transport.Close(); err != nil {
			slog.Warn("error closing transport", slog.Any("error", err))
		}
	}
	waitOrTimeout(session.ReceiveDone, "session receive: "+params.SessionID)

	d.emit(EvtSessionClosed, "", d.sessionInfo(session))
	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "closed", "session_id": params.SessionID,
	})
	d.setStatusIfEmpty(StatusDisconnected, "Not connected")
	d.loadHistorySessions()
}

// handleListSessions returns a list of active sessions.
func (d *Daemon) handleListSessions(cmd Command) {
	d.mu.RLock()
	live := mapValues(d.sessions)
	d.mu.RUnlock()

	sessions := make([]SessionInfo, 0, len(live))
	for _, s := range live {
		sessions = append(sessions, d.sessionInfo(s))
	}
	d.emit(EvtResponse, cmd.ID, MapA{"sessions": sessions})
}

// handleRenameSession renames a live session in memory.
func (d *Daemon) handleRenameSession(cmd Command) {
	var params RenameSessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if !d.checkName(cmd.ID, params.Name) {
		return
	}

	d.mu.RLock()
	var session *liveSession
	for _, s := range d.sessions {
		if s.ID == params.SessionID {
			session = s
			break
		}
	}
	d.mu.RUnlock()
	if session == nil {
		d.emitError(
			cmd.ID,
			"session_not_found",
			fmt.Sprintf("session not found: %s", params.SessionID),
		)
		return
	}
	session.mu.Lock()
	session.PeerName = params.Name
	session.mu.Unlock()

	d.emit(EvtSessionUpdated, "", MapS{"session_id": params.SessionID})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "ok"})
}

// handleGenerateP2PToken adds a p2p token to the running p2p server.
func (d *Daemon) handleGenerateP2PToken(cmd Command) {
	var params GenerateP2PTokenParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	tokenHex, err := d.GenerateP2PToken(params.BrokerAddr, params.PeerPubB64)
	if err != nil {
		code := "p2p_token_failed"
		switch {
		case errors.Is(err, errNoP2PServer):
			code = "p2p_server_not_running"
		case errors.Is(err, errBrokerMismatch):
			code = "broker_addr_mismatch"
		}
		d.emitError(cmd.ID, code, fmt.Sprintf("generate p2p token: %v", err))
		return
	}
	d.emit(EvtResponse, cmd.ID, MapA{
		"token": tokenHex, "broker_addr": params.BrokerAddr,
		"peer_pub_b64": params.PeerPubB64,
	})
}

// handleRemoveP2PToken removes an active p2p token.
func (d *Daemon) handleRemoveP2PToken(cmd Command) {
	var params RemoveP2PTokenParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}
	if err := d.RemoveP2PToken(params.Token); err != nil {
		d.emitError(cmd.ID, "p2p_token_remove_failed", err.Error())
		return
	}
	d.emit(EvtResponse, cmd.ID, MapS{"status": "removed"})
}

// handleListP2PTokens returns all active p2p tokens.
func (d *Daemon) handleListP2PTokens(cmd Command) {
	tokens := d.GetP2PTokens()
	d.emit(EvtResponse, cmd.ID, MapA{"tokens": tokens})
}

// deriveAndStoreRelayTokens sends this side's relay-token key and keeps
// the pending exchange on the session. The receive loop finishes it.
func (d *Daemon) deriveAndStoreRelayTokens(
	t *kamune.Transport, session *liveSession,
) {
	pending, err := relayconn.BeginRelayTokenExchange(t)
	if err != nil {
		d.addLogEntry("WARN", "Failed to derive relay tokens: "+err.Error())
		return
	}
	session.mu.Lock()
	session.relayToken = pending
	session.mu.Unlock()
}

// finishRelayToken completes a pending exchange from a SessionData
// payload and stores the pool. A second SessionData is ignored.
func (d *Daemon) finishRelayToken(session *liveSession, payload []byte) {
	session.mu.Lock()
	pending := session.relayToken
	session.mu.Unlock()
	if pending == nil {
		return
	}
	tokens, err := relayconn.CompleteRelayTokenPayload(pending, payload)
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
	if err := store.SetMeta(
		session.ID,
		storage.NewByteSlicesMeta(storage.RelayTokensKey, slices),
	); err != nil {
		d.addLogEntry("WARN", "Failed to store relay tokens: "+err.Error())
		return
	}
	session.mu.Lock()
	if session.relayToken == pending {
		session.relayToken = nil
	}
	session.mu.Unlock()
}

// makeReconnectFn returns a reconnect function that re-dials with resumption
// tokens, trying stored ECDH tokens for relay connections (mirrors
// cmd/bus/network.go:687-723). The function fails with an error wrapping
// errNotResumable, without dialing, when store has no peer for the session.
func (d *Daemon) makeReconnectFn(
	ctx context.Context,
	session *liveSession,
	params *DialParams,
	store *storage.Storage,
	opts []kamune.DialOption,
) func(string) (*kamune.Transport, error) {
	if params.Transport == "p2p" {
		return nil
	}
	addr := params.Addr
	relayAddr := params.RelayAddr
	relayPin, _ := parseRelayPin(params.RelayAddr, params.RelayPin)
	password := params.Password
	isDirectP2P := params.Transport == "direct-p2p"
	directPeerAddr := params.DirectPeerAddr
	return func(sessionID string) (*kamune.Transport, error) {
		if store == nil {
			return nil, kamune.ErrMissingStorage
		}
		// Resuming needs the session's peer record. Without it each try
		// would spend a resumption token and fail the same way.
		if _, err := store.GetPeer(sessionID); err != nil {
			return nil, fmt.Errorf("%w: %w", errNotResumable, err)
		}
		resumeOpts := append(
			[]kamune.DialOption{kamune.DialWithResume(sessionID)}, opts...,
		)
		if isDirectP2P {
			pConn, err := directP2PDial(directPeerAddr)
			if err != nil {
				return nil, fmt.Errorf("direct p2p redial: %w", err)
			}
			resumeOpts = append(resumeOpts, kamune.DialWithFunc(
				func(_ string) (kamune.Conn, error) {
					return pConn, nil
				},
			))
		} else if relayAddr != "" {
			if m, err := store.GetMeta(
				sessionID, storage.RelayTokensKey,
			); err == nil && m.Value() != nil {
				if tokens := decodeTokenList(m.Value()); len(tokens) > 0 {
					fn, err := dialRelayFuncMultiToken(
						ctx, d.relayTimeout, relayAddr, password,
						relayPin, tokens,
					)
					if err == nil {
						resumeOpts = append(
							resumeOpts, kamune.DialWithFunc(fn),
						)
					}
				}
			}
		}
		dl, err := kamune.NewDialer(
			addr, store, d.outboundVerifier(), resumeOpts...,
		)
		if err != nil {
			return nil, err
		}
		t, err := dl.Dial()
		if err != nil {
			return nil, err
		}
		d.deriveAndStoreRelayTokens(t, session)
		return t, nil
	}
}

// resumeRelaySession starts keeping a relay listener registered for
// sessionID, a session that the relay server accepted on the relay
// listener meta and whose connection dropped, so that its peer can
// resume it; see awaitRelayResume. It does nothing for a session that
// did not come through the relay or that cannot be resumed.
func (d *Daemon) resumeRelaySession(meta any, sessionID string) {
	if _, ok := meta.(*tokenTracker); !ok || d.isIncognito() {
		return
	}
	target, ok := d.currentRelayTarget()
	if !ok || d.ctx.Err() != nil {
		return
	}
	d.wg.Go(func() { d.awaitRelayResume(target, sessionID) })
}

// awaitRelayResume keeps a relay listener registered with one of the
// reconnect tokens of sessionID, a relay session of target's server
// whose connection dropped, so that its peer can resume the session
// through the relay. Each token is registered once and then removed
// from the stored pool, as is a token whose registration failed after
// the relay had it. When the listener ends before a session has run on
// it, or the relay takes no token, it tries again after a short wait. It
// returns once a session has run on such a listener, when the user
// removed its token, when the server stops, when the session can no
// longer be resumed or has no reconnect token left, and
// d.relayResumeWindow after it started.
func (d *Daemon) awaitRelayResume(target relayTarget, sessionID string) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 5 * time.Second
	)
	deadline := time.Now().Add(d.relayResumeWindow)
	for {
		store := d.store()
		if !relayResumable(store, sessionID) {
			d.dropRelayPool(sessionID)
			d.addLogEntry("INFO",
				"Session "+sessionID+" can no longer be resumed; "+
					"its relay reconnect tokens are dropped")
			return
		}
		tokens := loadRelayPool(store, sessionID)
		if len(tokens) == 0 {
			d.addLogEntry("INFO",
				"No relay reconnect tokens left for session "+sessionID+
					"; it cannot resume through the relay")
			return
		}

		var tt *tokenTracker
		for _, token := range tokens {
			rt, code, err := d.addRelayToken(
				target, token, "ecdh", "", sessionID,
			)
			// Never register a token that the relay has seen again,
			// whether or not its registration worked.
			if err == nil || code != "relay_listen_failed" ||
				relayTokenSent(err) {
				d.popRelayToken(store, sessionID, token)
			}
			if err != nil {
				if code != "relay_listen_failed" {
					return
				}
				d.addLogEntry("WARN",
					"Relay reconnect registration failed: "+err.Error())
				continue
			}
			tt, _ = rt.listener.(*tokenTracker)
			d.addLogEntry("INFO",
				"Relay reconnect listener registered for session "+
					sessionID)
			break
		}

		if tt != nil {
			select {
			case <-tt.Dead():
			case <-target.listeners.Done():
				return
			case <-d.ctx.Done():
				return
			}
			d.mu.RLock()
			resumed := tt.sessionID != ""
			d.mu.RUnlock()
			if resumed {
				return
			}
			if tt.removed.Load() {
				d.dropRelayPool(sessionID)
				d.addLogEntry("INFO",
					"Relay reconnect listener for session "+sessionID+
						" was removed; it is not resumed through the "+
						"relay")
				return
			}
		}
		if !time.Now().Before(deadline) {
			d.addLogEntry("INFO",
				"Session "+sessionID+" was not resumed through the "+
					"relay in time; its relay listener is not renewed")
			return
		}

		jitter := time.Duration(rand.Int63n(int64(maxBackoff - minBackoff)))
		select {
		case <-time.After(minBackoff + jitter):
		case <-target.listeners.Done():
			return
		case <-d.ctx.Done():
			return
		}
	}
}

// popRelayToken removes token from the relay reconnect tokens stored
// for sessionID.
func (d *Daemon) popRelayToken(
	store *storage.Storage, sessionID string, token []byte,
) {
	err := store.RemoveListItem(sessionID, storage.RelayTokensKey, token)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		d.addLogEntry("WARN",
			"Failed to drop a used relay reconnect token: "+err.Error())
	}
}

// cancelRelayResume removes the relay tokens registered for the peer of
// sessionID to resume it on, which no peer has used yet, and closes
// their listeners, so that awaitRelayResume registers none again.
func (d *Daemon) cancelRelayResume(sessionID string) {
	var removed []*tokenTracker
	d.mu.Lock()
	d.relayTokens = slices.DeleteFunc(d.relayTokens, func(rt relayToken) bool {
		tt, ok := rt.listener.(*tokenTracker)
		if !ok || tt.resumeOf != sessionID || tt.consumed.Load() {
			return false
		}
		removed = append(removed, tt)
		return true
	})
	tokens := slices.Clone(d.relayTokens)
	d.mu.Unlock()
	if len(removed) == 0 {
		return
	}

	for _, tt := range removed {
		tt.removed.Store(true)
		_ = tt.Close()
	}
	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
}

// dropRelayPool deletes the relay reconnect tokens stored for sessionID,
// once the session is over and no peer may resume it.
func (d *Daemon) dropRelayPool(sessionID string) {
	store := d.store()
	if store == nil {
		return
	}
	if err := store.DeleteMeta(sessionID, storage.RelayTokensKey); err != nil {
		d.addLogEntry("DEBUG",
			"Failed to drop relay reconnect tokens: "+err.Error())
	}
}

// handleGenerateRelayToken creates a new relay token for the running server.
// When peer_pub_b64 is provided, it derives a deterministic (static) token
// using ECDH (mirrors cmd/bus/network.go:427-466). The token is registered
// with the relay after the command returns, so that a slow relay does not
// hold up other commands; the response follows once it is registered.
func (d *Daemon) handleGenerateRelayToken(cmd Command) {
	var params GenerateRelayTokenParams
	if cmd.Params != nil {
		if err := json.Unmarshal(cmd.Params, &params); err != nil {
			d.emitError(cmd.ID, "invalid_params",
				fmt.Sprintf("invalid params: %v", err))
			return
		}
	}

	target, ok := d.currentRelayTarget()
	if !ok {
		d.emitError(cmd.ID, "relay_not_configured", "relay is not configured — start a relay server first")
		return
	}

	// A token for one peer that cannot be derived is an error: a random
	// token in its place would not be the token the peer derives.
	var staticToken []byte
	relayMode := "random"
	if params.PeerPubB64 != "" {
		if _, err := parsePeerPubB64ToRaw(params.PeerPubB64); err != nil {
			d.emitError(cmd.ID, "invalid_peer_key",
				fmt.Sprintf("invalid peer_pub_b64: %v", err))
			return
		}
		tok, err := d.deriveP2PToken(params.PeerPubB64)
		if err != nil {
			d.emitError(cmd.ID, "relay_token_failed",
				fmt.Sprintf("derive static token: %v", err))
			return
		}
		staticToken = tok
		relayMode = "static"
	}

	d.wg.Go(func() {
		rt, code, err := d.addRelayToken(
			target, staticToken, relayMode, params.PeerPubB64, "",
		)
		if err != nil {
			d.emitError(cmd.ID, code, err.Error())
			return
		}
		d.addLogEntry("INFO", "Generated relay token: "+shortToken(rt.Token))
		d.emit(EvtResponse, cmd.ID, MapA{
			"token": rt.Token, "ttl_ns": rt.TTL,
			"session_ttl_ns": rt.SessionTTL, "expires_at": rt.ExpiresAt,
			"mode": rt.Mode,
		})
	})
}

// relayTarget is the relay of a running relay server, and the listeners
// that the server accepts its connections from.
type relayTarget struct {
	listeners *multiListener
	addr      string
	password  string
	// pin is the relay's certificate fingerprint, or nil.
	pin []byte
}

// currentRelayTarget returns the relay of the running relay server, and
// false when no relay server is running.
func (d *Daemon) currentRelayTarget() (relayTarget, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return relayTarget{
		listeners: d.relayListeners,
		addr:      d.relayAddr,
		password:  d.relayPassword,
		pin:       d.relayPin,
	}, d.relayListeners != nil
}

// addRelayToken registers a new token with target's relay and adds its
// listener to target's server, unless that server has stopped since. The
// registration may take up to d.relayTimeout, so addRelayToken must not
// run on the command loop. resumeOf names the session that the token is
// registered for, so that its peer can resume it, or is empty. On
// failure it returns the error code to report: relay_listen_failed,
// server_stopped or listener_failed.
func (d *Daemon) addRelayToken(
	target relayTarget,
	staticToken []byte,
	mode, peerPubB64, resumeOf string,
) (relayToken, string, error) {
	listener, token, ttl, sessionTTL, err := listenRelayTracked(
		d.ctx, d, target.addr, target.password, target.pin, staticToken,
	)
	if err != nil {
		return relayToken{}, "relay_listen_failed", err
	}
	if tt, ok := listener.(*tokenTracker); ok {
		// Set before the listener is in use.
		tt.resumeOf = resumeOf
	}

	rt := relayToken{
		Token: token, TTL: ttl, SessionTTL: sessionTTL,
		ExpiresAt: time.Now().Add(ttl), Mode: mode,
		PeerPubB64: peerPubB64,
		listener:   listener,
	}
	d.mu.Lock()
	// A server that stopped, or stopped and started again, has other
	// listeners or none.
	if d.relayListeners != target.listeners {
		d.mu.Unlock()
		_ = listener.Close()
		return relayToken{}, "server_stopped",
			errors.New("server stopped while generating token")
	}
	if err := target.listeners.Add(listener); err != nil {
		d.mu.Unlock()
		_ = listener.Close()
		return relayToken{}, "listener_failed",
			fmt.Errorf("add listener: %w", err)
	}
	d.relayTokens = append(d.relayTokens, rt)
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.Unlock()

	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
	return rt, "", nil
}

// handleRemoveRelayToken removes an active relay token.
func (d *Daemon) handleRemoveRelayToken(cmd Command) {
	var params RemoveRelayTokenParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
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
		d.emitError(cmd.ID, "token_not_found", "token not found")
		return
	}
	rt := d.relayTokens[idx]
	d.relayTokens = append(d.relayTokens[:idx], d.relayTokens[idx+1:]...)
	tokens := make([]relayToken, len(d.relayTokens))
	copy(tokens, d.relayTokens)
	d.mu.Unlock()

	// A token that a dropped session would resume on is not registered
	// again once the user removed it.
	if tt, ok := rt.listener.(*tokenTracker); ok {
		tt.removed.Store(true)
	}
	rt.listener.Close()

	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
	d.addLogEntry("INFO", "Removed relay token: "+shortToken(params.Token))
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

// handleGetShareInfo returns a share card for the running server. For a
// relay server the card carries the token of the last card while that is
// fresh, see reusableShareToken, and a newly registered relay token
// otherwise, after the command returns; see addRelayToken.
func (d *Daemon) handleGetShareInfo(cmd Command) {
	d.mu.RLock()
	if d.server == nil {
		d.mu.RUnlock()
		d.emitError(cmd.ID, "server_not_running", "server is not running")
		return
	}
	transport := d.serverTransport
	serverAddr := d.serverBoundAddr
	pubKey := d.pubKey
	brokerAddr := d.serverBrokerAddr
	p2pTokens := d.p2pTokensSnapshot()
	d.mu.RUnlock()

	fp := shareFingerprint{
		Emoji:   strings.Join(fingerprint.Emoji(pubKey), " • "),
		Hex:     fingerprint.Hex(pubKey),
		Numeric: fingerprint.Numeric(pubKey),
	}

	var (
		address   string
		port      string
		relayInfo *relayShareInfo
		urlStr    string
	)

	switch transport {
	case "tcp", "udp", "", "direct-p2p":
		host, p, autoDetect := parseServerAddr(serverAddr)
		port = p
		if autoDetect {
			ip, err := detectLocalIP()
			if err != nil {
				d.emitError(cmd.ID, "detect_ip_failed", fmt.Sprintf("detect local IP: %v", err))
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
		urlStr = scheme + "://" + net.JoinHostPort(address, port)
	case "relay":
		target, ok := d.currentRelayTarget()
		if !ok {
			d.emitError(cmd.ID, "server_stopped", "server stopped while generating token")
			return
		}
		d.wg.Go(func() { d.shareRelayInfo(cmd, target, fp) })
		return
	case "p2p":
		var token string
		if len(p2pTokens) > 0 {
			token = p2pTokens[0].Token
		}
		address = brokerAddr
		urlStr = fmt.Sprintf("p2p://%s?token=%s", brokerAddr, token)
	default:
		d.emitError(cmd.ID, "unknown_transport", fmt.Sprintf("unknown transport: %s", transport))
		return
	}

	d.emit(EvtResponse, cmd.ID, MapA{
		"url":                 urlStr,
		"transport":           transport,
		"address":             address,
		"port":                port,
		"fingerprint_emoji":   fp.Emoji,
		"fingerprint_hex":     fp.Hex,
		"fingerprint_numeric": fp.Numeric,
		"relay_info":          relayInfo,
	})
}

// shareFingerprint is the server's key fingerprint on a share card.
type shareFingerprint struct {
	Emoji, Hex, Numeric string
}

// shareRelayInfo answers get_share_info for a relay server with a card
// that carries the token of the last card while that is fresh, or a
// newly registered relay token.
func (d *Daemon) shareRelayInfo(
	cmd Command, target relayTarget, fp shareFingerprint,
) {
	d.shareMu.Lock()
	defer d.shareMu.Unlock()
	rt, ok := d.reusableShareToken(target)
	if !ok {
		var code string
		var err error
		rt, code, err = d.addRelayToken(target, nil, "random", "", "")
		if err != nil {
			if code == "relay_listen_failed" {
				code = "relay_token_failed"
				err = fmt.Errorf("generate relay token: %w", err)
			}
			d.emitError(cmd.ID, code, err.Error())
			return
		}
		d.mu.Lock()
		if d.relayListeners == target.listeners {
			d.shareListener = rt.listener
		}
		d.mu.Unlock()
		d.addLogEntry("INFO",
			"Share card: generated relay token: "+shortToken(rt.Token))
	}

	scheme, host, _ := parseRelayAddr(target.addr)
	urlStr := fmt.Sprintf(
		"relay://%s?token=%s&scheme=%s", host, rt.Token, scheme,
	)
	if target.password != "" {
		urlStr += "&password=1"
	}
	var pin string
	if target.pin != nil {
		pin = hex.EncodeToString(target.pin)
		urlStr += "&pin=" + pin
	}
	d.emit(EvtResponse, cmd.ID, MapA{
		"url":                 urlStr,
		"transport":           "relay",
		"address":             "",
		"port":                "",
		"fingerprint_emoji":   fp.Emoji,
		"fingerprint_hex":     fp.Hex,
		"fingerprint_numeric": fp.Numeric,
		"relay_info": &relayShareInfo{
			Address: host, Scheme: scheme, Token: rt.Token,
			Password: target.password != "", Pin: pin,
		},
	})
}

// reusableShareToken returns the relay token of the last share card of
// target's server while a peer can still use it for a good while: the
// token list holds it, no peer has used it and it has more than half
// its lifetime left. A client that asks for a card again and again so
// gets the same token, rather than a new relay registration each time.
func (d *Daemon) reusableShareToken(target relayTarget) (relayToken, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.shareListener == nil || d.relayListeners != target.listeners {
		return relayToken{}, false
	}
	if tt, ok := d.shareListener.(*tokenTracker); ok &&
		(tt.consumed.Load() || tt.stopping.Load()) {
		return relayToken{}, false
	}
	for _, rt := range d.relayTokens {
		if rt.listener != d.shareListener {
			continue
		}
		fresh := rt.TTL <= 0 || time.Until(rt.ExpiresAt) > rt.TTL/2
		return rt, fresh && !rt.Consumed
	}
	return relayToken{}, false
}

// loadChatHistory starts the session's message count and last activity
// from its stored history. It reads the stored counter and the last
// entry only, so a long history costs neither time nor memory.
func (d *Daemon) loadChatHistory(session *liveSession) {
	if d.isIncognito() {
		return
	}
	store := d.store()
	if store == nil {
		return
	}

	_, last, count, err := store.SessionTimestamps(session.ID)
	if err != nil {
		d.addLogEntry("DEBUG", "No history for session: "+session.ID)
		return
	}

	session.mu.Lock()
	session.msgCount = count
	if last.After(session.LastActivity) {
		session.LastActivity = last
	}
	session.mu.Unlock()
}

// removeSession removes a session from the map if it matches the session
// pointer, and returns the remaining session count.
func (d *Daemon) removeSession(session *liveSession) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current, ok := d.sessions[session.ID]
	if !ok || current != session {
		return len(d.sessions), false
	}
	delete(d.sessions, session.ID)
	return len(d.sessions), true
}

// finishSession removes session from the live sessions and reports
// that it closed. It returns false, and does nothing, when session is not
// listed: the daemon closed it itself.
func (d *Daemon) finishSession(session *liveSession) bool {
	remaining, removed := d.removeSession(session)
	if !removed {
		return false
	}
	d.emit(EvtSessionClosed, "", d.sessionInfo(session))
	if remaining == 0 {
		d.setStatus(StatusDisconnected, "Not connected")
		d.addLogEntry("INFO", "All sessions disconnected")
	}
	d.loadHistorySessions()
	return true
}

// sessionInfo returns a SessionInfo for a live session (caller does not hold lock).
func (d *Daemon) sessionInfo(s *liveSession) SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return d.sessionInfoLocked(s)
}

// sessionInfoLocked returns a SessionInfo; caller must hold s.mu.
func (d *Daemon) sessionInfoLocked(s *liveSession) SessionInfo {
	return SessionInfo{
		SessionID:        s.ID,
		PeerName:         s.PeerName,
		IsServer:         s.IsServer,
		MsgCount:         s.msgCount,
		LastActivity:     s.LastActivity,
		TransportType:    s.TransportType,
		RemoteVersion:    s.RemoteVersion,
		Cause:            s.Cause,
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

// relayLinkLost removes the relay token of t, whose listener lost its
// link to the relay before a peer used it, and reports it: the relay no
// longer knows the token, so no peer can connect with it. A listener
// registered for a session to resume on is registered again by
// awaitRelayResume.
func (d *Daemon) relayLinkLost(t *tokenTracker) {
	if !d.dropRelayToken(t) {
		return
	}
	if t.resumeOf != "" {
		d.addLogEntry("WARN",
			"Relay reconnect listener for session "+t.resumeOf+
				" lost its relay connection")
		return
	}
	const lost = " lost its relay connection; generate a new relay token"
	d.addLogEntry("WARN", "relay token "+shortToken(t.token)+lost)
	d.emitError("", "relay_link_lost", "relay token "+t.token+lost)
}

// relayTokenExpired removes the relay token of t, which expired before a
// peer used it.
func (d *Daemon) relayTokenExpired(t *tokenTracker) {
	if d.dropRelayToken(t) {
		d.addLogEntry("INFO", "Relay token expired: "+shortToken(t.token))
	}
}

// dropRelayToken removes the relay token whose listener is t from the
// token list and emits the new list, with a warning when it is empty. It
// returns false when the list does not hold t.
func (d *Daemon) dropRelayToken(t *tokenTracker) bool {
	d.mu.Lock()
	idx := slices.IndexFunc(d.relayTokens, func(rt relayToken) bool {
		return rt.listener == t
	})
	if idx == -1 {
		d.mu.Unlock()
		return false
	}
	d.relayTokens = slices.Delete(d.relayTokens, idx, idx+1)
	tokens := slices.Clone(d.relayTokens)
	d.mu.Unlock()

	d.emit(EvtRelayTokens, "", MapA{"tokens": tokens})
	if len(tokens) == 0 {
		// The server keeps running: new tokens can still be registered.
		d.addLogEntry("WARN",
			"The relay server has no relay token left; no peer can "+
				"connect until generate_relay_token or get_share_info "+
				"registers one")
	}
	return true
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

// parseServerAddr splits the bound address addr. autoDetect reports
// that it is bound to every interface, so a local IP must be found to
// share.
func parseServerAddr(addr string) (host, port string, autoDetect bool) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", false
	}
	if ip := net.ParseIP(h); h == "" || ip != nil && ip.IsUnspecified() {
		return "", p, true
	}
	return h, p, false
}

// boundListener is a tcp or udp server's listener, which the daemon
// binds itself to learn the address it is bound to.
type boundListener struct {
	net.Listener
}

// listenDirect binds addr for a server of transport tcp or udp.
func listenDirect(transport, addr string) (*boundListener, error) {
	if addr == "" {
		return nil, errors.New("listen address is required")
	}
	if transport == "udp" {
		l, err := kcp.Listen(addr)
		if err != nil {
			return nil, fmt.Errorf("listening udp: %w", err)
		}
		return &boundListener{Listener: l}, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening tcp: %w", err)
	}
	return &boundListener{Listener: l}, nil
}

func (l *boundListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(c), nil
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

// relayShareInfo is the share-info payload for relay transports. Pin is
// the relay's certificate fingerprint in hex, when the server pins it.
type relayShareInfo struct {
	Address  string `json:"address"`
	Scheme   string `json:"scheme"`
	Token    string `json:"token"`
	Password bool   `json:"password"`
	Pin      string `json:"pin,omitempty"`
}

// waitOrTimeout waits for ch or returns after channelTimeout.
func waitOrTimeout[T any](ch <-chan T, label string) {
	select {
	case <-ch:
	case <-time.After(channelTimeout):
		slog.Warn("Timeout waiting for " + label)
	}
}

func (d *Daemon) stopRelayResources() {
	d.mu.Lock()
	listeners := d.relayListeners
	d.relayListeners = nil
	d.relayTokens = nil
	d.shareListener = nil
	d.relayAddr = ""
	d.relayPassword = ""
	d.relayPin = nil
	d.mu.Unlock()
	if listeners != nil {
		_ = listeners.Close()
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
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "-")
	v, _, _ = strings.Cut(v, "+")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ver{}, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ver{}, false
	}
	return ver{major: maj, minor: min}, true
}
