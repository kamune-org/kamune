package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

type appState int

const (
	stateWelcome appState = iota
	stateInput
	stateConnecting
	stateVerify
	stateChat
	stateHistory
)

type inputMode int

const (
	modeDirectDial inputMode = iota
	modeDirectServe
	modeRelayDial
	modeRelayServe
)

type connectedMsg struct {
	transport  *kamune.Transport
	isServer   bool
	sessionTTL time.Duration
}

type connectFailedMsg struct {
	err error
}

type verifyRequest struct {
	peer *storage.Peer
	// knownName is the name stored for the peer's key, if it is known.
	knownName string
	// numericFP and localNumericFP are the fingerprint.Numeric of the
	// peer's key and of the local identity key.
	numericFP      string
	localNumericFP string
	emojiFP        string
	hexFP          string
	responseCh     chan<- error
	isNew          bool
}

type relayReadyMsg struct {
	token      []byte
	sessionTTL time.Duration
}

type tickMsg time.Time

type chatMessageMsg struct {
	sender storage.Sender
	text   string
	time   time.Time
}

type peerDisconnectedMsg struct{}

type receiveErrorMsg struct {
	err error
}

type historySessionsMsg struct {
	sessions []storage.SessionSummary
	err      error
}

type historyMessagesMsg struct {
	sessionID string
	messages  []chatLine
}

type historyLoadedMsg struct {
	messages []chatLine
}

type styles struct {
	title      lipgloss.Style
	bold       lipgloss.Style
	muted      lipgloss.Style
	err        lipgloss.Style
	highlight  lipgloss.Style
	good       lipgloss.Style
	userPrefix lipgloss.Style
	userText   lipgloss.Style
	peerPrefix lipgloss.Style
	peerText   lipgloss.Style
}

func defaultStyles() styles {
	return styles{
		title:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#43BF6D")),
		bold:       lipgloss.NewStyle().Bold(true),
		muted:      lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")),
		err:        lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")),
		highlight:  lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")),
		good:       lipgloss.NewStyle().Foreground(lipgloss.Color("#43BF6D")),
		userPrefix: lipgloss.NewStyle().Foreground(lipgloss.Color("#4A90E2")),
		userText:   lipgloss.NewStyle().Foreground(lipgloss.Color("#E0F0FF")),
		peerPrefix: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		peerText:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF7E1")),
	}
}

var menuItems = []string{
	"Direct Connect (TCP)",
	"Start Server (TCP)",
	"Connect via Relay",
	"Start Relay Server",
	"View Chat History",
	"Quit",
}

type model struct {
	program *tea.Program
	store   *storage.Storage
	state   appState
	cursor  int

	// Input
	mode   inputMode
	inputs []textinput.Model

	// Connecting
	connectErr      error
	connCtx         context.Context
	connCancel      context.CancelFunc
	srv             *kamune.Server
	doneCh          chan struct{}
	connCh          chan *kamune.Transport
	relayToken      []byte
	relaySessionTTL time.Duration
	sessionExpiry   time.Time

	// Verify
	verifyReq *verifyRequest

	// Chat
	transport     *kamune.Transport
	pingFailures  int
	lastPongAt    time.Time
	pongCh        chan []byte
	keepAliveDone chan struct{}
	vp            viewport.Model
	ta            textarea.Model
	messages      []chatLine
	versionWarn   string

	// History
	sessions    []storage.SessionSummary
	histCursor  int
	histVP      viewport.Model
	histMsgs    []chatLine
	histViewing bool

	// Window
	width  int
	height int

	s styles
}

func (m *model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case connectedMsg:
		m.transport = msg.transport
		if msg.sessionTTL > 0 {
			m.relaySessionTTL = msg.sessionTTL
		}
		return m.enterChat()
	case connectFailedMsg:
		if m.state != stateConnecting {
			return m, nil
		}
		m.connectErr = msg.err
		m.cancelConnect()
		m.state = stateWelcome
		return m, nil
	case verifyRequest:
		if m.state != stateConnecting {
			return m, nil
		}
		m.verifyReq = &msg
		m.state = stateVerify
		return m, nil
	case tickMsg:
		if m.state == stateChat && !m.sessionExpiry.IsZero() {
			return m, tickCountdown()
		}
		return m, nil
	case relayReadyMsg:
		m.relayToken = msg.token
		m.relaySessionTTL = msg.sessionTTL
		return m, nil
	case chatMessageMsg:
		return m.handleChatMessage(msg), nil
	case peerDisconnectedMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(m.messages, noticeLine(
			m.s.highlight, "Peer disconnected. Press Esc to return.",
		))
		m.refreshChat()
		return m, nil
	case receiveErrorMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(m.messages,
			noticeLine(m.s.err, "Error: "+msg.err.Error()),
		)
		m.refreshChat()
		return m, nil
	case historySessionsMsg:
		if msg.err != nil {
			m.connectErr = msg.err
			m.state = stateWelcome
			return m, nil
		}
		m.sessions = msg.sessions
		m.histCursor = 0
		m.state = stateHistory
		return m, nil
	case historyMessagesMsg:
		m.histMsgs = msg.messages
		m.histViewing = true
		m.histVP = viewport.New(m.width-2, m.height-4)
		m.histVP.MouseWheelEnabled = true
		m.refreshHistory()
		return m, nil
	case historyLoadedMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(msg.messages, m.messages...)
		m.refreshChat()
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.cleanup()
			return m, tea.Quit
		}
	}

	switch m.state {
	case stateWelcome:
		return m.updateWelcome(msg)
	case stateInput:
		return m.updateInput(msg)
	case stateConnecting:
		return m.updateConnecting(msg)
	case stateVerify:
		return m.updateVerify(msg)
	case stateChat:
		return m.updateChat(msg)
	case stateHistory:
		return m.updateHistory(msg)
	}
	return m, nil
}

func (m *model) View() string {
	switch m.state {
	case stateWelcome:
		return m.viewWelcome()
	case stateInput:
		return m.viewInput()
	case stateConnecting:
		return m.viewConnecting()
	case stateVerify:
		return m.viewVerify()
	case stateChat:
		return m.viewChat()
	case stateHistory:
		return m.viewHistory()
	}
	return ""
}

// refreshChat lays the transcript out for the chat viewport and scrolls to
// its end.
func (m *model) refreshChat() {
	m.vp.SetContent(m.s.renderLines(m.messages, contentWidth(m.vp)))
	m.vp.GotoBottom()
}

// refreshHistory lays the messages of the history browser out for its
// viewport.
func (m *model) refreshHistory() {
	if len(m.histMsgs) == 0 {
		m.histVP.SetContent("(no messages)")
		return
	}
	m.histVP.SetContent(m.s.renderLines(m.histMsgs, contentWidth(m.histVP)))
}

func (m *model) mkVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		var isNew bool
		var knownName string
		if known, err := store.FindPeer(peer.PublicKey); err != nil {
			isNew = true
		} else {
			knownName = known.Name
		}
		key := peer.PublicKey
		var localFP string
		if own, err := store.PublicKey(); err == nil {
			localFP = fingerprint.Numeric(own)
		}
		respCh := make(chan error, 1)
		m.program.Send(verifyRequest{
			peer:           peer,
			isNew:          isNew,
			knownName:      knownName,
			numericFP:      fingerprint.Numeric(key),
			localNumericFP: localFP,
			emojiFP:        strings.Join(fingerprint.Emoji(key), " • "),
			hexFP:          fingerprint.Hex(key),
			responseCh:     respCh,
		})
		err := <-respCh
		if err == nil && isNew {
			peer.FirstSeen = time.Now()
			if serr := store.StorePeer(peer); serr != nil {
				slog.Error("failed to store peer", "error", serr)
			}
		}
		return err
	}
}

func (m *model) startConnect() tea.Cmd {
	vfn := m.mkVerifier()
	m.connCtx, m.connCancel = context.WithCancel(context.Background())

	switch m.mode {
	case modeDirectDial:
		go func() {
			t, err := dial(m.inputs[0].Value(), m.store, vfn)
			if err != nil {
				m.program.Send(connectFailedMsg{err})
				return
			}
			warn, _ := checkMinorMismatch(kamune.AppVersion, t.RemotePeer().AppVersion)
			m.versionWarn = warn
			m.program.Send(connectedMsg{transport: t})
		}()
		return nil

	case modeDirectServe:
		connCh := make(chan *kamune.Transport, 1)
		doneCh := make(chan struct{})
		m.connCh = connCh
		m.doneCh = doneCh
		srv, err := serve(m.inputs[0].Value(), m.store, vfn, connCh, doneCh)
		if err != nil {
			return func() tea.Msg { return connectFailedMsg{err} }
		}
		m.srv = srv
		return waitConn(m.connCtx, connCh, true)

	case modeRelayDial:
		addr := m.inputs[0].Value()
		token := m.inputs[1].Value()
		go func() {
			t, sessionTTL, err := relayDial(addr, token, "", m.store, vfn)
			if err != nil {
				m.program.Send(connectFailedMsg{err})
				return
			}
			warn, _ := checkMinorMismatch(kamune.AppVersion, t.RemotePeer().AppVersion)
			m.versionWarn = warn
			m.program.Send(connectedMsg{transport: t, sessionTTL: sessionTTL})
		}()
		return nil

	case modeRelayServe:
		connCh := make(chan *kamune.Transport, 1)
		doneCh := make(chan struct{})
		m.connCh = connCh
		m.doneCh = doneCh
		addr := m.inputs[0].Value()
		go func() {
			srv, token, sessionTTL, err := relayServe(addr, "", m.store, vfn, connCh, doneCh)
			if err != nil {
				m.program.Send(connectFailedMsg{err})
				return
			}
			m.srv = srv
			m.program.Send(relayReadyMsg{token: token, sessionTTL: sessionTTL})
		}()
		return waitConn(m.connCtx, connCh, true)
	}
	return nil
}

func waitConn(ctx context.Context, connCh <-chan *kamune.Transport, isServer bool) tea.Cmd {
	return func() tea.Msg {
		select {
		case t := <-connCh:
			return connectedMsg{transport: t, isServer: isServer}
		case <-ctx.Done():
			return nil
		}
	}
}

func tickCountdown() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *model) enterChat() (tea.Model, tea.Cmd) {
	m.state = stateChat
	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	if peer := m.transport.RemotePeer(); peer != nil {
		err := m.store.CreateSession(m.transport.SessionID(), peer.PublicKey)
		if err != nil {
			slog.Warn("failed to create session record",
				slog.String("session_id", m.transport.SessionID()),
				slog.Any("error", err),
			)
		}
	}

	m.ta = textarea.New()
	m.ta.Placeholder = "Send a message..."
	m.ta.Focus()
	m.ta.FocusedStyle = textarea.Style{
		Base: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#43BF6D")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#383838")).
			Padding(0, 1),
		CursorLine: lipgloss.NewStyle(),
	}
	m.ta.Prompt = "┃ "
	m.ta.CharLimit = 280
	m.ta.SetWidth(30)
	m.ta.SetHeight(3)
	m.ta.ShowLineNumbers = false
	m.ta.KeyMap.InsertNewline.SetEnabled(false)

	if m.width > 0 {
		m.ta.SetWidth(m.width)
	}

	vp := viewport.New(30, 5)
	vp.MouseWheelEnabled = true
	vp.Style = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#383838")).
		Padding(0, 1)

	if m.width > 0 {
		vp.Width = m.width
	}
	if m.height > 0 {
		vp.Height = m.height - m.ta.Height() - lipgloss.Height("\n\n")
	}

	if m.versionWarn != "" {
		m.messages = []chatLine{
			noticeLine(m.s.highlight, "⚠ "+m.versionWarn),
		}
	}
	m.vp = vp
	m.vp.SetContent("Session ID is " + m.transport.SessionID() + ". Loading history…")

	m.pongCh = make(chan []byte, 1)
	m.startReceiving()
	m.keepAliveDone = make(chan struct{})
	go m.keepAliveLoop()
	if !m.sessionExpiry.IsZero() {
		return m, tea.Batch(loadChatHistory(m), tickCountdown())
	}
	return m, loadChatHistory(m)
}

func loadChatHistory(m *model) tea.Cmd {
	return func() tea.Msg {
		entries, err := m.store.GetChatHistory(m.transport.SessionID())
		if err != nil {
			slog.Warn("failed to load chat history",
				slog.String("session_id", m.transport.SessionID()),
				slog.Any("error", err),
			)
			return historyLoadedMsg{messages: []chatLine{noticeLine(
				m.s.err, "Could not load chat history: "+err.Error(),
			)}}
		}
		sid := m.transport.SessionID()
		header := "Session ID is " + sid + ". Happy Chatting!"
		if len(entries) > 0 {
			header = fmt.Sprintf("Session ID is %s. Restored %d message(s). Happy Chatting!",
				sid, len(entries))
		}
		msgs := []chatLine{noticeLine(m.s.muted, header)}
		for _, ent := range entries {
			msgs = append(msgs,
				messageLine(ent.Sender, ent.Timestamp, string(ent.Data)),
			)
		}
		return historyLoadedMsg{messages: msgs}
	}
}

func (m *model) startReceiving() {
	go receiveLoop(m.transport, m.pongCh, m.program.Send)
}

// receiveLoop reads frames from t and passes what they mean to send until
// the transport fails or the peer leaves. Only RouteExchangeMessages frames
// are chat. Pings are answered and pongs go to pongCh. Frames on other
// routes, such as the RouteSessionData frame that bus and the daemon send
// to set up relay tokens, are of no use to the TUI and are dropped.
func receiveLoop(
	t *kamune.Transport, pongCh chan<- []byte, send func(tea.Msg),
) {
	for {
		metadata, payload, err := t.ReceivePayload()
		if err != nil {
			switch {
			case errors.Is(err, kamune.ErrPeerDisconnected),
				errors.Is(err, kamune.ErrConnClosed):
				send(peerDisconnectedMsg{})
				return
			case errors.Is(err, kamune.ErrReceiveTimeout):
				continue
			default:
				send(receiveErrorMsg{err})
				return
			}
		}

		route := metadata.Route()
		switch route {
		case kamune.RouteExchangeMessages, kamune.RoutePing,
			kamune.RoutePong:
		default:
			slog.Debug("dropping frame", slog.String("route", route.String()))
			continue
		}
		b := kamune.Bytes(nil)
		if err := proto.Unmarshal(payload, b); err != nil {
			send(receiveErrorMsg{fmt.Errorf("decoding %s: %w", route, err)})
			continue
		}

		switch route {
		case kamune.RoutePing:
			_, _ = t.Send(kamune.Bytes(b.GetValue()), kamune.RoutePong)
		case kamune.RoutePong:
			select {
			case pongCh <- b.GetValue():
			default:
			}
		default:
			send(chatMessageMsg{
				sender: storage.SenderPeer,
				text:   string(b.GetValue()),
				time:   metadata.Timestamp(),
			})
		}
	}
}

// keepAliveLoop sends periodic pings to detect dead connections. After
// 3 consecutive failures, the peer is considered unresponsive.
func (m *model) keepAliveLoop() {
	const pingTimeout = 10 * time.Second
	defer close(m.keepAliveDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.doneCh:
			return
		case <-ticker.C:
			if err := tuiSendPing(m.transport, m.pongCh, pingTimeout); err != nil {
				m.pingFailures++
				if m.pingFailures >= 3 {
					m.program.Send(peerDisconnectedMsg{})
					return
				}
			} else {
				m.pingFailures = 0
				m.lastPongAt = time.Now()
			}
		}
	}
}

// tuiSendPing sends a RoutePing and waits for a matching RoutePong
// within timeout.
func tuiSendPing(t *kamune.Transport, pongCh <-chan []byte, timeout time.Duration) error {
	const pingDataSize = 8
	tok := make([]byte, pingDataSize)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	if _, err := t.Send(kamune.Bytes(tok), kamune.RoutePing); err != nil {
		return err
	}
	select {
	case <-pongCh:
	default:
	}
	select {
	case data := <-pongCh:
		if string(data) != string(tok) {
			return kamune.ErrVerificationFailed
		}
		return nil
	case <-time.After(timeout):
		return kamune.ErrReceiveTimeout
	}
}

func (m *model) handleChatMessage(msg chatMessageMsg) *model {
	m.messages = append(m.messages,
		messageLine(storage.SenderPeer, msg.time, msg.text),
	)
	if m.store != nil {
		if err := m.store.AddChatEntry(
			m.transport.SessionID(),
			[]byte(msg.text),
			msg.time,
			storage.SenderPeer,
		); err != nil {
			slog.Error("failed to persist received chat entry",
				slog.String("session_id", m.transport.SessionID()),
				slog.Any("error", err),
			)
			m.messages = append(m.messages, notSavedLine(m.s, err))
		}
	}
	m.refreshChat()
	return m
}

func (m *model) cancelConnect() {
	if m.connCancel != nil {
		m.connCancel()
		m.connCancel = nil
	}
	if m.srv != nil {
		m.srv.Close()
		m.srv = nil
	}
	m.connCh = nil
	m.doneCh = nil
	m.relayToken = nil
	m.relaySessionTTL = 0
	m.sessionExpiry = time.Time{}
}

func (m *model) cleanup() {
	if m.connCancel != nil {
		m.connCancel()
		m.connCancel = nil
	}
	if m.doneCh != nil {
		close(m.doneCh)
		m.doneCh = nil
	}
	if m.keepAliveDone != nil {
		<-m.keepAliveDone
		m.keepAliveDone = nil
	}
	if m.transport != nil {
		m.transport.Close()
		m.transport = nil
	}
	if m.srv != nil {
		m.srv.Close()
		m.srv = nil
	}
	m.connCh = nil
	m.relayToken = nil
	m.relaySessionTTL = 0
	m.sessionExpiry = time.Time{}
}
