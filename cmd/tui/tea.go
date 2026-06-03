package main

import (
	"context"
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
	transport *kamune.Transport
	isServer  bool
}

type connectFailedMsg struct {
	err error
}

type verifyRequest struct {
	peer       *storage.Peer
	isNew      bool
	emojiFP    string
	hexFP      string
	responseCh chan<- error
}

type relayReadyMsg struct {
	token []byte
}

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
	messages  []string
}

type historyLoadedMsg struct {
	messages []string
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
	connectErr error
	connCtx    context.Context
	connCancel context.CancelFunc
	srv        *kamune.Server
	doneCh     chan struct{}
	connCh     chan *kamune.Transport
	relayToken []byte

	// Verify
	verifyReq *verifyRequest

	// Chat
	transport   *kamune.Transport
	vp          viewport.Model
	ta          textarea.Model
	messages    []string
	versionWarn string

	// History
	sessions    []storage.SessionSummary
	histCursor  int
	histVP      viewport.Model
	histMsgs    []string
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
	case relayReadyMsg:
		m.relayToken = msg.token
		return m, nil
	case chatMessageMsg:
		return m.handleChatMessage(msg), nil
	case peerDisconnectedMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(m.messages, m.s.highlight.Render("Peer disconnected. Press Esc to return."))
		m.vp.SetContent(renderChatContent(m))
		m.vp.GotoBottom()
		return m, nil
	case receiveErrorMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(m.messages, m.s.err.Render("Error: "+msg.err.Error()))
		m.vp.SetContent(renderChatContent(m))
		m.vp.GotoBottom()
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
		content := strings.Join(msg.messages, "\n")
		if content == "" {
			content = "(no messages)"
		}
		m.histVP.SetContent(content)
		m.histVP.MouseWheelEnabled = true
		return m, nil
	case historyLoadedMsg:
		if m.state != stateChat {
			return m, nil
		}
		m.messages = append(msg.messages, m.messages...)
		m.vp.SetContent(renderChatContent(m))
		m.vp.GotoBottom()
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

func renderChatContent(m *model) string {
	return lipgloss.NewStyle().Width(m.vp.Width).Render(strings.Join(m.messages, "\n"))
}

func (m *model) mkVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		var isNew bool
		if _, err := store.FindPeer(peer.PublicKey); err != nil {
			isNew = true
		}
		key := peer.PublicKey
		emojiFP := strings.Join(fingerprint.Emoji(key), " • ")
		hexFP := fingerprint.Hex(key)
		respCh := make(chan error, 1)
		m.program.Send(verifyRequest{
			peer:       peer,
			isNew:      isNew,
			emojiFP:    emojiFP,
			hexFP:      hexFP,
			responseCh: respCh,
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
			t, err := relayDial(addr, token, "", m.store, vfn)
			if err != nil {
				m.program.Send(connectFailedMsg{err})
				return
			}
			warn, _ := checkMinorMismatch(kamune.AppVersion, t.RemotePeer().AppVersion)
			m.versionWarn = warn
			m.program.Send(connectedMsg{transport: t})
		}()
		return nil

	case modeRelayServe:
		connCh := make(chan *kamune.Transport, 1)
		doneCh := make(chan struct{})
		m.connCh = connCh
		m.doneCh = doneCh
		addr := m.inputs[0].Value()
		go func() {
			srv, token, err := relayServe(addr, "", m.store, vfn, connCh, doneCh)
			if err != nil {
				m.program.Send(connectFailedMsg{err})
				return
			}
			m.srv = srv
			m.program.Send(relayReadyMsg{token: token})
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

func (m *model) enterChat() (tea.Model, tea.Cmd) {
	m.state = stateChat
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
		m.messages = []string{m.s.highlight.Render("⚠ " + m.versionWarn)}
	}
	m.vp = vp
	m.vp.SetContent("Session ID is " + m.transport.SessionID() + ". Loading history…")

	m.startReceiving()
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
			return nil
		}
		sid := m.transport.SessionID()
		header := "Session ID is " + sid + ". Happy Chatting!"
		if len(entries) > 0 {
			header = fmt.Sprintf("Session ID is %s. Restored %d message(s). Happy Chatting!",
				sid, len(entries))
		}
		msgs := []string{m.s.muted.Render(header)}

		for _, ent := range entries {
			sender := "You"
			ps := m.s.userPrefix
			ts := m.s.userText
			if ent.Sender != storage.SenderLocal {
				sender = "Peer"
				ps = m.s.peerPrefix
				ts = m.s.peerText
			}
			prefix := ps.Render("[" + ent.Timestamp.Format(time.DateTime) + "] " + sender + ": ")
			msg := prefix + ts.Render(string(ent.Data))
			msgs = append(msgs, msg)
		}
		return historyLoadedMsg{messages: msgs}
	}
}

func (m *model) startReceiving() {
	go func() {
		for {
			b := kamune.Bytes(nil)
			metadata, err := m.transport.Receive(b)
			if err != nil {
				switch {
				case errors.Is(err, kamune.ErrPeerDisconnected):
					m.program.Send(peerDisconnectedMsg{})
					return
				case errors.Is(err, kamune.ErrConnClosed):
					m.program.Send(peerDisconnectedMsg{})
					return
				case errors.Is(err, kamune.ErrReceiveTimeout):
					continue
				default:
					m.program.Send(receiveErrorMsg{err})
					return
				}
			}
			text := string(b.GetValue())
			m.program.Send(chatMessageMsg{
				sender: storage.SenderPeer,
				text:   text,
				time:   metadata.Timestamp(),
			})
		}
	}()
}

func (m *model) handleChatMessage(msg chatMessageMsg) *model {
	prefix := m.s.peerPrefix.Render("[" + msg.time.Format(time.DateTime) + "] Peer: ")
	m.messages = append(m.messages, prefix+m.s.peerText.Render(msg.text))
	m.vp.SetContent(renderChatContent(m))
	m.vp.GotoBottom()
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
	}
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
}
