package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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

// attempt is one connection attempt: a dial, or a server waiting for a
// peer. Its goroutines stop when its context is cancelled, and every
// message they send names it, so that Update can tell those messages from
// the ones of an attempt that is over. They report to Update only through
// messages and never touch the model.
type attempt struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newAttempt() *attempt {
	ctx, cancel := context.WithCancel(context.Background())
	return &attempt{ctx: ctx, cancel: cancel}
}

type connectedMsg struct {
	att       *attempt
	transport *kamune.Transport
	// release, when set, is closed once the session is over. The server
	// handler that delivered transport waits for it, since the
	// connection is closed when the handler returns.
	release    chan struct{}
	sessionTTL time.Duration
}

type connectFailedMsg struct {
	att *attempt
	err error
}

type verifyRequest struct {
	att  *attempt
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

// verifyEndedMsg tells Update that the verifier stopped waiting for the
// answer to the prompt of the request with responseCh, so that the prompt
// can close.
type verifyEndedMsg struct {
	responseCh chan<- error
	err        error
}

// verifyPromptTimeout is how long the verifier waits for the user to
// answer a prompt before it rejects the peer. The kamune handshake allows
// the verifier a little longer.
const verifyPromptTimeout = 2 * time.Minute

var (
	// errPromptOpen rejects a peer that arrives while the prompt for
	// another peer is open.
	errPromptOpen = fmt.Errorf(
		"%w: another peer is being verified", kamune.ErrVerificationFailed,
	)
	// errPromptNotShown rejects a peer whose prompt cannot be shown, as
	// when a chat has started already.
	errPromptNotShown = fmt.Errorf(
		"%w: no prompt can be shown now", kamune.ErrVerificationFailed,
	)
	// errPromptTimeout rejects a peer that the user did not answer for
	// within verifyPromptTimeout.
	errPromptTimeout = fmt.Errorf(
		"%w: no answer in time", kamune.ErrVerificationFailed,
	)
	// errAttemptCancelled rejects a peer whose connection attempt was
	// cancelled while its prompt was open.
	errAttemptCancelled = fmt.Errorf(
		"%w: connection attempt cancelled", kamune.ErrVerificationFailed,
	)
)

// relayReadyMsg says that the relay server of att is registered with the
// relay under token, and hands srv to Update. Update closes srv when att
// is over, or, if srv's session starts a chat, when that chat ends.
type relayReadyMsg struct {
	att        *attempt
	srv        *kamune.Server
	token      []byte
	sessionTTL time.Duration
}

type tickMsg time.Time

type chatMessageMsg struct {
	time time.Time
	// saveErr is why the message could not be added to the history.
	saveErr error
	text    string
	sender  storage.Sender
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
	// send passes a message to the program's event loop. Goroutines use
	// it to report to Update.
	send   func(tea.Msg)
	store  *storage.Storage
	state  appState
	cursor int

	// Input
	mode   inputMode
	inputs []textinput.Model

	// Connecting
	connectErr error
	// att is the connection attempt in progress, if any.
	att             *attempt
	srv             *kamune.Server
	relayToken      []byte
	relaySessionTTL time.Duration
	sessionExpiry   time.Time

	// Verify
	verifyReq *verifyRequest
	// promptTimeout overrides verifyPromptTimeout when it is positive.
	promptTimeout time.Duration

	// Chat
	sess     *chatSession
	vp       viewport.Model
	ta       textarea.Model
	messages []chatLine
	// rendered holds messages laid out for a view renderedWidth cells
	// wide, when it has as many entries as messages.
	rendered      []string
	renderedWidth int

	// History
	sessions    []storage.SessionSummary
	histCursor  int
	histVP      viewport.Model
	histMsgs    []chatLine
	histViewing bool

	// Window
	width  int
	height int

	// closing tracks the goroutines that close sessions and servers off
	// the event loop. shutdown waits for them.
	closing sync.WaitGroup

	s styles
}

// closeWait bounds how long the TUI waits on exit for its sessions and
// servers to close. Transport.Close gives up on the close frame after
// 5 seconds.
const closeWait = 10 * time.Second

// outboxSize is how many messages a chat may have waiting to be sent.
const outboxSize = 16

// sentMsg reports what came of sending text in a chat.
type sentMsg struct {
	at  time.Time
	err error
	// saveErr is why the sent message could not be added to the history.
	saveErr error
	text    string
}

// chatSession is the state of a chat that the goroutines serving it
// share. They get it as an argument and never read the model, which only
// Update may touch.
type chatSession struct {
	t *kamune.Transport
	// stop is closed when the chat ends.
	stop   chan struct{}
	pongCh chan []byte
	// outbox holds the messages the user sent that writeLoop has yet to
	// send.
	outbox chan string
	// release is the release channel of the connectedMsg that delivered
	// t, if it had one.
	release chan struct{}
}

func newChatSession(t *kamune.Transport, release chan struct{}) *chatSession {
	return &chatSession{
		t:       t,
		stop:    make(chan struct{}),
		pongCh:  make(chan []byte, 1),
		outbox:  make(chan string, outboxSize),
		release: release,
	}
}

// sessionMsg carries msg from a goroutine of the chat session sess. Update
// applies it only while sess is the chat on screen, so that what a chat
// sends while it ends does not land on the screen or the session that
// comes after it.
type sessionMsg struct {
	sess *chatSession
	msg  tea.Msg
}

// sender returns a function that passes the messages of s to send.
func (s *chatSession) sender(send func(tea.Msg)) func(tea.Msg) {
	return func(msg tea.Msg) { send(sessionMsg{sess: s, msg: msg}) }
}

// end stops the goroutines of the session. It closes the transport, and
// then srv if it is set, on a goroutine that wg tracks: Transport.Close
// sends a frame and may wait a few seconds for it.
func (s *chatSession) end(wg *sync.WaitGroup, srv *kamune.Server) {
	close(s.stop)
	wg.Go(func() {
		closeSession(s.t, s.release)
		if srv != nil {
			_ = srv.Close()
		}
	})
}

// writeLoop sends the messages queued in the outbox of s, in order, until
// the session stops, adds each one sent to the history in store, and
// passes the result of each to send. A send may block for as long as the
// connection lets it, and the history is a database write, so neither
// runs on the event loop.
func writeLoop(s *chatSession, store *storage.Storage, send func(tea.Msg)) {
	for {
		select {
		case <-s.stop:
			return
		case text := <-s.outbox:
			md, err := s.t.Send(
				kamune.Bytes([]byte(text)), kamune.RouteExchangeMessages,
			)
			res := sentMsg{text: text, err: err}
			if err == nil {
				res.at = md.Timestamp()
				res.saveErr = saveEntry(
					store, s.t.SessionID(), text, res.at,
					storage.SenderLocal,
				)
			}
			send(res)
		}
	}
}

// saving returns a send function for the receive loop of the session sid
// that adds each chat message to the history in store before it passes
// the message on to send. The database write thus runs on the receive
// goroutine, not on the event loop.
func saving(
	store *storage.Storage, sid string, send func(tea.Msg),
) func(tea.Msg) {
	return func(msg tea.Msg) {
		if c, ok := msg.(chatMessageMsg); ok {
			c.saveErr = saveEntry(store, sid, c.text, c.time, c.sender)
			msg = c
		}
		send(msg)
	}
}

// saveEntry adds a chat message to the history of the session sid in
// store, if there is a store.
func saveEntry(
	store *storage.Storage, sid, text string, at time.Time,
	sender storage.Sender,
) error {
	if store == nil {
		return nil
	}
	err := store.AddChatEntry(sid, []byte(text), at, sender)
	if err != nil {
		slog.Error("failed to persist chat entry",
			slog.String("session_id", sid),
			slog.Any("error", err),
		)
	}
	return err
}

// closeSession closes t and then release, if it is set. A server handler
// that waits for release returns only once the close frame has gone out,
// since its return closes the connection.
func closeSession(t *kamune.Transport, release chan struct{}) {
	_ = t.Close()
	if release != nil {
		close(release)
	}
}

func (m *model) Init() tea.Cmd {
	return textinput.Blink
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case connectedMsg:
		if msg.att == nil || msg.att != m.att ||
			(m.state != stateConnecting && m.state != stateVerify) {
			// Nobody waits for this session: its attempt is over, or a
			// chat has started already. End it rather than let it take
			// the place of the chat on screen. Closing it sends a frame,
			// so it is not done on the event loop.
			m.closing.Go(func() {
				closeSession(msg.transport, msg.release)
			})
			return m, nil
		}
		if m.state == stateVerify {
			// A peer accepted earlier, or one that resumed its session,
			// got through while the prompt for another was open.
			answer(m.verifyReq.responseCh, errPromptNotShown)
			m.verifyReq = nil
		}
		if msg.sessionTTL > 0 {
			m.relaySessionTTL = msg.sessionTTL
		}
		return m.enterChat(msg)
	case connectFailedMsg:
		if msg.att != m.att ||
			(m.state != stateConnecting && m.state != stateVerify) {
			return m, nil
		}
		if m.verifyReq != nil {
			answer(m.verifyReq.responseCh, errAttemptCancelled)
			m.verifyReq = nil
		}
		m.connectErr = msg.err
		m.cancelConnect()
		m.state = stateWelcome
		return m, nil
	case verifyRequest:
		if msg.att != m.att {
			answer(msg.responseCh, errAttemptCancelled)
			return m, nil
		}
		if m.state != stateConnecting {
			// Nobody would see the prompt. Reject the peer now rather
			// than leave its handshake waiting for an answer.
			answer(msg.responseCh, errPromptNotShown)
			return m, nil
		}
		m.verifyReq = &msg
		m.state = stateVerify
		return m, nil
	case verifyEndedMsg:
		if m.state != stateVerify || m.verifyReq == nil ||
			m.verifyReq.responseCh != msg.responseCh {
			return m, nil
		}
		m.verifyReq = nil
		m.connectErr = msg.err
		m.state = stateConnecting
		return m, nil
	case tickMsg:
		if m.state == stateChat && !m.sessionExpiry.IsZero() {
			return m, tickCountdown()
		}
		return m, nil
	case relayReadyMsg:
		if msg.att != m.att {
			// The user gave up on this relay server while it was being
			// set up. Closing it unregisters it from the relay.
			m.closing.Go(func() { _ = msg.srv.Close() })
			return m, nil
		}
		m.srv = msg.srv
		m.relayToken = msg.token
		m.relaySessionTTL = msg.sessionTTL
		return m, nil
	case sessionMsg:
		if msg.sess == nil || msg.sess != m.sess || m.state != stateChat {
			// The chat that sent it is over.
			return m, nil
		}
		m.updateSession(msg.msg)
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

// updateSession applies msg, which came from a goroutine of the chat on
// screen, m.sess.
func (m *model) updateSession(msg tea.Msg) {
	switch msg := msg.(type) {
	case chatMessageMsg:
		m.handleChatMessage(msg)
	case peerDisconnectedMsg:
		m.addLines(noticeLine(
			m.s.highlight, "Peer disconnected. Press Esc to return.",
		))
	case receiveErrorMsg:
		m.addLines(noticeLine(m.s.err, "Error: "+msg.err.Error()))
	case historyLoadedMsg:
		m.messages = append(msg.messages, m.messages...)
		m.rendered = nil
		m.trimTranscript()
		m.refreshChat()
	case sentMsg:
		m.handleSent(msg)
	}
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

// refreshChat shows the transcript in the chat viewport and scrolls to
// its end. Only the entries that have not been laid out for the width of
// the viewport yet are laid out.
func (m *model) refreshChat() {
	width := contentWidth(m.vp)
	if width != m.renderedWidth || len(m.rendered) != len(m.messages) {
		m.rendered = m.rendered[:0]
		m.renderedWidth = width
		for _, l := range m.messages {
			m.rendered = append(m.rendered, m.s.renderLine(l, width))
		}
	}
	m.vp.SetContent(strings.Join(m.rendered, "\n"))
	m.vp.GotoBottom()
}

// addLines adds lines to the end of the chat transcript and shows them.
func (m *model) addLines(lines ...chatLine) {
	width := contentWidth(m.vp)
	laidOut := width == m.renderedWidth &&
		len(m.rendered) == len(m.messages)
	m.messages = append(m.messages, lines...)
	if laidOut {
		for _, l := range lines {
			m.rendered = append(m.rendered, m.s.renderLine(l, width))
		}
	}
	m.trimTranscript()
	m.refreshChat()
}

// trimTranscript drops the oldest entries of the chat transcript beyond
// maxTranscriptLines, and puts a notice in their place.
func (m *model) trimTranscript() {
	over := len(m.messages) - maxTranscriptLines
	if over <= 0 {
		return
	}
	over++ // room for the notice
	laidOut := len(m.rendered) == len(m.messages)
	notice := noticeLine(m.s.muted,
		"Earlier messages are left out here; View Chat History has them.",
	)
	m.messages = append([]chatLine{notice}, m.messages[over:]...)
	if laidOut {
		m.rendered = append(
			[]string{m.s.renderLine(notice, m.renderedWidth)},
			m.rendered[over:]...,
		)
	} else {
		m.rendered = nil
	}
}

// clearTranscript empties the chat transcript.
func (m *model) clearTranscript() {
	m.messages = nil
	m.rendered = nil
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

// mkVerifier returns the verifier for the connection attempt att. It shows
// one prompt at a time and rejects a peer that arrives while a prompt is
// open. It waits for the user's answer for at most the prompt timeout, and
// no longer than att lasts, so a peer whose prompt is never answered
// cannot hold its handshake open.
func (m *model) mkVerifier(att *attempt) kamune.RemoteVerifier {
	send := m.send
	timeout := m.promptTimeout
	if timeout <= 0 {
		timeout = verifyPromptTimeout
	}
	var prompting atomic.Bool
	return func(store *storage.Storage, peer *storage.Peer) error {
		if !prompting.CompareAndSwap(false, true) {
			return errPromptOpen
		}
		defer prompting.Store(false)

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
		send(verifyRequest{
			att:            att,
			peer:           peer,
			isNew:          isNew,
			knownName:      knownName,
			numericFP:      fingerprint.Numeric(key),
			localNumericFP: localFP,
			emojiFP:        strings.Join(fingerprint.Emoji(key), " • "),
			hexFP:          fingerprint.Hex(key),
			responseCh:     respCh,
		})

		timer := time.NewTimer(timeout)
		defer timer.Stop()
		var err error
		select {
		case err = <-respCh:
		case <-timer.C:
			err = errPromptTimeout
			send(verifyEndedMsg{responseCh: respCh, err: err})
		case <-att.ctx.Done():
			err = errAttemptCancelled
		}
		if err == nil && isNew {
			peer.FirstSeen = time.Now()
			if serr := store.StorePeer(peer); serr != nil {
				slog.Error("failed to store peer", "error", serr)
			}
		}
		return err
	}
}

// answer gives the verifier waiting on ch the answer err, unless it has
// one already.
func answer(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func (m *model) startConnect() tea.Cmd {
	att := newAttempt()
	m.att = att
	vfn := m.mkVerifier(att)
	send := m.send
	store := m.store
	addr := m.inputs[0].Value()
	// deliver hands a session of the attempt's server to Update.
	deliver := func(t *kamune.Transport, release chan struct{}) {
		send(connectedMsg{att: att, transport: t, release: release})
	}

	switch m.mode {
	case modeDirectDial:
		go func() {
			t, err := dial(att.ctx, addr, store, vfn)
			if err != nil {
				send(connectFailedMsg{att, err})
				return
			}
			send(connectedMsg{att: att, transport: t})
		}()

	case modeDirectServe:
		srv, err := serve(addr, store, vfn, deliver)
		if err != nil {
			return func() tea.Msg { return connectFailedMsg{att, err} }
		}
		m.srv = srv

	case modeRelayDial:
		token := m.inputs[1].Value()
		go func() {
			t, sessionTTL, err := relayDial(
				att.ctx, addr, token, "", store, vfn,
			)
			if err != nil {
				send(connectFailedMsg{att, err})
				return
			}
			send(connectedMsg{
				att: att, transport: t, sessionTTL: sessionTTL,
			})
		}()

	case modeRelayServe:
		go func() {
			srv, token, sessionTTL, err := relayServe(
				att.ctx, addr, "", store, vfn, deliver,
			)
			if err != nil {
				send(connectFailedMsg{att, err})
				return
			}
			send(relayReadyMsg{
				att: att, srv: srv, token: token, sessionTTL: sessionTTL,
			})
		}()
	}
	return nil
}

func tickCountdown() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *model) enterChat(msg connectedMsg) (tea.Model, tea.Cmd) {
	t := msg.transport
	m.state = stateChat
	m.sess = newChatSession(t, msg.release)
	if m.mode == modeDirectServe && m.srv != nil {
		// The TUI shows one chat at a time, so stop taking peers: a
		// handshake that reached the server now would wait for a prompt
		// that cannot be shown. Close leaves the session handed to the
		// handler running. A relay listener takes a single peer, and
		// closing it would end this session too, so it stays open.
		_ = m.srv.Close()
		m.srv = nil
	}
	// The attempt is over; this stops the verifier of any other peer.
	m.att.cancel()
	m.att = nil
	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	if peer := t.RemotePeer(); peer != nil {
		err := m.store.CreateSession(t.SessionID(), peer.PublicKey)
		if err != nil {
			slog.Warn("failed to create session record",
				slog.String("session_id", t.SessionID()),
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

	m.clearTranscript()
	if peer := t.RemotePeer(); peer != nil {
		warn, _ := checkMinorMismatch(kamune.AppVersion, peer.AppVersion)
		if warn != "" {
			m.messages = []chatLine{noticeLine(m.s.highlight, "⚠ "+warn)}
		}
	}
	m.vp = vp
	m.vp.SetContent("Session ID is " + t.SessionID() + ". Loading history…")

	send := m.sess.sender(m.send)
	recv := saving(m.store, t.SessionID(), send)
	go receiveLoop(m.sess.t, m.sess.pongCh, recv)
	go keepAliveLoop(m.sess, send)
	go writeLoop(m.sess, m.store, send)
	sess := m.sess
	history := loadChatHistory(m.store, t.SessionID(), m.s)
	load := func() tea.Msg { return sessionMsg{sess: sess, msg: history()} }
	if !m.sessionExpiry.IsZero() {
		return m, tea.Batch(load, tickCountdown())
	}
	return m, load
}

// loadChatHistory returns a command that reads the history of the session
// sid. It runs on a goroutine of its own, so it gets what it needs as
// arguments rather than reading the model.
func loadChatHistory(
	store *storage.Storage, sid string, s styles,
) tea.Cmd {
	return func() tea.Msg {
		entries, err := store.GetChatHistory(sid)
		if err != nil {
			slog.Warn("failed to load chat history",
				slog.String("session_id", sid),
				slog.Any("error", err),
			)
			return historyLoadedMsg{messages: []chatLine{noticeLine(
				s.err, "Could not load chat history: "+err.Error(),
			)}}
		}
		header := "Session ID is " + sid + ". Happy Chatting!"
		if len(entries) > 0 {
			header = fmt.Sprintf("Session ID is %s. Restored %d message(s). Happy Chatting!",
				sid, len(entries))
		}
		msgs := []chatLine{noticeLine(s.muted, header)}
		for _, ent := range entries {
			msgs = append(msgs,
				messageLine(ent.Sender, ent.Timestamp, string(ent.Data)),
			)
		}
		return historyLoadedMsg{messages: msgs}
	}
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

// keepAliveLoop sends periodic pings to detect dead connections until
// the session stops. After 3 consecutive failures, the peer is considered
// unresponsive.
func keepAliveLoop(sess *chatSession, send func(tea.Msg)) {
	const pingTimeout = 10 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var failures int
	for {
		select {
		case <-sess.stop:
			return
		case <-ticker.C:
			err := tuiSendPing(sess.t, sess.pongCh, pingTimeout)
			if err == nil {
				failures = 0
				continue
			}
			failures++
			if failures >= 3 {
				send(peerDisconnectedMsg{})
				return
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

// handleChatMessage shows a message from the peer, which the receive
// goroutine has added to the history.
func (m *model) handleChatMessage(msg chatMessageMsg) {
	lines := []chatLine{messageLine(storage.SenderPeer, msg.time, msg.text)}
	if msg.saveErr != nil {
		lines = append(lines, notSavedLine(m.s, msg.saveErr))
	}
	m.addLines(lines...)
}

func (m *model) cancelConnect() {
	if m.att != nil {
		m.att.cancel()
		m.att = nil
	}
	if srv := m.srv; srv != nil {
		// Closing a relay server may wait for the relay to answer.
		m.closing.Go(func() { _ = srv.Close() })
		m.srv = nil
	}
	m.relayToken = nil
	m.relaySessionTTL = 0
	m.sessionExpiry = time.Time{}
}

func (m *model) cleanup() {
	if m.att != nil {
		m.att.cancel()
		m.att = nil
	}
	// A relay listener outlives its attempt, since closing it ends the
	// session it took, so it is closed after the session.
	srv := m.srv
	m.srv = nil
	switch {
	case m.sess != nil:
		m.sess.end(&m.closing, srv)
		m.sess = nil
	case srv != nil:
		m.closing.Go(func() { _ = srv.Close() })
	}
	m.relayToken = nil
	m.relaySessionTTL = 0
	m.sessionExpiry = time.Time{}
}

// shutdown ends what the UI left open, as when a signal rather than a key
// stopped it, and waits up to limit for the sessions and servers to
// close. It reports whether they did. Call it only once the program has
// stopped.
func (m *model) shutdown(limit time.Duration) bool {
	m.cleanup()
	done := make(chan struct{})
	go func() {
		m.closing.Wait()
		close(done)
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
