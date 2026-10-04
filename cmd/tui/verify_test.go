package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"valid", "alice", "alice"},
		{"empty", "", "(unnamed)"},
		{"persian with zwnj", "ع\u200Cر", "ع\u200Cر"},
		{"line breaks", "bob\nalice", "bob alice"},
		{"escape sequence", "bob\x1b]0;pwned\x07", "bob"},
		{"zero-width space", "bo\u200Bb", "bob"},
		{"bidi override", "\u202Ebob", "bob"},
		{"only controls", "\x1b\x07", "(unnamed)"},
		{
			"too long",
			strings.Repeat("a", kamune.MaxPeerNameLength+10),
			strings.Repeat("a", kamune.MaxPeerNameLength),
		},
		{
			"too long, multi-byte",
			"\n" + strings.Repeat("é", kamune.MaxPeerNameLength),
			" " + strings.Repeat("é", kamune.MaxPeerNameLength/2-1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := displayName(tt.input)
			a.Equal(tt.want, got)
			if got != "(unnamed)" {
				a.NoError(kamune.ValidatePeerName(got))
			}
		})
	}
}

func TestViewVerify_PeerClaimsComeAfterFingerprints(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateVerify
	m.verifyReq = &verifyRequest{
		peer: &storage.Peer{
			Name: "Alice\x1b]0;x\x07\n\nHex fingerprint:\n  FAKE\n\n" +
				"✓ This peer has connected before.",
			AppVersion: "0.7.0\x1b]52;c;aGk=\x07\n" +
				strings.Repeat("9", 100),
		},
		numericFP:      "11111 22222",
		localNumericFP: "33333 44444",
		emojiFP:        "E1 E2",
		hexFP:          "AA:BB",
		isNew:          true,
	}

	view := m.viewVerify()
	requireNoTerminalControls(a, view)
	var headings int
	for _, ln := range strings.Split(view, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "Hex fingerprint:") {
			headings++
		}
	}
	a.Equal(1, headings)
	numericAt := strings.Index(view, "11111 22222")
	hexAt := strings.Index(view, "AA:BB")
	claimAt := strings.Index(view, "Claimed name (unverified): Alice")
	a.Positive(numericAt)
	a.Less(numericAt, strings.Index(view, "33333 44444"))
	a.Less(numericAt, strings.Index(view, "E1 E2"))
	a.Greater(hexAt, numericAt)
	a.Greater(claimAt, hexAt)
	a.Less(strings.Index(view, "not known"), claimAt)
	for _, ln := range strings.Split(view, "\n") {
		if strings.Contains(ln, "FAKE") {
			a.Contains(ln, "Claimed name (unverified):")
		}
	}
	nines := maxVersionLength - len("0.7.0 ")
	a.Contains(view, "App version: 0.7.0 "+strings.Repeat("9", nines)+"…")
	a.NotContains(view, strings.Repeat("9", nines+1))
	a.NotContains(view, "Stored name")
}

func TestViewVerify_KnownPeerShowsStoredName(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateVerify
	m.verifyReq = &verifyRequest{
		peer:      &storage.Peer{Name: "Mallory"},
		knownName: "Alice",
		emojiFP:   "E1 E2",
		hexFP:     "AA:BB",
	}

	view := m.viewVerify()
	a.Contains(view, "If its app shows no numeric fingerprint, compare")
	a.Contains(view, "the hex fingerprint instead.")
	for _, ln := range strings.Split(view, "\n") {
		ln = strings.TrimRight(ln, " ")
		a.LessOrEqual(lipgloss.Width(ln), 80, "line %q", ln)
	}
	a.Contains(view, "connected before")
	a.Contains(view, "Stored name: Alice")
	a.Contains(view, "Claimed name (unverified): Mallory")
}

func TestUpdateVerify_Keys(t *testing.T) {
	runes := func(s string) tea.KeyMsg {
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
	tests := []struct {
		name      string
		key       tea.KeyMsg
		answered  bool
		accepted  bool
		wantState appState
	}{
		{"enter is ignored", tea.KeyMsg{Type: tea.KeyEnter}, false, false,
			stateVerify},
		{"space is ignored", tea.KeyMsg{Type: tea.KeySpace}, false, false,
			stateVerify},
		{"other rune is ignored", runes("x"), false, false, stateVerify},
		{"pasted y is ignored",
			tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y"), Paste: true},
			false, false, stateVerify},
		{"y accepts", runes("y"), true, true, stateConnecting},
		{"Y accepts", runes("Y"), true, true, stateConnecting},
		{"n rejects", runes("n"), true, false, stateWelcome},
		{"N rejects", runes("N"), true, false, stateWelcome},
		{"esc rejects", tea.KeyMsg{Type: tea.KeyEsc}, true, false,
			stateWelcome},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m := newTestModel()
			m.state = stateVerify
			respCh := make(chan error, 1)
			m.verifyReq = &verifyRequest{
				peer:       &storage.Peer{Name: "alice"},
				responseCh: respCh,
			}

			m.Update(tt.key)
			a.Equal(tt.wantState, m.state)
			if !tt.answered {
				a.Empty(respCh)
				a.NotNil(m.verifyReq)
				return
			}
			a.Len(respCh, 1)
			err := <-respCh
			if tt.accepted {
				a.NoError(err)
				return
			}
			a.Error(err)
			a.Equal(err, m.connectErr)
		})
	}
}

// promptModel returns a model whose messages from goroutines go to the
// returned channel, and a peer for its verifier to ask about.
func promptModel(t *testing.T) (*model, chan tea.Msg, *storage.Peer) {
	t.Helper()
	a := require.New(t)
	m := newTestModel()
	m.store = openTestStore(t)
	msgs := make(chan tea.Msg, 8)
	m.send = func(msg tea.Msg) { msgs <- msg }
	key, err := openTestStore(t).PublicKey()
	a.NoError(err)
	return m, msgs, &storage.Peer{Name: "alice", PublicKey: key}
}

// runVerifier runs vfn for peer in a goroutine and returns its result.
func runVerifier(
	vfn kamune.RemoteVerifier, store *storage.Storage, peer *storage.Peer,
) <-chan error {
	done := make(chan error, 1)
	go func() { done <- vfn(store, peer) }()
	return done
}

// waitFor returns the next value of ch, failing the test if none comes
// within a generous limit.
func waitFor[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		require.New(t).FailNow("timed out")
		panic("unreachable")
	}
}

func TestVerifier_AnsweredWhenPromptCannotShow(t *testing.T) {
	for _, state := range []appState{stateWelcome, stateChat, stateVerify} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			a := require.New(t)
			m, msgs, peer := promptModel(t)
			m.state = state
			done := runVerifier(
				m.mkVerifier(context.Background()), m.store, peer,
			)

			m.Update(waitFor(t, msgs))
			err := waitFor(t, done)
			a.ErrorIs(err, errPromptNotShown)
			a.ErrorIs(err, kamune.ErrVerificationFailed)
			a.Equal(state, m.state)
		})
	}
}

func TestVerifier_PromptTimesOut(t *testing.T) {
	a := require.New(t)
	m, msgs, peer := promptModel(t)
	m.state = stateConnecting
	m.mode = modeDirectServe
	m.inputs = []textinput.Model{mkInput("addr", ":9000")}
	m.promptTimeout = time.Millisecond
	done := runVerifier(m.mkVerifier(context.Background()), m.store, peer)

	m.Update(waitFor(t, msgs))
	a.ErrorIs(waitFor(t, done), errPromptTimeout)
	ended := waitFor(t, msgs)
	a.IsType(verifyEndedMsg{}, ended)
	m.Update(ended)
	a.Equal(stateConnecting, m.state)
	a.Nil(m.verifyReq)
	a.Contains(m.viewConnecting(), "no answer in time")

	// A late answer does nothing.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	a.Equal(stateConnecting, m.state)
}

func TestVerifier_StopsWhenAttemptIsCancelled(t *testing.T) {
	a := require.New(t)
	m, msgs, peer := promptModel(t)
	m.state = stateConnecting
	ctx, cancel := context.WithCancel(context.Background())
	done := runVerifier(m.mkVerifier(ctx), m.store, peer)

	m.Update(waitFor(t, msgs))
	a.Equal(stateVerify, m.state)
	cancel()
	a.ErrorIs(waitFor(t, done), errAttemptCancelled)
}

func TestVerifier_OnePromptAtATime(t *testing.T) {
	a := require.New(t)
	m, msgs, peer := promptModel(t)
	m.state = stateConnecting
	m.mode = modeDirectServe
	vfn := m.mkVerifier(context.Background())
	first := runVerifier(vfn, m.store, peer)
	m.Update(waitFor(t, msgs))
	a.Equal(stateVerify, m.state)

	a.ErrorIs(waitFor(t, runVerifier(vfn, m.store, peer)), errPromptOpen)
	a.Equal(stateVerify, m.state)

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	a.NoError(waitFor(t, first))
	// The prompt is free again for the next peer.
	next := runVerifier(vfn, m.store, peer)
	m.Update(waitFor(t, msgs))
	a.Equal(stateVerify, m.state)
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	a.Error(waitFor(t, next))
}

func TestEnterChat_StopsDirectServer(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.store = openTestStore(t)
	m.state = stateConnecting
	m.mode = modeDirectServe
	l := &pipeListener{
		conns:  make(chan kamune.Conn),
		closed: make(chan struct{}),
	}
	srv, err := kamune.NewServer(
		"", func(*kamune.Transport) error { return nil }, m.store,
		m.mkVerifier(context.Background()), kamune.ServeWithListener(l),
	)
	a.NoError(err)
	m.srv = srv

	tr := dialPipe(t, func(t *kamune.Transport) error {
		_, _, err := t.ReceivePayload()
		return err
	})
	m.Update(connectedMsg{transport: tr, isServer: true})
	a.Equal(stateChat, m.state)
	select {
	case <-l.closed:
	default:
		a.Fail("the server still takes peers during the chat")
	}
}
