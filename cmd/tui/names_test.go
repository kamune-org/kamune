package main

import (
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestNameKey(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		same bool
	}{
		{"equal", "Bob", "Bob", true},
		{"case", "Bob", "bOB", true},
		{"surrounding space", "Bob", "  Bob\t", true},
		{"inner space runs", "Bob Lee", "Bob \u00A0 Lee", true},
		{"zero-width joiner", "Bob", "Bob\u200D", true},
		{"zero-width non-joiner", "Bob", "B\u200Cob", true},
		{"hangul filler", "Bob", "Bob\u3164", true},
		{"halfwidth hangul filler", "Bob", "Bo\uFFA0b", true},
		{"combining grapheme joiner", "Bob", "B\u034Fob", true},
		{"variation selector", "Bob", "Bob\uFE0F", true},
		{"braille blank", "Bob", "\u2800Bob", true},
		{"fullwidth", "Bob", "\uFF22\uFF4F\uFF42", true},
		{"sharp s", "Strauß", "STRAUSS", true},
		{"other name", "Bob", "Rob", false},
		{"inner space", "Bob Lee", "BobLee", false},
		{"cyrillic o", "Bob", "B\u043Eb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.same, nameKey(tt.x) == nameKey(tt.y),
				"%q and %q", nameKey(tt.x), nameKey(tt.y))
		})
	}
	a := require.New(t)
	a.Empty(nameKey("\u200D\u3164 \u2800\uFE0F"))
}

// storedNames returns the names of the peers in store.
func storedNames(t *testing.T, store *storage.Storage) []string {
	t.Helper()
	peers, err := store.ListPeers()
	require.New(t).NoError(err)
	var names []string
	for _, p := range peers {
		names = append(names, p.Name)
	}
	return names
}

func TestRememberPeer_TakenNameIsNotStored(t *testing.T) {
	tests := []struct {
		name    string
		claimed string
		// pseudonym is whether the peer is stored under the pseudonym of
		// its key rather than under the name it claimed.
		pseudonym bool
	}{
		{"free name", "Carol", false},
		{"taken name", "Bob", true},
		{"taken name, other case", "BOB", true},
		{"taken name with a joiner", "Bob\u200D", true},
		{"no name", "", true},
		{"name that shows as nothing", "\u3164", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			store := openTestStore(t)
			bobKey, err := openTestStore(t).PublicKey()
			a.NoError(err)
			a.NoError(store.StorePeer(&storage.Peer{
				Name: "Bob", PublicKey: bobKey,
			}))
			key, err := openTestStore(t).PublicKey()
			a.NoError(err)

			rememberPeer(store, &storage.Peer{
				Name: tt.claimed, PublicKey: key,
			})
			stored, err := store.FindPeer(key)
			a.NoError(err)
			want := tt.claimed
			if tt.pseudonym {
				want = fingerprint.Pseudonym(key)
			}
			a.Equal(want, stored.Name)

			// A peer that is stored keeps its name, though its own name
			// is now among the stored ones.
			rememberPeer(store, &storage.Peer{Name: "Dave", PublicKey: key})
			stored, err = store.FindPeer(key)
			a.NoError(err)
			a.Equal(want, stored.Name)
		})
	}
}

// TestVerify_NewKeyClaimingAContactsName runs a TUI direct server, twice,
// for a dialer whose key is not stored and that introduces itself with
// the name of a stored peer written in fullwidth letters, which the core
// accepts and nameKey folds to the stored name. The prompt warns of the
// name, the peer is stored under its pseudonym, and the next prompt and
// the chat name it by that pseudonym.
func TestVerify_NewKeyClaimingAContactsName(t *testing.T) {
	a := require.New(t)
	const claimed = "\uFF22\uFF4F\uFF42"
	store, dialerStore := openTestStore(t), openTestStore(t)
	bobKey, err := openTestStore(t).PublicKey()
	a.NoError(err)
	a.NoError(store.StorePeer(&storage.Peer{Name: "Bob", PublicKey: bobKey}))
	key, err := dialerStore.PublicKey()
	a.NoError(err)
	pseudonym := fingerprint.Pseudonym(key)

	// round accepts the dialer at the prompt and returns the prompt and
	// the model, which is in the chat then.
	round := func() (string, *model) {
		m := newTestModel()
		m.store = store
		m.mode = modeDirectServe
		m.state = stateConnecting
		m.att = newAttempt()
		msgs := make(chan tea.Msg, 8)
		m.send = func(msg tea.Msg) { msgs <- msg }
		t.Cleanup(func() { m.shutdown(time.Minute) })
		l := &pipeListener{
			conns:  make(chan kamune.Conn, 1),
			closed: make(chan struct{}),
		}
		att := m.att
		srv, err := serve("", store, m.mkVerifier(att),
			func(tr *kamune.Transport, release chan struct{}) {
				m.send(connectedMsg{
					att: att, transport: tr, release: release,
				})
			},
			func(error) {}, kamune.ServeWithListener(l),
		)
		a.NoError(err)
		m.srv = srv

		clientNet, serverNet := net.Pipe()
		l.conns <- kamune.NewConn(serverNet)
		d, err := kamune.NewDialer("", dialerStore,
			func(*storage.Storage, *storage.Peer) error { return nil },
			kamune.DialWithClientName(claimed),
			kamune.DialWithFunc(func(string) (kamune.Conn, error) {
				return kamune.NewConn(clientNet), nil
			}),
		)
		a.NoError(err)
		dialed := make(chan *kamune.Transport, 1)
		go func() {
			tr, err := d.Dial()
			if err != nil {
				tr = nil
			}
			dialed <- tr
		}()
		t.Cleanup(func() {
			if tr := <-dialed; tr != nil {
				_ = tr.CloseAbort()
			}
		})

		m.Update(waitFor(t, (<-chan tea.Msg)(msgs)))
		a.Equal(stateVerify, m.state)
		view := m.viewVerify()
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		m.Update(waitFor(t, (<-chan tea.Msg)(msgs)))
		a.Equal(stateChat, m.state)
		return view, m
	}
	lineWith := func(view, s string) string {
		for _, ln := range strings.Split(view, "\n") {
			if strings.Contains(ln, s) {
				return ln
			}
		}
		return ""
	}

	view, m := round()
	a.Contains(view, "not known")
	a.Contains(lineWith(view, "Claimed name"), claimed)
	a.Contains(view, nameTakenWarning)
	a.Contains(view, "If you accept, it is stored as "+pseudonym+".")
	a.ElementsMatch([]string{"Bob", pseudonym}, storedNames(t, store))
	notices := peerNotices(m, fingerprint.Numeric(key))
	a.Len(notices, 1)
	a.Contains(notices[0], "Chatting with "+pseudonym+" ")

	view, m = round()
	a.Contains(view, "connected before")
	a.Equal(pseudonym, strings.TrimSpace(strings.TrimPrefix(
		strings.TrimSpace(lineWith(view, "Stored name:")), "Stored name:",
	)))
	a.Equal(1, strings.Count(view, nameTakenWarning))
	a.NotContains(view, "If you accept")
	a.ElementsMatch([]string{"Bob", pseudonym}, storedNames(t, store))
	notices = peerNotices(m, fingerprint.Numeric(key))
	a.Len(notices, 1)
	a.Contains(notices[0], "Chatting with "+pseudonym+" ")
}

func TestViewVerify_StoredNameTaken(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateVerify
	m.verifyReq = &verifyRequest{
		peer:           &storage.Peer{Name: "Bob"},
		knownName:      "Bob",
		knownNameTaken: true,
	}

	view := m.viewVerify()
	a.Contains(view, "connected before")
	a.Equal(1, strings.Count(view, nameTakenWarning))
	a.Less(strings.Index(view, "Stored name: Bob"),
		strings.Index(view, nameTakenWarning))
	a.Less(strings.Index(view, nameTakenWarning),
		strings.Index(view, "Claimed name"))
}

// TestVerifier_SaysWhatANewPeerIsStoredAs checks that the prompt gives
// the pseudonym that a new peer is stored under, and only for a peer that
// is not stored under the name it claims.
func TestVerifier_SaysWhatANewPeerIsStoredAs(t *testing.T) {
	tests := []struct {
		name    string
		claimed string
		stored  bool
		// pseudonym is whether the prompt says that the peer is stored
		// under its pseudonym.
		pseudonym bool
	}{
		{"free name", "Carol", false, false},
		{"taken name", "bob", false, true},
		{"no name", "", false, true},
		{"name that shows as nothing", "ㅤ", false, true},
		{"stored peer without a name", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m, msgs, peer := promptModel(t)
			m.state = stateConnecting
			bobKey, err := openTestStore(t).PublicKey()
			a.NoError(err)
			a.NoError(m.store.StorePeer(&storage.Peer{
				Name: "Bob", PublicKey: bobKey,
			}))
			peer.Name = tt.claimed
			if tt.stored {
				a.NoError(m.store.StorePeer(&storage.Peer{
					Name: "Dave", PublicKey: peer.PublicKey,
				}))
			}
			done := runVerifier(m.mkVerifier(m.att), m.store, peer)

			m.Update(waitFor(t, msgs))
			a.Equal(stateVerify, m.state)
			view := m.viewVerify()
			line := "If you accept, it is stored as " +
				fingerprint.Pseudonym(peer.PublicKey) + "."
			if tt.pseudonym {
				a.Contains(view, line)
			} else {
				a.NotContains(view, "If you accept")
			}
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
			a.Error(waitFor(t, done))
		})
	}
}
