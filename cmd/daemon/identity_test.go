package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestIdentifyPeer(t *testing.T) {
	tests := []struct {
		name         string
		claimed      string
		stored       string
		other        string
		wantLabel    string
		wantKnown    bool
		wantMismatch bool
		wantConflict bool
	}{
		{
			name: "known peer under its own name", claimed: "Bob",
			stored: "Bob", wantLabel: "Bob", wantKnown: true,
		},
		{
			name: "known peer claiming another peer's name", claimed: "Bob",
			stored: "Mallory", other: "Bob", wantLabel: "Mallory",
			wantKnown: true, wantMismatch: true, wantConflict: true,
		},
		{
			name: "known peer under a local nickname", claimed: "Robert",
			stored: "Bob from work", wantLabel: "Bob from work",
			wantKnown: true, wantMismatch: true,
		},
		{
			name: "unknown peer is not named by its claim", claimed: "Bob",
			wantLabel: "<unknown>",
		},
		{
			name: "unknown peer claiming a stored name", claimed: "bob",
			other: "Bob", wantLabel: "<unknown>", wantConflict: true,
		},
		{
			name:    "unknown peer claiming a stored name with a joiner",
			claimed: "Bob\u200d", other: "Bob", wantLabel: "<unknown>",
			wantConflict: true,
		},
		{
			name:    "unknown peer claiming a stored name with a filler",
			claimed: "Bob\u3164", other: "Bob", wantLabel: "<unknown>",
			wantConflict: true,
		},
		{
			name:    "unknown peer claiming a stored name with spaces",
			claimed: " Bob  Smith ", other: "Bob Smith",
			wantLabel: "<unknown>", wantConflict: true,
		},
		{
			name: "known peer stored under a legacy name", claimed: "Eve",
			stored: "Eve\u202egnp.exe", wantLabel: "Eve\ufffdgnp.exe",
			wantKnown: true, wantMismatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, _ := newTestDaemon(t, VerificationModeQuick, false)
			store := d.store()
			peer := &storage.Peer{
				Name: tt.claimed, PublicKey: newTestPeerKey(t),
			}
			if tt.stored != "" {
				a.NoError(store.StorePeer(&storage.Peer{
					Name: tt.stored, PublicKey: peer.PublicKey,
				}))
			}
			if tt.other != "" {
				a.NoError(store.StorePeer(&storage.Peer{
					Name: tt.other, PublicKey: newTestPeerKey(t),
				}))
			}

			id := identifyPeer(store, peer)

			want := tt.wantLabel
			if want == "<unknown>" {
				want = unknownPeerLabel(peer.PublicKey)
				a.NotContains(want, tt.claimed)
			}
			a.Equal(want, id.Label)
			// The handshake rejects such claims now; a stored name may
			// still hold them, and it is shown sanitized.
			a.Equal(kamune.SanitizePeerName(tt.claimed), id.ClaimedName)
			a.NoError(kamune.ValidatePeerName(id.ClaimedName))
			a.Equal(tt.wantKnown, id.Known)
			a.Equal(tt.wantMismatch, id.NameMismatch)
			a.Equal(tt.wantConflict, id.NameConflict)
			a.Equal(fingerprint.Base64(peer.PublicKey), id.KeyB64)
			a.Equal(fingerprint.Numeric(peer.PublicKey), id.Numeric)
			a.NoError(kamune.ValidatePeerName(id.Label))
		})
	}
}

func TestUnknownPeerLabel(t *testing.T) {
	a := require.New(t)
	key := newTestPeerKey(t)
	label := unknownPeerLabel(key)
	a.Regexp(`^Unknown peer \d{5} \d{5}$`, label)
	a.Equal(label, unknownPeerLabel(key))
	a.NotEqual(label, unknownPeerLabel(newTestPeerKey(t)))
}

func TestSanitizeName(t *testing.T) {
	long := strings.Repeat("é", kamune.MaxPeerNameLength)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "clean", in: "Bob", want: "Bob"},
		{name: "joiner between latin letters", in: "a\u200db", want: "a\ufffdb"},
		{
			name: "joiner after a virama kept",
			in:   "\u0915\u094d\u200d\u0937",
			want: "\u0915\u094d\u200d\u0937",
		},
		{name: "bidi override", in: "Bob\u202egnp", want: "Bob\ufffdgnp"},
		{name: "line break", in: "a\nb", want: "a\ufffdb"},
		{name: "invalid utf-8", in: "a\xffb", want: "a\ufffdb"},
		{
			name: "too long", in: long,
			want: strings.Repeat("é", (kamune.MaxPeerNameLength-3)/2) +
				"…",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := sanitizeName(tt.in)
			a.Equal(tt.want, got)
			a.NoError(kamune.ValidatePeerName(got))
		})
	}
}

// An unknown peer that the user accepts is stored under the name it
// claimed only when no other stored peer reads as that name; otherwise,
// or when it claimed none, under the pseudonym of its key.
func TestRememberPeerKeepsOtherPeersNames(t *testing.T) {
	tests := []struct {
		claimed   string
		wantClaim bool
	}{
		{claimed: "Carol", wantClaim: true},
		{claimed: "Bob"},
		{claimed: "BOB"},
		{claimed: "Bob\u200d"},
		{claimed: "\u3164Bob"},
		{claimed: ""},
		{claimed: "\u200d"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.claimed), func(t *testing.T) {
			a := require.New(t)
			d, _ := newTestDaemon(t, VerificationModeQuick, false)
			store := d.store()
			a.NoError(store.StorePeer(&storage.Peer{
				Name: "Bob", PublicKey: newTestPeerKey(t),
			}))
			peer := &storage.Peer{
				Name: tt.claimed, PublicKey: newTestPeerKey(t),
			}

			d.noteAdmitted(peer.PublicKey)
			d.rememberPeer(store, peer, false)

			stored, err := store.FindPeer(peer.PublicKey)
			a.NoError(err)
			want := fingerprint.Pseudonym(peer.PublicKey)
			if tt.wantClaim {
				want = tt.claimed
			}
			a.Equal(want, stored.Name)
		})
	}
}

// startNamedServer starts a TCP server on d that introduces itself as
// name, and returns its address once it accepts connections.
func startNamedServer(
	t *testing.T, d *Daemon, rec *eventRecorder, name string,
) string {
	a := require.New(t)
	addr := fmt.Sprintf("127.0.0.1:%d", findFreePort(t))
	d.handleStartServer(Command{
		ID:     "start",
		Params: mustJSON(StartServerParams{Addr: addr, Name: name}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "start"
	})
	a.Equal(EvtServerStarted, evt.Evt, "start failed: %v", evt.Data)
	deadline := time.Now().Add(testEventTimeout)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			a.NoError(conn.Close())
			return addr
		}
		a.True(time.Now().Before(deadline), "server never listened")
		time.Sleep(10 * time.Millisecond)
	}
}

// storeAs stores peer's identity in d under name, and returns its key.
func storeAs(t *testing.T, d, peer *Daemon, name string) []byte {
	a := require.New(t)
	pub, err := peer.store().PublicKey()
	a.NoError(err)
	a.NoError(d.store().StorePeer(&storage.Peer{
		Name: name, PublicKey: pub, FirstSeen: time.Now(),
	}))
	return pub
}

// The BUS-01 scenario without a pin: Mallory is a stored peer whose
// server introduces itself as Bob, the name of another stored peer.
// Quick mode admits her stored key, but the session is named by her
// stored name, with her claim and the clash flagged.
func TestQuickSessionIsNamedByStoredName(t *testing.T) {
	a := require.New(t)
	mallory, malloryRec := newTestDaemon(
		t, VerificationModeAutoAccept, false,
	)
	alice, aliceRec := newTestDaemon(t, VerificationModeQuick, false)
	malloryKey := storeAs(t, alice, mallory, "Mallory")
	a.NoError(alice.store().StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: newTestPeerKey(t),
	}))

	addr := startNamedServer(t, mallory, malloryRec, "Bob")
	alice.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt := aliceRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
	a.Equal("Mallory", evt.Data["peer_name"])
	a.Equal("Bob", evt.Data["claimed_name"])
	a.Equal(fingerprint.Base64(malloryKey), evt.Data["peer_key"])
	a.Equal(fingerprint.Numeric(malloryKey), evt.Data["peer_fingerprint"])
	a.Equal(true, evt.Data["known_peer"])
	a.Equal(true, evt.Data["name_mismatch"])
	a.Equal(true, evt.Data["name_conflict"])
}

// In Strict mode the prompt for a stored peer that claims another
// peer's name shows its stored name, and its claim apart.
func TestStrictPromptShowsStoredName(t *testing.T) {
	a := require.New(t)
	mallory, malloryRec := newTestDaemon(
		t, VerificationModeAutoAccept, false,
	)
	alice, aliceRec := newTestDaemon(t, VerificationModeStrict, false)
	malloryKey := storeAs(t, alice, mallory, "Mallory")
	a.NoError(alice.store().StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: newTestPeerKey(t),
	}))

	addr := startNamedServer(t, mallory, malloryRec, "Bob")
	alice.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt := aliceRec.waitFor(t, isEvent(EvtVerifyPeer))
	a.Equal("Mallory", evt.Data["peer_name"])
	a.Equal("Bob", evt.Data["claimed_name"])
	a.Equal(fingerprint.Base64(malloryKey), evt.Data["peer_key"])
	a.Equal(true, evt.Data["known"])
	a.Equal(true, evt.Data["name_mismatch"])
	a.Equal(true, evt.Data["name_conflict"])
	id, ok := evt.Data["request_id"].(float64)
	a.True(ok)
	alice.handleVerifyResponse(Command{
		Params: mustJSON(VerifyResponseParams{RequestID: int64(id)}),
	})
	evt = aliceRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtError, evt.Evt)
}

// An unknown peer that claims a stored peer's name is asked about under
// a label made from its key, with the clash flagged, and once accepted
// is stored and named under its key's pseudonym, not the clashing name.
func TestUnknownPeerClaimingStoredName(t *testing.T) {
	a := require.New(t)
	mallory, malloryRec := newTestDaemon(
		t, VerificationModeAutoAccept, false,
	)
	alice, aliceRec := newTestDaemon(t, VerificationModeQuick, false)
	a.NoError(alice.store().StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: newTestPeerKey(t),
	}))
	malloryKey, err := mallory.store().PublicKey()
	a.NoError(err)

	addr := startNamedServer(t, mallory, malloryRec, "Bob")
	alice.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt := aliceRec.waitFor(t, isEvent(EvtVerifyPeer))
	a.Equal(unknownPeerLabel(malloryKey), evt.Data["peer_name"])
	a.Equal("Bob", evt.Data["claimed_name"])
	a.Equal(false, evt.Data["known"])
	a.Equal(false, evt.Data["name_mismatch"])
	a.Equal(true, evt.Data["name_conflict"])
	id, ok := evt.Data["request_id"].(float64)
	a.True(ok)
	alice.handleVerifyResponse(Command{
		Params: mustJSON(VerifyResponseParams{
			RequestID: int64(id), Accepted: true,
		}),
	})
	evt = aliceRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
	pseudonym := fingerprint.Pseudonym(malloryKey)
	a.Equal(pseudonym, evt.Data["peer_name"])
	a.Equal("Bob", evt.Data["claimed_name"])
	a.Equal(true, evt.Data["known_peer"])
	stored, err := alice.store().FindPeer(malloryKey)
	a.NoError(err)
	a.Equal(pseudonym, stored.Name)
}

func TestPinPeer(t *testing.T) {
	tests := []struct {
		name    string
		pinned  bool
		match   bool
		wantErr error
		wantRun bool
	}{
		{name: "no pin", wantRun: true},
		{name: "matching key", pinned: true, match: true, wantRun: true},
		{name: "other key", pinned: true, wantErr: errPeerKeyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, _ := newTestDaemon(t, VerificationModeQuick, false)
			peer := &storage.Peer{Name: "Bob", PublicKey: newTestPeerKey(t)}
			var want []byte
			if tt.pinned {
				want = newTestPeerKey(t)
				if tt.match {
					want = peer.PublicKey
				}
			}
			ran := false
			rv := d.pinPeer(want, func(*storage.Storage, *storage.Peer) error {
				ran = true
				return nil
			})

			err := rv(d.store(), peer)
			if tt.wantErr != nil {
				a.ErrorIs(err, tt.wantErr)
			} else {
				a.NoError(err)
			}
			a.Equal(tt.wantRun, ran)
		})
	}
}

// The BUS-01 scenario: Mallory is a stored peer, and her server answers
// a dial that the user made for Bob, introducing herself as Bob. Quick
// mode used to admit her silently. With Bob's key in peer_pub_b64 the
// dial fails before she is verified.
func TestDialRejectsAnotherPeersKey(t *testing.T) {
	tests := []struct {
		name     string
		mode     VerificationMode
		toBob    bool
		wantCode string
	}{
		{
			name: "quick, another key", mode: VerificationModeQuick,
			wantCode: "peer_key_mismatch",
		},
		{
			name: "strict, another key", mode: VerificationModeStrict,
			wantCode: "peer_key_mismatch",
		},
		{name: "quick, the pinned key", mode: VerificationModeQuick, toBob: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			mallory, malloryRec := newTestDaemon(
				t, VerificationModeAutoAccept, false,
			)
			alice, aliceRec := newTestDaemon(t, tt.mode, false)
			malloryKey := storeAs(t, alice, mallory, "Mallory")
			bobKey := newTestPeerKey(t)
			if tt.toBob {
				bobKey = malloryKey
			} else {
				a.NoError(alice.store().StorePeer(&storage.Peer{
					Name: "Bob", PublicKey: bobKey,
				}))
			}

			addr := startNamedServer(t, mallory, malloryRec, "Bob")
			alice.handleDial(Command{
				ID: "dial",
				Params: mustJSON(DialParams{
					Addr: addr, PeerPubB64: fingerprint.Base64(bobKey),
				}),
			})
			evt := aliceRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "dial" &&
					(e.Evt == EvtSessionStarted || e.Evt == EvtError) ||
					e.Evt == EvtVerifyPeer
			})
			if tt.wantCode == "" {
				a.Equal(EvtSessionStarted, evt.Evt, "dial: %v", evt.Data)
				return
			}
			a.Equal(EvtError, evt.Evt, "got %s: %v", evt.Evt, evt.Data)
			a.Equal(tt.wantCode, evt.Data["code"])
			alice.mu.RLock()
			a.Empty(alice.sessions)
			alice.mu.RUnlock()
		})
	}
}

func TestDialRefusesBadPeerKey(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.handleDial(Command{
		ID: "dial",
		Params: mustJSON(DialParams{
			Addr: "127.0.0.1:1", PeerPubB64: "not-a-key",
		}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "dial" })
	a.Equal(EvtError, evt.Evt)
	a.Equal("invalid_peer_key", evt.Data["code"])
}
