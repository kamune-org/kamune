package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/kamune-org/kamune/pkg/storage"
)

// openWithout opens the database at path without a passphrase, creating
// it, as the user does after confirming.
func openWithout(t *testing.T, app *App, path string) {
	t.Helper()
	a := require.New(t)
	app.confirmFn = func(string, string) bool { return true }
	opened, err := app.OpenWithoutPassphrase(path, false)
	a.NoError(err)
	a.True(opened)
}

func TestChangePassphrase(t *testing.T) {
	cases := []struct {
		name string
		// current is the passphrase the database is created with.
		current string
		old     string
		new     string
		// confirm answers the question asked before the passphrase is
		// removed.
		confirm bool
		// keychain is whether a passphrase is saved in the keychain
		// before, and save is ChangePassphrase's saveToKeychain.
		keychain bool
		save     bool
		changed  bool
		errIs    error
	}{
		{name: "changed", current: "secret", old: "secret",
			new: "other", changed: true},
		{name: "changed and saved", current: "secret", old: "secret",
			new: "other", save: true, changed: true},
		{name: "changed drops the saved passphrase", current: "secret",
			old: "secret", new: "other", keychain: true, changed: true},
		{name: "changed replaces the saved passphrase", current: "secret",
			old: "secret", new: "other", keychain: true, save: true,
			changed: true},
		{name: "wrong current passphrase", current: "secret",
			old: "wrong", new: "other", keychain: true,
			errIs: storage.ErrWrongPassphrase},
		{name: "same passphrase", current: "secret", old: "secret",
			new: "secret", errIs: ErrSamePassphrase},
		{name: "removed once confirmed", current: "secret",
			old: "secret", new: "", confirm: true, changed: true},
		{name: "removal declined", current: "secret", old: "secret",
			new: ""},
		{name: "added", current: "", old: "", new: "secret",
			changed: true},
		{name: "added and saved", current: "", old: "", new: "secret",
			save: true, changed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, path := newLockedApp(t)
			if tc.current == "" {
				openWithout(t, app, path)
			} else {
				a.NoError(app.CreateDatabase(
					path, tc.current, tc.current, false,
				))
			}
			account := keychainAccount(path)
			if tc.keychain {
				a.NoError(keyring.Set(keychainService, account, tc.current))
			}
			// A peer stored before the change must be there after it.
			peer := newTestPeer(t, "carol")
			a.NoError(app.store().StorePeer(peer))
			asked := 0
			app.confirmFn = func(string, string) bool {
				asked++
				return tc.confirm
			}
			var events []string
			app.onEvent = func(name string, _ ...any) {
				events = append(events, name)
			}

			changed, err := app.ChangePassphrase(tc.old, tc.new, tc.save)
			if tc.errIs != nil {
				a.ErrorIs(err, tc.errIs)
			} else {
				a.NoError(err)
			}
			a.Equal(tc.changed, changed)
			if tc.new == "" && tc.old != "" {
				a.Equal(1, asked, "removing the passphrase asks first")
			} else {
				a.Zero(asked)
			}

			opens := tc.current
			if tc.changed {
				opens = tc.new
				a.Contains(events, "db-passphrase-changed")
			}
			a.Equal(opens == "", app.GetNoPassphrase())
			a.NotNil(app.store(), "the database stays open")
			_, err = app.store().FindPeer(peer.PublicKey)
			a.NoError(err)

			saved, kerr := keyring.Get(keychainService, account)
			switch {
			case tc.changed && tc.save:
				a.NoError(kerr)
				a.Equal(tc.new, saved)
			case tc.changed:
				a.ErrorIs(kerr, keyring.ErrNotFound,
					"a saved passphrase that no longer opens the "+
						"database is removed")
			case tc.keychain:
				a.NoError(kerr, "a failed change keeps the saved one")
				a.Equal(tc.current, saved)
			}

			a.NoError(app.ServiceShutdown())
			store, err := app.openDB(path, []byte(opens), false)
			a.NoError(err)
			_, err = store.FindPeer(peer.PublicKey)
			a.NoError(err)
			a.NoError(store.Close())
			if opens != tc.current {
				_, err = app.openDB(path, []byte(tc.current), false)
				a.ErrorIs(err, storage.ErrWrongPassphrase,
					"the old passphrase no longer opens the database")
			}
		})
	}
}

func TestChangePassphraseRefusedWhileStorageInUse(t *testing.T) {
	a := require.New(t)
	app, path := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.sessions = append(app.sessions, &liveSession{ID: "s1"})
	app.mu.Unlock()

	changed, err := app.ChangePassphrase("secret", "other", false)
	a.ErrorIs(err, ErrStorageBusy)
	a.False(changed)

	app.mu.Lock()
	app.sessions = nil
	app.mu.Unlock()
	a.NoError(app.ServiceShutdown())
	store, err := app.openDB(path, []byte("secret"), false)
	a.NoError(err, "a refused change keeps the passphrase")
	a.NoError(store.Close())
}

func TestChangePassphraseNeedsOpenDatabase(t *testing.T) {
	a := require.New(t)
	app, _ := newLockedApp(t)
	changed, err := app.ChangePassphrase("", "secret", false)
	a.ErrorIs(err, ErrStorageLocked)
	a.False(changed)
	a.Nil(app.store(), "nor does it open the database")
}
