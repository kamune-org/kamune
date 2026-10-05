package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/zalando/go-keyring"
	bolterrors "go.etcd.io/bbolt/errors"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// newLockedApp returns an app whose database path is a file in a new
// temporary directory, with no database open.
func newLockedApp(t *testing.T) (*App, string) {
	t.Helper()
	keyring.MockInit()
	app := NewApp()
	path := filepath.Join(t.TempDir(), "db")
	app.dbPath = path
	t.Cleanup(func() { _ = app.ServiceShutdown() })
	return app, path
}

func TestSettingsBeforeUnlockDoNotOpenDB(t *testing.T) {
	a := require.New(t)
	app, path := newLockedApp(t)

	app.SetTheme("dark")
	app.SetLogLevel("DEBUG")
	a.False(app.SetVerificationMode(int(VerificationModeStrict)))
	a.False(app.SetIncognito(true))
	a.ErrorIs(app.SetMyName("alice"), ErrStorageLocked)
	app.RefreshHistory()

	a.Nil(app.store())
	_, err := os.Stat(path)
	a.ErrorIs(err, os.ErrNotExist,
		"nothing may create the database before it is unlocked")

	a.NoError(app.CreateDatabase(path, "secret", "secret", false))
	store := app.store()
	a.NotNil(store)
	a.True(app.GetStorageReady())

	// Settings changed while locked are written once unlocked.
	theme, err := store.GetSettings("bus", "theme")
	a.NoError(err)
	a.Equal("dark", theme)
	level, err := store.GetSettings("bus", "log_level")
	a.NoError(err)
	a.Equal("DEBUG", level)
	a.Equal("dark", app.GetTheme())
	a.Equal(VerificationModeQuick, app.currentVerifMode())
	a.False(app.GetIncognito())

	// The database is protected by the passphrase the user chose.
	a.NoError(app.ServiceShutdown())
	_, err = app.openDB(path, nil, false)
	a.ErrorIs(err, storage.ErrWrongPassphrase)
}

func TestStartupWithSavedPassphraseDoesNotCreateDB(t *testing.T) {
	a := require.New(t)
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "db")
	t.Setenv("KAMUNE_DB_PATH", path)
	a.NoError(keyring.Set(keychainService, keychainAccount(path), ""))

	app := NewApp()
	t.Cleanup(func() { _ = app.ServiceShutdown() })
	a.NoError(app.ServiceStartup(
		context.Background(), application.ServiceOptions{},
	))

	a.Nil(app.store())
	a.False(app.GetStorageReady())
	_, err := os.Stat(path)
	a.ErrorIs(err, os.ErrNotExist)
}

// newUnlockedApp returns an app with a database at a new temporary path,
// unlocked with passphrase.
func newUnlockedApp(t *testing.T, passphrase string) (*App, string) {
	t.Helper()
	app, path := newLockedApp(t)
	require.New(t).NoError(
		app.CreateDatabase(path, passphrase, passphrase, false),
	)
	return app, path
}

// createDB creates a database at a new temporary path with passphrase and
// returns its path.
func createDB(t *testing.T, passphrase string) string {
	t.Helper()
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	store, err := (&App{}).openDB(path, []byte(passphrase), true)
	a.NoError(err)
	a.NoError(store.Close())
	return path
}

func TestUnlockRefusedWhileStorageInUse(t *testing.T) {
	cases := []struct {
		name string
		use  func(app *App)
	}{
		{"session", func(app *App) {
			app.sessions = append(app.sessions, &liveSession{ID: "s1"})
		}},
		{"server starting", func(app *App) { app.starting++ }},
		{"dial", func(app *App) { app.dialOps++ }},
		{"server or session closing", func(app *App) { app.closing++ }},
		{"relay listeners", func(app *App) {
			app.relayListeners = newMultiListener()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, path := newUnlockedApp(t, "secret")
			other := createDB(t, "other")
			open := app.store()

			app.mu.Lock()
			tc.use(app)
			app.mu.Unlock()
			t.Cleanup(func() {
				app.mu.Lock()
				app.sessions = nil
				app.starting = 0
				app.dialOps = 0
				app.closing = 0
				app.relayListeners = nil
				app.mu.Unlock()
			})

			a.ErrorIs(
				app.SubmitPassphrase(other, "other", false), ErrStorageBusy,
			)
			a.Same(open, app.store())
			a.Equal(path, app.GetDBPath())
			_, err := open.GetSettings("bus", "theme")
			a.NoError(err, "the database in use must stay open")
		})
	}
}

func TestUnlockOpenDatabaseKeepsIt(t *testing.T) {
	a := require.New(t)
	app, path := newUnlockedApp(t, "secret")
	open := app.store()

	a.ErrorIs(app.SubmitPassphrase(path, "secret", false), ErrStorageOpen)
	a.ErrorIs(app.SubmitPassphrase(path, "wrong", false), ErrStorageOpen)
	a.Same(open, app.store())
	_, err := open.GetSettings("bus", "theme")
	a.NoError(err, "the open database must stay open")
}

// TestUnlockOpenDatabaseUnderOtherPath checks that the open database,
// named by another path to the same file, counts as the open one, so it
// is neither opened a second time nor reported as held by another
// program.
func TestUnlockOpenDatabaseUnderOtherPath(t *testing.T) {
	app, path := newUnlockedApp(t, "secret")
	link := filepath.Join(t.TempDir(), "link")
	require.New(t).NoError(os.Symlink(path, link))
	wd, err := os.Getwd()
	require.New(t).NoError(err)
	rel, err := filepath.Rel(wd, path)
	require.New(t).NoError(err)

	cases := []struct {
		name string
		path string
	}{
		{"symbolic link", link},
		{"relative path", rel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			open := app.store()
			a.ErrorIs(app.SubmitPassphrase(tc.path, "secret", false),
				ErrStorageOpen)
			a.Same(open, app.store())
			a.Equal(path, app.GetDBPath())
		})
	}
}

func TestSameDBPath(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	other := filepath.Join(dir, "other")
	require.New(t).NoError(os.WriteFile(db, nil, 0o600))
	require.New(t).NoError(os.WriteFile(other, nil, 0o600))
	link := filepath.Join(dir, "link")
	require.New(t).NoError(os.Symlink(db, link))

	cases := []struct {
		name string
		x, y string
		same bool
	}{
		{"same path", db, db, true},
		{"unclean path", db, dir + "/./db", true},
		{"symbolic link", link, db, true},
		{"other file", db, other, false},
		{"missing file", db, filepath.Join(dir, "missing"), false},
		{"both missing, same path", dir + "/x", dir + "/./x", true},
		{"empty", "", db, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.same, sameDBPath(tc.x, tc.y))
			a.Equal(tc.same, sameDBPath(tc.y, tc.x))
		})
	}
}

// createDBWithSettings creates a database as createDB does, with the bus
// settings settings stored in it.
func createDBWithSettings(
	t *testing.T, passphrase string, settings map[string]string,
) string {
	t.Helper()
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	store, err := (&App{}).openDB(path, []byte(passphrase), true)
	a.NoError(err)
	for key, value := range settings {
		a.NoError(store.SetSettings("bus", key, value))
	}
	a.NoError(store.Close())
	return path
}

// TestSwitchDatabaseResetsSettings switches from a database in
// Auto-Accept and incognito mode, with a dark theme and the DEBUG log
// level, to another one, and checks that the new database's settings
// apply, and the defaults for what it does not keep, so that none of the
// old database's settings carries over.
func TestSwitchDatabaseResetsSettings(t *testing.T) {
	cases := []struct {
		name          string
		settings      map[string]string
		wantMode      VerificationMode
		wantIncognito bool
		wantTheme     string
		wantLevel     string
	}{
		{name: "new database", wantMode: VerificationModeQuick,
			wantLevel: "INFO"},
		{name: "stored settings", settings: map[string]string{
			"verification_mode": "0", "incognito": "false",
			"theme": "light", "log_level": "WARN",
		}, wantMode: VerificationModeStrict, wantTheme: "light",
			wantLevel: "WARN"},
		{name: "stored Auto-Accept and incognito", settings: map[string]string{
			"verification_mode": "2", "incognito": "true",
		}, wantMode: VerificationModeAutoAccept, wantIncognito: true,
			wantLevel: "INFO"},
		{name: "unknown mode and level", settings: map[string]string{
			"verification_mode": "7", "log_level": "LOUD",
		}, wantMode: VerificationModeStrict, wantLevel: "INFO"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.confirmFn = func(string, string) bool { return true }
			a.True(app.SetVerificationMode(int(VerificationModeAutoAccept)))
			a.True(app.SetIncognito(true))
			app.SetTheme("dark")
			app.SetLogLevel("DEBUG")

			other := createDBWithSettings(t, "other", tc.settings)
			events := recordEvents(app)
			a.NoError(app.SubmitPassphrase(other, "other", false))

			a.Equal(int(tc.wantMode), app.GetVerificationMode())
			a.Equal(tc.wantIncognito, app.GetIncognito())
			a.Equal(tc.wantTheme, app.GetTheme())
			a.Equal(tc.wantLevel, app.GetLogLevel())
			a.NotEmpty(events.named("verification-mode-changed"))
			a.NotEmpty(events.named("incognito-changed"))
		})
	}
}

func TestUnlockOtherDatabaseClosesOldOnlyOnSuccess(t *testing.T) {
	a := require.New(t)
	app, path := newUnlockedApp(t, "secret")
	other := createDB(t, "other")
	open := app.store()

	a.Error(app.SubmitPassphrase(other, "wrong", false))
	a.Same(open, app.store())
	a.Equal(path, app.GetDBPath())
	_, err := open.GetSettings("bus", "theme")
	a.NoError(err, "a failed unlock must leave the open database open")

	a.NoError(app.SubmitPassphrase(other, "other", false))
	a.NotSame(open, app.store())
	a.Equal(other, app.GetDBPath())
	a.True(app.GetStorageReady())
	_, err = open.GetSettings("bus", "theme")
	a.Error(err, "the database unlocked before must be closed")
}

// readUntilEnd is a test server handler that reads until the session ends.
func readUntilEnd(tr *kamune.Transport) error {
	for {
		if _, _, err := tr.ReceivePayload(); err != nil {
			return nil
		}
	}
}

// dialTestTransport returns a session dialed to a test server, which
// reads from it until it ends.
func dialTestTransport(t *testing.T) *kamune.Transport {
	t.Helper()
	a := require.New(t)
	addr, _ := startTestServer(t, "srv", readUntilEnd)
	d, err := kamune.NewDialer(
		addr, openTestStorage(t),
		func(*storage.Storage, *storage.Peer) error { return nil },
		kamune.DialWithTCP(),
	)
	a.NoError(err)
	tr, err := d.Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestStorageBusyUntilTeardownEnds(t *testing.T) {
	cases := []struct {
		name     string
		teardown func(app *App) error
	}{
		{"stop server", func(app *App) error { return app.StopServer() }},
		{"disconnect session", func(app *App) error {
			return app.DisconnectSession("s1")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			other := createDB(t, "other")

			// The test ends the session's receive loop, so the teardown
			// waits for the test after it has taken the session out.
			receiveDone := make(chan struct{})
			app.mu.Lock()
			app.sessions = append(app.sessions, &liveSession{
				ID:          "s1",
				Transport:   dialTestTransport(t),
				ReceiveDone: receiveDone,
			})
			app.mu.Unlock()

			done := make(chan error, 1)
			go func() { done <- tc.teardown(app) }()
			a.Eventually(func() bool {
				return len(app.GetSessions()) == 0
			}, testWait, time.Millisecond)
			a.ErrorIs(
				app.SubmitPassphrase(other, "other", false), ErrStorageBusy,
				"the database must stay open while the session closes",
			)

			close(receiveDone)
			a.NoError(<-done)
			a.NoError(app.SubmitPassphrase(other, "other", false))
		})
	}
}

// TestCancelServerStart cancels a server start that waits for its relay
// and checks that the start ends at once without a server, that it holds
// the database until then, and that no second start may run alongside
// it.
func TestCancelServerStart(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	t.Cleanup(func() { _ = app.StopServer() })
	other := createDB(t, "other")

	// A relay that takes the server's connection and never answers, so
	// the start waits on it until it is cancelled.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()

	started := make(chan error, 1)
	go func() {
		_, _, err := app.StartServer(
			"", "relay", "tcp://"+ln.Addr().String(), "srv", "", "", "",
			false, false, "",
		)
		started <- err
	}()
	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(testWait):
		t.Fatal("the server start did not reach the relay")
	}

	a.ErrorIs(
		app.SubmitPassphrase(other, "other", false), ErrStorageBusy,
		"a start in progress uses the database",
	)
	_, _, err = app.StartServer(
		"127.0.0.1:0", "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.ErrorIs(err, ErrServerStarting)

	app.CancelStartServer()
	// Well below the relay handshake timeout, which would end the start
	// as well.
	const cancelWait = 10 * time.Second
	select {
	case err := <-started:
		a.ErrorIs(err, ErrStartCancelled)
	case <-time.After(cancelWait):
		t.Fatal("the cancelled server start did not end")
	}
	a.False(app.GetServerRunning())
	a.NoError(app.SubmitPassphrase(other, "other", false))
}

func TestFailedServerStartLeavesStorageFree(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	other := createDB(t, "other")

	// NewServer rejects a name with a control character, after the direct
	// P2P listener has been set up.
	_, _, err := app.StartServer(
		"127.0.0.1:0", "udp", "", "bad\x01name", "", "", "",
		true, false, "127.0.0.1:9",
	)
	a.Error(err)

	app.mu.RLock()
	listener := app.p2pListener
	busy := app.storageBusyLocked()
	app.mu.RUnlock()
	if listener != nil {
		t.Cleanup(func() { _ = listener.Close() })
	}
	a.Nil(listener)
	a.False(busy)
	a.NoError(app.SubmitPassphrase(other, "other", false))
}

// TestSubmitPassphraseNeverCreates checks that SubmitPassphrase opens
// only a database that exists, so that a typo in the path cannot create
// a new one with a passphrase entered once.
func TestSubmitPassphraseNeverCreates(t *testing.T) {
	a := require.New(t)
	app, path := newLockedApp(t)

	err := app.SubmitPassphrase(path, "secret", false)
	a.ErrorIs(err, os.ErrNotExist)
	a.Equal("There is no database at this path", err.Error())
	a.Nil(app.store())
	_, err = os.Stat(path)
	a.ErrorIs(err, os.ErrNotExist)
}

// TestCreateDatabaseNeedsRepeatedPassphrase checks that a new database is
// created only when its passphrase was entered twice alike, and that the
// passphrase then opens it.
func TestCreateDatabaseNeedsRepeatedPassphrase(t *testing.T) {
	cases := []struct {
		name               string
		passphrase, repeat string
		wantErr            error
	}{
		{"repeated", "secret", "secret", nil},
		{"typo", "secret", "secrte", ErrPassphraseMismatch},
		{"not repeated", "secret", "", ErrPassphraseMismatch},
		{"empty", "", "", ErrPassphraseRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, path := newLockedApp(t)

			err := app.CreateDatabase(path, tc.passphrase, tc.repeat, true)
			if tc.wantErr != nil {
				a.ErrorIs(err, tc.wantErr)
				a.Nil(app.store())
				_, err = os.Stat(path)
				a.ErrorIs(err, os.ErrNotExist)
				_, err = keyring.Get(keychainService, keychainAccount(path))
				a.ErrorIs(err, keyring.ErrNotFound)
				return
			}
			a.NoError(err)
			a.NotNil(app.store())
			a.True(app.DatabaseExists(path))
			saved, err := keyring.Get(keychainService, keychainAccount(path))
			a.NoError(err)
			a.Equal(tc.passphrase, saved)

			a.NoError(app.ServiceShutdown())
			reopened, _ := newLockedApp(t)
			a.NoError(reopened.SubmitPassphrase(path, tc.passphrase, false))
		})
	}
}

func TestDatabaseExists(t *testing.T) {
	a := require.New(t)
	app, path := newUnlockedApp(t, "secret")
	a.True(app.DatabaseExists(path))
	a.False(app.DatabaseExists(filepath.Join(t.TempDir(), "db")))
	a.False(app.DatabaseExists(""))
}

func TestSubmitEmptyPassphraseRefused(t *testing.T) {
	a := require.New(t)
	app, path := newLockedApp(t)

	a.ErrorIs(app.SubmitPassphrase(path, "", true), ErrPassphraseRequired)
	a.Nil(app.store())
	_, err := os.Stat(path)
	a.ErrorIs(err, os.ErrNotExist)
	_, err = keyring.Get(keychainService, keychainAccount(path))
	a.ErrorIs(err, keyring.ErrNotFound)
}

func TestOpenWithoutPassphraseNeedsConfirmation(t *testing.T) {
	a := require.New(t)
	app, path := newLockedApp(t)
	var asked []string
	answer := false
	app.confirmFn = func(title, message string) bool {
		asked = append(asked, message)
		return answer
	}

	opened, err := app.OpenWithoutPassphrase(path, true)
	a.NoError(err)
	a.False(opened)
	a.Len(asked, 1)
	a.Contains(asked[0], "not protected")
	a.Nil(app.store())
	_, err = os.Stat(path)
	a.ErrorIs(err, os.ErrNotExist, "a declined prompt must not create it")
	_, err = keyring.Get(keychainService, keychainAccount(path))
	a.ErrorIs(err, keyring.ErrNotFound)

	answer = true
	opened, err = app.OpenWithoutPassphrase(path, true)
	a.NoError(err)
	a.True(opened)
	a.NotNil(app.store())
	a.True(app.GetNoPassphrase())
	saved, err := keyring.Get(keychainService, keychainAccount(path))
	a.NoError(err)
	a.Empty(saved)
}

func TestNoPassphraseFlagFollowsOpenDatabase(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	a.False(app.GetNoPassphrase())

	other := filepath.Join(t.TempDir(), "db")
	app.confirmFn = func(string, string) bool { return true }
	opened, err := app.OpenWithoutPassphrase(other, false)
	a.NoError(err)
	a.True(opened)
	a.True(app.GetNoPassphrase())
}

func TestStartupKeepsSavedPassphrase(t *testing.T) {
	cases := []struct {
		name string
		// setup prepares the database at path and returns a function
		// that ends anything it holds open, or nil.
		setup func(t *testing.T, path string) func()
		errIs error
	}{
		{
			name: "database in use",
			setup: func(t *testing.T, path string) func() {
				store, err := (&App{}).openDB(path, []byte("secret"), true)
				require.New(t).NoError(err)
				return func() { _ = store.Close() }
			},
			errIs: bolterrors.ErrTimeout,
		},
		{
			name:  "no database",
			setup: func(*testing.T, string) func() { return nil },
			errIs: os.ErrNotExist,
		},
		{
			// The file may be another database, or a damaged copy, and
			// the saved passphrase still open the right one.
			name: "passphrase does not open the file",
			setup: func(t *testing.T, path string) func() {
				store, err := (&App{}).openDB(path, []byte("other"), true)
				require.New(t).NoError(err)
				require.New(t).NoError(store.Close())
				return nil
			},
			errIs: storage.ErrWrongPassphrase,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			keyring.MockInit()
			path := filepath.Join(t.TempDir(), "db")
			t.Setenv("KAMUNE_DB_PATH", path)
			if release := tc.setup(t, path); release != nil {
				t.Cleanup(release)
			}
			account := keychainAccount(path)
			a.NoError(keyring.Set(keychainService, account, "secret"))

			app := NewApp()
			app.dbTimeout = 100 * time.Millisecond
			t.Cleanup(func() { _ = app.ServiceShutdown() })
			a.NoError(app.ServiceStartup(
				context.Background(), application.ServiceOptions{},
			))

			a.Nil(app.store())
			a.NotEmpty(app.GetStorageError())
			saved, err := keyring.Get(keychainService, account)
			a.NoError(err, "the saved passphrase must be kept")
			a.Equal("secret", saved)
			a.ErrorIs(app.UnlockWithSavedPassphrase(path), tc.errIs)
			a.Nil(app.store())
			saved, err = keyring.Get(keychainService, account)
			a.NoError(err, "a retry must keep the saved passphrase")
			a.Equal("secret", saved)
		})
	}
}

func TestForgetSavedPassphraseAsksFirst(t *testing.T) {
	a := require.New(t)
	app, path := newLockedApp(t)
	account := keychainAccount(path)
	asked := 0
	answer := false
	app.confirmFn = func(string, string) bool {
		asked++
		return answer
	}

	forgot, err := app.ForgetSavedPassphrase(path)
	a.ErrorIs(err, ErrNoSavedPassphrase)
	a.False(forgot)
	a.Zero(asked, "there is nothing to ask about")

	a.NoError(keyring.Set(keychainService, account, "secret"))
	forgot, err = app.ForgetSavedPassphrase(path)
	a.NoError(err)
	a.False(forgot)
	a.Equal(1, asked)
	saved, err := keyring.Get(keychainService, account)
	a.NoError(err, "a declined prompt must keep the saved passphrase")
	a.Equal("secret", saved)

	answer = true
	forgot, err = app.ForgetSavedPassphrase(path)
	a.NoError(err)
	a.True(forgot)
	a.Equal(2, asked)
	_, err = keyring.Get(keychainService, account)
	a.ErrorIs(err, keyring.ErrNotFound)
}

func TestUnlockWithSavedPassphraseRetries(t *testing.T) {
	a := require.New(t)
	keyring.MockInit()
	path := filepath.Join(t.TempDir(), "db")
	t.Setenv("KAMUNE_DB_PATH", path)
	held, err := (&App{}).openDB(path, []byte("secret"), true)
	a.NoError(err)
	a.NoError(keyring.Set(keychainService, keychainAccount(path), "secret"))

	app := NewApp()
	app.dbTimeout = 100 * time.Millisecond
	t.Cleanup(func() { _ = app.ServiceShutdown() })
	a.NoError(app.ServiceStartup(
		context.Background(), application.ServiceOptions{},
	))
	a.Nil(app.store())
	a.Contains(app.GetStorageError(), "in use")

	a.NoError(held.Close())
	a.NoError(app.UnlockWithSavedPassphrase(path))
	a.NotNil(app.store())
	a.True(app.GetStorageReady())
	a.Empty(app.GetStorageError())
}

func TestSubmitPassphraseReportsWrongPassphrase(t *testing.T) {
	a := require.New(t)
	app, _ := newLockedApp(t)
	other := createDB(t, "other")

	err := app.SubmitPassphrase(other, "wrong", false)
	a.ErrorIs(err, storage.ErrWrongPassphrase)
	a.Equal("Wrong passphrase", err.Error())
}

// TestIncognitoReadsAreSynchronized toggles incognito mode while a session
// reads it, as the receive loop does. It only finds a data race when run
// with -race; without it, it checks nothing.
func TestIncognitoReadsAreSynchronized(t *testing.T) {
	app, _ := newUnlockedApp(t, "secret")
	session := &liveSession{ID: "s1"}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 20 {
			app.SetIncognito(i%2 == 0)
		}
	})
	wg.Go(func() {
		for range 20 {
			_ = app.sessionIncognito(session)
		}
	})
	wg.Wait()
}

func TestSetIncognitoRefusedWhileSessionStarts(t *testing.T) {
	cases := []struct {
		name string
		// begin starts a server or a dial and returns once it is under
		// way, with a function that lets it end and waits for it.
		begin func(t *testing.T, app *App) (finish func())
	}{
		{
			name: "dial waiting for verification",
			begin: func(t *testing.T, app *App) func() {
				addr, _ := startTestServer(t, "srv", readUntilEnd)
				done := make(chan error, 1)
				go func() {
					_, err := app.ConnectToServer(
						addr, "tcp", "", "", "", "", "", "", "",
						false, false, "",
					)
					done <- err
				}()
				ids := waitPending(t, app, 1)
				return func() {
					app.VerifyResponse(ids[0], true)
					require.New(t).NoError(<-done)
				}
			},
		},
		{
			name: "server start waiting for its relay",
			begin: func(t *testing.T, app *App) func() {
				a := require.New(t)
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				a.NoError(err)
				t.Cleanup(func() { _ = ln.Close() })
				accepted := make(chan net.Conn, 1)
				go func() {
					if c, err := ln.Accept(); err == nil {
						accepted <- c
					}
				}()
				done := make(chan error, 1)
				go func() {
					_, _, err := app.StartServer(
						"", "relay", "tcp://"+ln.Addr().String(), "srv",
						"", "", "", false, false, "",
					)
					done <- err
				}()
				var conn net.Conn
				select {
				case conn = <-accepted:
				case <-time.After(testWait):
					t.Fatal("the server start did not reach the relay")
				}
				return func() {
					_ = conn.Close()
					a.Error(<-done)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			var toasts []string
			app.onEvent = func(name string, data ...any) {
				if name == "toast" {
					toasts = append(toasts, data[0].(string))
				}
			}

			finish := tc.begin(t, app)
			a.False(app.SetIncognito(true),
				"what is starting read the mode already")
			a.False(app.GetIncognito())
			a.Len(toasts, 1)
			a.Contains(toasts[0], "Incognito mode not changed")

			finish()
			a.True(app.SetIncognito(true))
			a.True(app.GetIncognito())
		})
	}
}
