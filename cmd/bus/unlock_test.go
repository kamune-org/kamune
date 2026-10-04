package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/zalando/go-keyring"

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

	a.NoError(app.SubmitPassphrase("secret", false))
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
	_, err = openDB(path, nil, false)
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
