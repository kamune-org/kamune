package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	bolterrors "go.etcd.io/bbolt/errors"
)

func TestStorageErrorReason(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{storage.ErrWrongPassphrase, "wrong_passphrase"},
		{storage.ErrCorruptMetadata, "corrupt_metadata"},
		{storage.ErrInsecurePermissions, "insecure_permissions"},
		{storage.ErrUnsupportedFormat, "unsupported_format"},
		{
			fmt.Errorf("%w: rewrite store file: lock file is not held",
				storage.ErrUpgradeFailed),
			"upgrade_failed",
		},
		{
			fmt.Errorf("%w: %w", storage.ErrCompactFailed, storage.ErrReopen),
			"compact_failed",
		},
		{
			fmt.Errorf("opening kamune db: open db: %w", bolterrors.ErrTimeout),
			"in_use",
		},
		{errPassphraseRequired, "passphrase_required"},
		{errors.New("disk full"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			a := require.New(t)
			wrapped := fmt.Errorf("opening: %w", tt.err)
			a.Equal(tt.want, storageErrorReason(wrapped))
		})
	}
}

// newEncryptedStorage creates a storage at a new path, encrypted with
// passphrase, and returns the path.
func newEncryptedStorage(t *testing.T, passphrase string) string {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "kamune.db")
	d := newQuietDaemon()
	t.Setenv("KAMUNE_DB_PASSPHRASE", passphrase)
	a.NoError(d.openStorage(OpenStorageParams{StoragePath: path}))
	d.cancel()
	d.closeStore()
	return path
}

// storage_open_failed carries a reason that tells a wrong passphrase, and
// a missing one, apart from other failures, in open_storage and in
// submit_passphrase.
func TestStorageOpenFailureReasons(t *testing.T) {
	a := require.New(t)
	path := newEncryptedStorage(t, "right")
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.closeStore()
	run := func(id ID, handle func(Command), params any) recordedEvent {
		t.Helper()
		handle(Command{ID: id, Params: mustJSON(params)})
		return rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	}

	t.Setenv("KAMUNE_DB_PASSPHRASE", "")
	evt := run("missing", d.handleOpenStorage,
		OpenStorageParams{StoragePath: path})
	a.Equal("storage_open_failed", evt.Data["code"])
	a.Equal("passphrase_required", evt.Data["reason"])

	t.Setenv("KAMUNE_DB_PASSPHRASE", "wrong")
	evt = run("env", d.handleOpenStorage, OpenStorageParams{StoragePath: path})
	a.Equal("storage_open_failed", evt.Data["code"])
	a.Equal("wrong_passphrase", evt.Data["reason"], evt.Data["error"])

	evt = run("submit", d.handleSubmitPassphrase,
		SubmitPassphraseParams{Passphrase: "also wrong"})
	a.Equal("storage_open_failed", evt.Data["code"])
	a.Equal("wrong_passphrase", evt.Data["reason"], evt.Data["error"])

	evt = run("right", d.handleSubmitPassphrase,
		SubmitPassphraseParams{Passphrase: "right"})
	a.Equal(EvtResponse, evt.Evt, "submit_passphrase: %v", evt.Data)
	a.NotNil(d.store())
}

// openWith opens the storage at path with passphrase on a new daemon and
// reports the error, closing the storage again.
func openWith(t *testing.T, path, passphrase string) error {
	d := newQuietDaemon()
	t.Cleanup(d.cancel)
	t.Setenv("KAMUNE_DB_PASSPHRASE", passphrase)
	err := d.openStorage(OpenStorageParams{StoragePath: path})
	d.closeStore()
	return err
}

// change_passphrase re-encrypts the open storage so that only the new
// passphrase opens it, keeps the storage open and usable, and replaces or
// removes the passphrase saved in the keychain.
func TestChangePassphrase(t *testing.T) {
	tests := []struct {
		name string
		// old is the storage's passphrase, empty for one without.
		old  string
		save bool
	}{
		{name: "encrypted", old: "old secret"},
		{name: "encrypted, saved", old: "old secret", save: true},
		{name: "unencrypted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d := newQuietDaemon()
			rec := newEventRecorder()
			d.output = json.NewEncoder(rec)
			t.Cleanup(func() {
				d.cancel()
				d.closeStore()
			})
			path := filepath.Join(t.TempDir(), "kamune.db")
			t.Setenv("KAMUNE_DB_PASSPHRASE", tt.old)
			a.NoError(d.openStorage(OpenStorageParams{
				StoragePath: path, DBNoPassphrase: tt.old == "",
			}))
			pub, err := d.store().PublicKey()
			a.NoError(err)
			account := keychainAccount(path)
			a.NoError(keyring.Set(keychainService, account, tt.old))
			t.Cleanup(func() { _ = keyring.Delete(keychainService, account) })

			n := 0
			change := func(old, new string) recordedEvent {
				t.Helper()
				n++
				id := ID(fmt.Sprintf("change-%d", n))
				d.handleChangePassphrase(Command{
					ID: id,
					Params: mustJSON(ChangePassphraseParams{
						OldPassphrase: old, NewPassphrase: new,
						SaveToKeychain: tt.save,
					}),
				})
				return rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == id
				})
			}

			evt := change("not it", "new secret")
			a.Equal(EvtError, evt.Evt)
			a.Equal("wrong_passphrase", evt.Data["code"])
			evt = change(tt.old, "")
			a.Equal(EvtError, evt.Evt)
			a.Equal("passphrase_required", evt.Data["code"])

			evt = change(tt.old, "new secret")
			a.Equal(EvtResponse, evt.Evt, "change_passphrase: %v", evt.Data)
			a.Equal("changed", evt.Data["status"])
			got, err := d.store().PublicKey()
			a.NoError(err, "the storage is no longer usable")
			a.Equal(pub, got)

			secret, err := keyring.Get(keychainService, account)
			if tt.save {
				a.NoError(err)
				a.Equal("new secret", secret)
			} else {
				a.ErrorIs(err, keyring.ErrNotFound,
					"the old passphrase stayed in the keychain")
			}

			// Reopening goes through the new passphrase.
			d.closeStore()
			if tt.old != "" {
				a.ErrorIs(openWith(t, path, tt.old),
					storage.ErrWrongPassphrase)
			}
			a.NoError(openWith(t, path, "new secret"))
		})
	}
}

// change_passphrase needs an open, idle storage.
func TestChangePassphraseNeedsIdleStorage(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	run := func(id ID) recordedEvent {
		t.Helper()
		d.handleChangePassphrase(Command{
			ID: id,
			Params: mustJSON(ChangePassphraseParams{
				NewPassphrase: "new secret",
			}),
		})
		return rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	}

	startTestServer(t, d, rec)
	evt := run("busy")
	a.Equal("storage_busy", evt.Data["code"])

	d.stopServer()
	d.closeStore()
	evt = run("closed")
	a.Equal("storage_not_opened", evt.Data["code"])
}

// A storage that another program holds fails to open with reason
// in_use, once the open has waited for it, not with a bare timeout.
func TestStorageInUseReason(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 5 seconds for the database's lock")
	}
	a := require.New(t)
	holder, _ := newTestDaemon(t, VerificationModeQuick, false)
	holder.mu.RLock()
	path := holder.dbPath
	holder.mu.RUnlock()

	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.handleOpenStorage(Command{
		ID: "open",
		Params: mustJSON(OpenStorageParams{
			StoragePath: path, DBNoPassphrase: true,
		}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "open" })
	a.Equal(EvtError, evt.Evt)
	a.Equal("storage_open_failed", evt.Data["code"])
	a.Equal("in_use", evt.Data["reason"], evt.Data["error"])
}
