package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
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
