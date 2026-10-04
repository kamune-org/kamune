package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestPassphraseSavedToKeychainOnlyOnRequest(t *testing.T) {
	tests := []struct {
		submit    *SubmitPassphraseParams
		name      string
		wantSaved bool
	}{
		{
			name: "environment passphrase",
		},
		{
			name:   "submitted passphrase",
			submit: &SubmitPassphraseParams{Passphrase: "submitted"},
		},
		{
			name: "submitted passphrase with save_to_keychain",
			submit: &SubmitPassphraseParams{
				Passphrase:     "submitted",
				SaveToKeychain: true,
			},
			wantSaved: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d := newQuietDaemon()
			t.Cleanup(func() {
				d.cancel()
				d.closeStore()
			})
			path := filepath.Join(t.TempDir(), "kamune.db")

			if tt.submit == nil {
				t.Setenv("KAMUNE_DB_PASSPHRASE", "from-environment")
				a.NoError(d.openStorage(OpenStorageParams{StoragePath: path}))
			} else {
				t.Setenv("KAMUNE_DB_PASSPHRASE", "")
				err := d.openStorage(OpenStorageParams{StoragePath: path})
				a.ErrorIs(err, errPassphraseRequired)
				d.handleSubmitPassphrase(Command{
					ID: "submit", Params: mustJSON(*tt.submit),
				})
			}
			a.NotNil(d.store())

			secret, err := keyring.Get(keychainService, keychainAccount(path))
			if !tt.wantSaved {
				a.ErrorIs(err, keyring.ErrNotFound)
				return
			}
			a.NoError(err)
			a.Equal(tt.submit.Passphrase, secret)
		})
	}
}
