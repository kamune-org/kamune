package relayconn

import (
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/relayconn/relayleg"
	"github.com/kamune-org/kamune/pkg/storage"
)

var _ SettingsStore = (*storage.Storage)(nil)

func openTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "relay-keys.db")
	st, err := storage.OpenStorage(
		storage.WithDBPath(path),
		storage.WithNoPassphrase(),
	)
	a.NoError(err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSettingsKeyStore(t *testing.T) {
	a := require.New(t)
	st := openTestStorage(t)
	ks := SettingsKeyStore(st)
	addr, err := ParseAddress("wss://example.com/kamune/ws")
	a.NoError(err)
	name := addr.StoreName()
	key := fixedRelayKey()

	got, ok, err := ks.RelayKey(name)
	a.NoError(err)
	a.False(ok)
	a.Equal(relayleg.PublicKey{}, got)

	a.NoError(ks.SetRelayKey(name, key))
	stored, err := st.GetSettings(relayKeySettingsApp, name)
	a.NoError(err)
	a.Equal(key.String(), stored)
	got, ok, err = ks.RelayKey(name)
	a.NoError(err)
	a.True(ok)
	a.Equal(key, got)

	a.NoError(ks.DeleteRelayKey(name))
	_, ok, err = ks.RelayKey(name)
	a.NoError(err)
	a.False(ok)

	a.NoError(ks.DeleteRelayKey(name))

	const badValue = "not-a-relay-key-value"
	a.NoError(st.SetSettings(relayKeySettingsApp, name, badValue))
	_, ok, err = ks.RelayKey(name)
	a.False(ok)
	a.Error(err)
	a.Contains(err.Error(), name)
	a.NotContains(err.Error(), badValue)
}

func TestMemoryKeyStore(t *testing.T) {
	a := require.New(t)
	ks := NewMemoryKeyStore()
	key := fixedRelayKey()
	other := key
	other[0] ^= 0xff

	_, ok, err := ks.RelayKey("missing")
	a.NoError(err)
	a.False(ok)
	a.NoError(ks.DeleteRelayKey("missing"))

	a.NoError(ks.SetRelayKey("a", key))
	a.NoError(ks.SetRelayKey("b", other))
	got, ok, err := ks.RelayKey("a")
	a.NoError(err)
	a.True(ok)
	a.Equal(key, got)
	got[0] ^= 0xff
	got, ok, err = ks.RelayKey("a")
	a.NoError(err)
	a.True(ok)
	a.Equal(key, got)

	local := key
	a.NoError(ks.SetRelayKey("a", local))
	local[1] ^= 0xff
	got, ok, err = ks.RelayKey("a")
	a.NoError(err)
	a.True(ok)
	a.Equal(key, got)

	got, ok, err = ks.RelayKey("b")
	a.NoError(err)
	a.True(ok)
	a.Equal(other, got)

	a.NoError(ks.DeleteRelayKey("a"))
	_, ok, err = ks.RelayKey("a")
	a.NoError(err)
	a.False(ok)
	_, ok, err = ks.RelayKey("b")
	a.NoError(err)
	a.True(ok)
}

func TestMemoryKeyStoreConcurrent(t *testing.T) {
	a := require.New(t)
	ks := NewMemoryKeyStore()
	const n = 64
	errc := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := exerciseMemory(ks, i); err != nil {
				errc <- err
			}
		}(i)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		a.NoError(err)
	}
	key := fixedRelayKey()
	a.NoError(ks.SetRelayKey("final", key))
	got, ok, err := ks.RelayKey("final")
	a.NoError(err)
	a.True(ok)
	a.Equal(key, got)
}

func exerciseMemory(ks KeyStore, i int) error {
	key := fixedRelayKey()
	key[0] = byte(i)
	name := "n" + strconv.Itoa(i%8)
	if err := ks.SetRelayKey(name, key); err != nil {
		return err
	}
	if _, _, err := ks.RelayKey(name); err != nil {
		return err
	}
	if err := ks.DeleteRelayKey("missing"); err != nil {
		return err
	}
	return ks.DeleteRelayKey(name)
}

func TestForgetRelayKey(t *testing.T) {
	stores := []struct {
		name string
		ks   KeyStore
	}{
		{name: "memory", ks: NewMemoryKeyStore()},
		{name: "settings", ks: SettingsKeyStore(openTestStorage(t))},
	}
	key := fixedRelayKey()
	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			a := require.New(t)
			addr, err := ParseAddress(
				"WSS://Example.COM./ws?rk=" + key.String(),
			)
			a.NoError(err)
			a.Equal("example.com:443", addr.StoreName())
			a.NoError(st.ks.SetRelayKey(addr.StoreName(), key))

			other, err := ParseAddress("example.com")
			a.NoError(err)
			a.NoError(ForgetRelayKey(st.ks, other))
			_, ok, err := st.ks.RelayKey(addr.StoreName())
			a.NoError(err)
			a.False(ok)
			a.NoError(ForgetRelayKey(st.ks, other))

			pathAddr, err := ParseAddress(
				"wss://example.com/kamune/ws",
			)
			a.NoError(err)
			a.NoError(st.ks.SetRelayKey(pathAddr.StoreName(), key))
			a.NoError(ForgetRelayKey(st.ks, other))
			got, ok, err := st.ks.RelayKey(pathAddr.StoreName())
			a.NoError(err)
			a.True(ok)
			a.Equal(key, got)
			a.NoError(ForgetRelayKey(st.ks, pathAddr))
			_, ok, err = st.ks.RelayKey(pathAddr.StoreName())
			a.NoError(err)
			a.False(ok)
		})
	}
}
