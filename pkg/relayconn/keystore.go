package relayconn

import (
	"fmt"
	"sync"

	"github.com/kamune-org/kamune/pkg/relayconn/relayleg"
)

// relayKeySettingsApp is the settings app SettingsKeyStore uses.
const relayKeySettingsApp = "kamune-relay-keys"

// KeyStore is the authority for relay key pins. Names are
// Address.StoreName values.
//
// NewMemoryKeyStore is safe for concurrent use. SettingsKeyStore is
// as safe as the SettingsStore it wraps.
type KeyStore interface {
	// RelayKey returns the key stored for name. The bool is false
	// when name is absent. A read failure is an error.
	RelayKey(name string) (relayleg.PublicKey, bool, error)
	// SetRelayKey stores k under name.
	SetRelayKey(name string, k relayleg.PublicKey) error
	// DeleteRelayKey removes name. An absent name is not an error.
	DeleteRelayKey(name string) error
}

// SettingsStore is the settings API SettingsKeyStore needs.
// A storage.Storage value satisfies it. The assertion lives in the
// test, so this package does not import storage.
type SettingsStore interface {
	// GetSettings returns the value stored under app and key.
	// A missing key returns an empty string and a nil error.
	GetSettings(app, key string) (string, error)
	// SetSettings stores value under app and key.
	SetSettings(app, key, value string) error
	// DeleteSettings removes app and key. An absent key is not
	// an error.
	DeleteSettings(app, key string) error
}

type memoryKeyStore struct {
	keys map[string]relayleg.PublicKey
	mu   sync.RWMutex
}

type settingsKeyStore struct {
	s SettingsStore
}

var (
	_ KeyStore = (*memoryKeyStore)(nil)
	_ KeyStore = settingsKeyStore{}
)

// NewMemoryKeyStore returns an in-memory KeyStore. It is safe for
// concurrent use.
func NewMemoryKeyStore() KeyStore {
	return &memoryKeyStore{keys: make(map[string]relayleg.PublicKey)}
}

func (s *memoryKeyStore) RelayKey(
	name string,
) (relayleg.PublicKey, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[name]
	return k, ok, nil
}

func (s *memoryKeyStore) SetRelayKey(
	name string, k relayleg.PublicKey,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[name] = k
	return nil
}

func (s *memoryKeyStore) DeleteRelayKey(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, name)
	return nil
}

// SettingsKeyStore returns a KeyStore that stores each relay key as
// PublicKey.String under the app "kamune-relay-keys". The settings
// key is the store name. GetSettings reports a missing key as an
// empty string, and that is not found rather than an error. A stored
// value that does not parse is a read error that names the store
// name and does not include the value.
//
// SettingsKeyStore adds no locking. It is as safe for concurrent use
// as the SettingsStore it wraps.
func SettingsKeyStore(s SettingsStore) KeyStore {
	return settingsKeyStore{s: s}
}

func (s settingsKeyStore) RelayKey(
	name string,
) (relayleg.PublicKey, bool, error) {
	var zero relayleg.PublicKey
	v, err := s.s.GetSettings(relayKeySettingsApp, name)
	if err != nil {
		return zero, false, err
	}
	if v == "" {
		return zero, false, nil
	}
	k, err := relayleg.ParsePublicKey(v)
	if err != nil {
		return zero, false, fmt.Errorf(
			"relay key for %s is invalid", name,
		)
	}
	return k, true, nil
}

func (s settingsKeyStore) SetRelayKey(
	name string, k relayleg.PublicKey,
) error {
	return s.s.SetSettings(relayKeySettingsApp, name, k.String())
}

func (s settingsKeyStore) DeleteRelayKey(name string) error {
	return s.s.DeleteSettings(relayKeySettingsApp, name)
}

// ForgetRelayKey deletes the key stored for a. It is not an error
// when that name is absent.
func ForgetRelayKey(s KeyStore, a Address) error {
	return s.DeleteRelayKey(a.StoreName())
}
