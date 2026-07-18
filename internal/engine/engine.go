package engine

import (
	"crypto/rand"
	"errors"
	"fmt"
	"iter"
	"time"
)

const (
	DefaultNamespace  = "kamune-store"
	PeersNamespace    = "peers"
	SettingsNamespace = "settings"
	SessionsNamespace = "sessions"

	kek = "key-encryption-key"
	dek = "data-encryption-key"
	dpk = "derived-passphrase-key"
)

var (
	ErrMissingItem      = errors.New("item not found")
	ErrMissingNamespace = errors.New("namespace not found")

	defaultNamespace  = []byte(DefaultNamespace)
	settingsNamespace = []byte(SettingsNamespace)
	peersNamespace    = []byte(PeersNamespace)
	sessionsNamespace = []byte(SessionsNamespace)
)

// Options holds backend-agnostic configuration for opening a store.
type Options struct {
	CreateIfMissing bool
	Timeout         time.Duration
}

// Option configures [Options] during store construction.
type Option func(*Options) error

// WithCreateIfMissing controls whether the backend creates the store when it
// does not exist. The default is true.
func WithCreateIfMissing(v bool) Option {
	return func(o *Options) error {
		o.CreateIfMissing = v
		return nil
	}
}

// WithTimeout sets the maximum time the backend waits for the store to open or
// connect. A zero value keeps the backend default.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) error {
		if d < 0 {
			return fmt.Errorf("timeout must be non-negative, got %s", d)
		}
		o.Timeout = d
		return nil
	}
}

// Store is the interface for pluggable storage backends.
type Store interface {
	Close() error
	Query(fn func(Namespace) error) error
	Command(fn func(Namespace) error) error
	RotatePassphrase(old, new []byte) error
	RotateDataKey(old, new []byte) error
}

// Namespace is the interface for pluggable namespace implementations.
type Namespace interface {
	Sub(name []byte) Namespace
	Ensure(name []byte) Namespace
	GetEncrypted(key []byte) ([]byte, error)
	PutEncrypted(key, value []byte) error
	Delete(key []byte) error
	DeleteNamespace(name []byte) error
	IterateEncrypted() iter.Seq2[[]byte, []byte]
	FirstKey() []byte
	LastKey() []byte
	KeyCount() int
	ListSubNamespaces() []string
}

// nilNamespace is a sentinel that satisfies [Namespace] without holding any
// backend resources. Sub and Ensure always return nilNamespace for missing
// namespaces, making chained calls like b.Sub("a").Sub("b") safe — every method
// returns a zero value or [ErrMissingNamespace].
type nilNamespace struct{}

func (nilNamespace) Sub(name []byte) Namespace               { return nilNamespace{} }
func (nilNamespace) Ensure(name []byte) Namespace            { return nilNamespace{} }
func (nilNamespace) GetEncrypted(key []byte) ([]byte, error) { return nil, ErrMissingNamespace }
func (nilNamespace) PutEncrypted(key, value []byte) error    { return ErrMissingNamespace }
func (nilNamespace) Delete(key []byte) error                 { return ErrMissingNamespace }
func (nilNamespace) DeleteNamespace(name []byte) error       { return ErrMissingNamespace }
func (nilNamespace) FirstKey() []byte                        { return nil }
func (nilNamespace) LastKey() []byte                         { return nil }
func (nilNamespace) KeyCount() int                           { return 0 }
func (nilNamespace) ListSubNamespaces() []string             { return nil }
func (nilNamespace) IterateEncrypted() iter.Seq2[[]byte, []byte] {
	return func(yield func(k, v []byte) bool) {}
}

func randomBytes(n int) []byte {
	src := make([]byte, n)
	_, _ = rand.Read(src)
	return src
}
