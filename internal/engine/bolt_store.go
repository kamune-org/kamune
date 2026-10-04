package engine

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/enigma"
)

const (
	wrappedSaltKey = "wrapped-salt"
	wrappedKey     = "wrapped-key"
	deriveSaltKey  = "derive-salt"
	secretSaltKey  = "secret-salt"
	kdfParamsKey   = "kdf-params"
)

// BoltStore is the BoltDB implementation of [Store].
type BoltStore struct {
	db     *bolt.DB
	cipher *enigma.Enigma
	opts   *bolt.Options
	lock   *fileLock
	path   string
	mu     sync.RWMutex
	// bound reports a store whose values are all bound to their location
	// (see [valueAD]). Only an unbound store opens values written without
	// associated data.
	bound bool
}

// NewBoltDB creates a new BoltStore at the given path, encrypting values with
// the provided passphrase. The passphrase is stretched with Argon2id. A store
// whose key is wrapped with the legacy HKDF derivation, or with weaker
// Argon2id parameters, is re-wrapped on its first successful open, and its
// file is rewritten so the old wrapped key does not remain in a free page.
// A store whose values are not all bound to their location gets a new data
// key on that open, with every value re-sealed under it with its location
// (see [valueAD]).
//
// Symbolic links in path are resolved first. Until it is closed, the store
// holds an exclusive lock on a file named after the database with a
// ".lock" suffix next to it (see [fileLock]); another open of the same
// database waits for it, up to the timeout. Copies left behind by an
// interrupted rewrite are removed. If the lock file cannot be opened, the
// store opens without it but never rewrites its file.
func NewBoltDB(
	path string, passphrase []byte, opts ...Option,
) (*BoltStore, error) {
	o := Options{CreateIfMissing: true}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, fmt.Errorf("option: %w", err)
		}
	}

	path, err := resolvePath(path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	_, statErr := os.Stat(path)
	exists := statErr == nil

	if !exists && !o.CreateIfMissing {
		return nil, fmt.Errorf("open db: %w", os.ErrNotExist)
	}

	boltOpts := &bolt.Options{Timeout: 5 * time.Second}
	if o.Timeout > 0 {
		boltOpts.Timeout = o.Timeout
	}
	lock, err := lockStore(path, boltOpts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			lock.release()
		}
	}()

	db, err := bolt.Open(path, 0600, boltOpts)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if mode, changed, err := restrictFileMode(path); err != nil {
		db.Close()
		return nil, fmt.Errorf("open db: %w", err)
	} else if changed {
		slog.Warn(
			"removed group and other access from database file",
			slog.String("path", path),
			slog.String("previous_mode", mode.String()),
		)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			defaultNamespace,
			settingsNamespace,
			peersNamespace,
			sessionsNamespace,
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// Release the handle so its file lock does not outlive the failed
		// open and block every retry in this process.
		db.Close()
		return nil, fmt.Errorf("creating default bucket: %w", err)
	}

	s := &BoltStore{db: db, opts: boltOpts, lock: lock, path: path}
	if err := s.open(passphrase); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("cipher: %w", err)
	}

	opened = true
	return s, nil
}

// Close closes the database and then releases the store's lock file.
func (s *BoltStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Close()
	lockErr := s.lock.release()
	s.lock = nil
	return errors.Join(err, lockErr)
}

func (s *BoltStore) Query(f func(b Namespace) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.View(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher, !s.bound))
	})
}

func (s *BoltStore) Command(f func(b Namespace) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher, !s.bound))
	})
}

const (
	secretSize = 32
	saltSize   = 32
)

// errNoCipherMeta reports that none of the key-wrapping metadata exists.
var errNoCipherMeta = errors.New("no cipher metadata")

// wrappedSecret is the data encryption secret wrapped under a key derived
// from the passphrase, with the salts and parameters of that derivation.
type wrappedSecret struct {
	deriveSalt  []byte
	wrappedSalt []byte
	wrappedKey  []byte
	kdf         kdfParams
}

// cipherMeta holds the raw cipher-wrapping metadata stored in the DB.
type cipherMeta struct {
	secretSalt []byte
	wrap       wrappedSecret
}

// readCipherMeta loads the metadata from the default bucket. It returns
// errNoCipherMeta when none is stored and [ErrCorruptMetadata] when it is
// incomplete or malformed. A store without kdf-params uses [legacyKDF].
func readCipherMeta(bucket *bolt.Bucket) (cipherMeta, error) {
	get := func(key string) []byte {
		return bytes.Clone(bucket.Get([]byte(key)))
	}
	m := cipherMeta{
		secretSalt: get(secretSaltKey),
		wrap: wrappedSecret{
			deriveSalt:  get(deriveSaltKey),
			wrappedSalt: get(wrappedSaltKey),
			wrappedKey:  get(wrappedKey),
		},
	}
	rawKDF := get(kdfParamsKey)

	var present int
	for _, v := range [][]byte{
		m.secretSalt, m.wrap.deriveSalt, m.wrap.wrappedSalt, m.wrap.wrappedKey,
	} {
		if v != nil {
			present++
		}
	}
	switch {
	case present == 0 && rawKDF == nil:
		return cipherMeta{}, errNoCipherMeta
	case present != 4:
		return cipherMeta{}, fmt.Errorf(
			"%w: %d of 4 entries", ErrCorruptMetadata, present,
		)
	case rawKDF == nil:
		m.wrap.kdf = legacyKDF
		return m, nil
	}

	kdf, err := parseKDFParams(rawKDF)
	if err != nil {
		return cipherMeta{}, err
	}
	m.wrap.kdf = kdf
	return m, nil
}

// wrapSecret wraps secret under a key derived from pass with params, using
// fresh salts.
func wrapSecret(
	secret, pass []byte, params kdfParams,
) (wrappedSecret, error) {
	w := wrappedSecret{
		deriveSalt:  randomBytes(saltSize),
		wrappedSalt: randomBytes(saltSize),
		kdf:         params,
	}
	keyCipher, err := w.keyCipher(pass)
	if err != nil {
		return wrappedSecret{}, err
	}
	w.wrappedKey = keyCipher.Encrypt(secret)
	return w, nil
}

func (w wrappedSecret) keyCipher(pass []byte) (*enigma.Enigma, error) {
	derived, err := w.kdf.derive(pass, w.deriveSalt)
	if err != nil {
		return nil, fmt.Errorf("derive from pass: %w", err)
	}
	c, err := enigma.NewEnigma(derived, w.wrappedSalt, []byte(kek))
	if err != nil {
		return nil, fmt.Errorf("key cipher: %w", err)
	}
	return c, nil
}

// unwrap returns the data encryption secret, or [ErrWrongPassphrase].
func (w wrappedSecret) unwrap(pass []byte) ([]byte, error) {
	keyCipher, err := w.keyCipher(pass)
	if err != nil {
		return nil, err
	}
	secret, err := keyCipher.Decrypt(w.wrappedKey)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: decrypt secret: %w", ErrWrongPassphrase, err,
		)
	}
	return secret, nil
}

// put stores the wrapping, replacing any previous one.
func (w wrappedSecret) put(bucket *bolt.Bucket) error {
	for _, kv := range []struct {
		key   string
		value []byte
	}{
		{wrappedKey, w.wrappedKey},
		{wrappedSaltKey, w.wrappedSalt},
		{deriveSaltKey, w.deriveSalt},
		{kdfParamsKey, w.kdf.marshal()},
	} {
		if err := bucket.Put([]byte(kv.key), kv.value); err != nil {
			return fmt.Errorf("put %s: %w", kv.key, err)
		}
	}
	return nil
}

func newDataCipher(secret, secretSalt []byte) (*enigma.Enigma, error) {
	c, err := enigma.NewEnigma(secret, secretSalt, []byte(dek))
	if err != nil {
		return nil, fmt.Errorf("data cipher: %w", err)
	}
	return c, nil
}

// unlock reads the metadata in tx and unwraps the data secret with pass.
func unlock(tx *bolt.Tx, pass []byte) (cipherMeta, []byte, error) {
	meta, err := readCipherMeta(tx.Bucket(defaultNamespace))
	if err != nil {
		return cipherMeta{}, nil, err
	}
	secret, err := meta.wrap.unwrap(pass)
	if err != nil {
		return cipherMeta{}, nil, err
	}
	return meta, secret, nil
}

// errStopIteration ends a bolt ForEach early.
var errStopIteration = errors.New("stop iteration")

// hasData reports whether any top-level bucket holds a key or a nested
// bucket. The [bindingKey] marker does not count as data.
func hasData(tx *bolt.Tx) (bool, error) {
	err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if bytes.Equal(name, defaultNamespace) &&
				string(k) == bindingKey {
				continue
			}
			return errStopIteration
		}
		return nil
	})
	switch {
	case errors.Is(err, errStopIteration):
		return true, nil
	case err != nil:
		return false, err
	default:
		return false, nil
	}
}

// open unlocks the data cipher with pass, or creates the key hierarchy of a
// new store, and then brings an existing store up to date with
// [BoltStore.upgrade].
func (s *BoltStore) open(pass []byte) error {
	var (
		meta   cipherMeta
		secret []byte
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		meta, secret, err = unlock(tx, pass)
		if err != nil {
			return err
		}
		s.cipher, err = newDataCipher(secret, meta.secretSalt)
		if err != nil {
			return err
		}
		s.bound = isBound(tx, s.cipher)
		return nil
	})
	if errors.Is(err, errNoCipherMeta) {
		return s.db.Update(func(tx *bolt.Tx) error {
			var err error
			s.cipher, err = createCipher(tx, pass)
			s.bound = err == nil
			return err
		})
	}
	if err != nil {
		return err
	}

	rewrap := meta.wrap.kdf.atLeast(defaultKDF) != meta.wrap.kdf
	if !rewrap && s.bound {
		return nil
	}
	bind := !s.bound
	err = s.upgrade(meta, secret, pass, bind)
	switch {
	case err == nil:
		if rewrap {
			slog.Info(
				"upgraded database key wrapping",
				slog.String("kdf", "argon2id"),
			)
		}
		if bind {
			slog.Info(
				"bound database values to their location " +
					"under a new data key",
			)
		}
	case errors.Is(err, ErrReopen):
		return fmt.Errorf("upgrade store: %w", err)
	default:
		slog.Warn("could not upgrade database", slog.Any("error", err))
	}
	return nil
}

// upgrade rewrites the store file, through [BoltStore.rewrite], with the
// changes an older store needs. open asks for an upgrade when the stored
// wrapping is legacy HKDF, or its Argon2id time or memory is below
// [defaultKDF], and when the store is not bound. Either way the data key
// ends up wrapped with fresh salts under the parameters [kdfParams.atLeast]
// gives for [defaultKDF].
//
// Without bind, the secret is wrapped again. With bind, the store is bound:
// the data key is replaced, as [BoltStore.RotateDataKey] does, every value
// that opens under the old key, with its location or without associated
// data, is sealed under the new key with its location (see [valueAD]), and
// [bindingKey] is recorded. Rewriting the file leaves no copy of the old
// wrapping or of the unbound values in it.
//
// If the upgrade fails before the file is replaced, the store stays usable
// as it was, and the upgrade is tried again on the next open. s.cipher
// must be set.
func (s *BoltStore) upgrade(
	meta cipherMeta, secret, pass []byte, bind bool,
) error {
	params := meta.wrap.kdf.atLeast(defaultKDF)
	if !bind {
		w, err := wrapSecret(secret, pass, params)
		if err != nil {
			return err
		}
		_, err = s.rewrite(rewriteOp{update: func(tx *bolt.Tx) error {
			return w.put(tx.Bucket(defaultNamespace))
		}})
		return err
	}

	key, err := newDataKey(pass, params)
	if err != nil {
		return err
	}
	old := s.cipher
	replaced, err := s.rewrite(rewriteOp{
		update: func(tx *bolt.Tx) error {
			return key.put(tx.Bucket(defaultNamespace))
		},
		mapValue: func(path [][]byte, k, v []byte) []byte {
			return rebindValue(old, key.cipher, path, k, v, true)
		},
	})
	if replaced {
		s.cipher = key.cipher
		s.bound = true
	}
	return err
}

// errNoLock reports a rewrite of a store that was opened without its lock
// file. Without the lock, another open could get the replaced file.
var errNoLock = errors.New("store lock file is not held")

// rewrite applies op with [rewriteFile] and switches to the reopened handle.
// It reports whether the file was replaced, which is when op's changes
// became durable. The caller must hold s.mu for writing or own s alone.
func (s *BoltStore) rewrite(op rewriteOp) (bool, error) {
	if s.lock == nil {
		return false, fmt.Errorf("rewrite store file: %w", errNoLock)
	}
	db, replaced, err := rewriteFile(s.db, s.path, s.opts, op)
	if db != nil {
		s.db = db
	}
	return replaced, err
}

// createCipher writes a new key hierarchy wrapped under [defaultKDF], for a
// bound store. Only a store without any data may get one. Anything else
// means the metadata was removed, and writing a new wrapped key would
// accept any passphrase and orphan the data.
func createCipher(tx *bolt.Tx, pass []byte) (*enigma.Enigma, error) {
	populated, err := hasData(tx)
	if err != nil {
		return nil, fmt.Errorf("check store contents: %w", err)
	}
	if populated {
		return nil, fmt.Errorf(
			"%w: store holds data but no key metadata", ErrCorruptMetadata,
		)
	}

	key, err := newDataKey(pass, defaultKDF)
	if err != nil {
		return nil, err
	}
	if err := key.put(tx.Bucket(defaultNamespace)); err != nil {
		return nil, err
	}
	return key.cipher, nil
}

// dataKey is a new data encryption key, with its cipher and its wrapping.
type dataKey struct {
	cipher *enigma.Enigma
	salt   []byte
	wrap   wrappedSecret
}

// newDataKey generates a data encryption key and wraps it under pass with
// params.
func newDataKey(pass []byte, params kdfParams) (dataKey, error) {
	secret := randomBytes(secretSize)
	salt := randomBytes(saltSize)
	c, err := newDataCipher(secret, salt)
	if err != nil {
		return dataKey{}, err
	}
	w, err := wrapSecret(secret, pass, params)
	if err != nil {
		return dataKey{}, fmt.Errorf("wrap data key: %w", err)
	}
	return dataKey{cipher: c, salt: salt, wrap: w}, nil
}

// put stores k in bucket, the default bucket, as the data key of a bound
// store, replacing any previous key and its wrapping.
func (k dataKey) put(bucket *bolt.Bucket) error {
	if err := bucket.Put([]byte(secretSaltKey), k.salt); err != nil {
		return fmt.Errorf("put %s: %w", secretSaltKey, err)
	}
	if err := putBinding(bucket, k.cipher); err != nil {
		return err
	}
	return k.wrap.put(bucket)
}

// RotatePassphrase re-wraps the data encryption key under a new passphrase,
// with key derivation parameters no weaker than the stored ones or
// [defaultKDF] (see [kdfParams.atLeast]). Encrypted data is untouched,
// so anyone who learned the key under the old passphrase can still use it;
// use [BoltStore.RotateDataKey] when the old passphrase may be known.
//
// The database file is rewritten without the old wrapped key and atomically
// replaced. On error the store is unchanged, unless the error wraps
// [ErrReopen]: then the new passphrase is in effect and the store must be
// opened again.
func (s *BoltStore) RotatePassphrase(old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.rewrite(rewriteOp{update: func(tx *bolt.Tx) error {
		meta, secret, err := unlock(tx, old)
		if err != nil {
			return fmt.Errorf("unlock with old passphrase: %w", err)
		}
		w, err := wrapSecret(
			secret, new, meta.wrap.kdf.atLeast(defaultKDF),
		)
		if err != nil {
			return fmt.Errorf("wrap with new passphrase: %w", err)
		}
		return w.put(tx.Bucket(defaultNamespace))
	}})
	if err != nil {
		return fmt.Errorf("rotate passphrase: %w", err)
	}
	return nil
}

// RotateDataKey generates a new data encryption key, re-encrypts every
// encrypted value in every namespace with it, and wraps it under the new
// passphrase with the parameters [BoltStore.RotatePassphrase] uses. Values
// are re-encrypted bound to their location (see [valueAD]), and the store
// is bound afterwards. Values written without associated data are
// re-encrypted only in a store that was not bound yet; in a bound store
// they do not open, and they are copied as they are.
//
// Values are re-encrypted as the database file is rewritten, and the new
// file atomically replaces the old one, so neither the old wrapped key nor
// values under the old key remain in it. Nested buckets are reached by
// handle, so any byte may appear in a bucket name. On error the store is
// unchanged, unless the error wraps [ErrReopen]: then the rotation is in
// effect and the store must be opened again with the new passphrase.
func (s *BoltStore) RotateDataKey(old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var oldCipher, newCipher *enigma.Enigma
	update := func(tx *bolt.Tx) error {
		meta, secret, err := unlock(tx, old)
		if err != nil {
			return fmt.Errorf("unlock with old passphrase: %w", err)
		}
		oldCipher, err = newDataCipher(secret, meta.secretSalt)
		if err != nil {
			return err
		}

		key, err := newDataKey(new, meta.wrap.kdf.atLeast(defaultKDF))
		if err != nil {
			return fmt.Errorf("new data key: %w", err)
		}
		newCipher = key.cipher
		// Store all cipher metadata so future reads reconstruct the correct
		// cipher on restart.
		return key.put(tx.Bucket(defaultNamespace))
	}
	// Values that do not decrypt under the old key, such as the raw cipher
	// metadata, are copied as they are.
	legacy := !s.bound
	reencrypt := func(path [][]byte, k, v []byte) []byte {
		return rebindValue(oldCipher, newCipher, path, k, v, legacy)
	}

	replaced, err := s.rewrite(rewriteOp{update: update, mapValue: reencrypt})
	if replaced {
		s.cipher = newCipher
		s.bound = true
	}
	if err != nil {
		return fmt.Errorf("rotate data key: %w", err)
	}
	return nil
}
