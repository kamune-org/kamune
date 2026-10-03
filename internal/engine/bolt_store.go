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
	mu     sync.RWMutex
}

// NewBoltDB creates a new BoltStore at the given path, encrypting values with
// the provided passphrase. The passphrase is stretched with Argon2id. A store
// whose key is wrapped with the legacy HKDF derivation, or with weaker
// Argon2id parameters, is re-wrapped on its first successful open.
func NewBoltDB(
	path string, passphrase []byte, opts ...Option,
) (*BoltStore, error) {
	o := Options{CreateIfMissing: true}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, fmt.Errorf("option: %w", err)
		}
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
	db, err := bolt.Open(path, 0600, boltOpts)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
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

	cipher, err := openCipher(db, passphrase)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("cipher: %w", err)
	}

	return &BoltStore{db: db, cipher: cipher}, nil
}

func (s *BoltStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Close()
}

func (s *BoltStore) Query(f func(b Namespace) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.View(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher))
	})
}

func (s *BoltStore) Command(f func(b Namespace) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher))
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

// unwrap returns the data encryption secret. It fails when pass is wrong.
func (w wrappedSecret) unwrap(pass []byte) ([]byte, error) {
	keyCipher, err := w.keyCipher(pass)
	if err != nil {
		return nil, err
	}
	secret, err := keyCipher.Decrypt(w.wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
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
// bucket.
func hasData(tx *bolt.Tx) (bool, error) {
	err := tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
		if k, _ := b.Cursor().First(); k != nil {
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

// openCipher unlocks the data cipher with pass, or creates the key hierarchy
// of a new store. When the stored wrapping is legacy HKDF, or its Argon2id
// time or memory is below [defaultKDF], the secret is re-wrapped with fresh
// salts under the parameters [kdfParams.atLeast] gives, in the same
// transaction, so a store is upgraded on its first unlock.
func openCipher(db *bolt.DB, pass []byte) (*enigma.Enigma, error) {
	var c *enigma.Enigma
	err := db.Update(func(tx *bolt.Tx) error {
		meta, secret, err := unlock(tx, pass)
		if errors.Is(err, errNoCipherMeta) {
			c, err = createCipher(tx, pass)
			return err
		}
		if err != nil {
			return err
		}

		target := meta.wrap.kdf.atLeast(defaultKDF)
		if target != meta.wrap.kdf {
			w, err := wrapSecret(secret, pass, target)
			if err != nil {
				return fmt.Errorf("upgrade key wrapping: %w", err)
			}
			if err := w.put(tx.Bucket(defaultNamespace)); err != nil {
				return fmt.Errorf("upgrade key wrapping: %w", err)
			}
			slog.Info(
				"upgraded database key wrapping",
				slog.String("kdf", "argon2id"),
			)
		}

		c, err = newDataCipher(secret, meta.secretSalt)
		return err
	})
	return c, err
}

// createCipher writes a new key hierarchy wrapped under [defaultKDF]. Only a
// store without any data may get one. Anything else means the metadata was
// removed, and writing a new wrapped key would accept any passphrase and
// orphan the data.
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

	secret := randomBytes(secretSize)
	secretSalt := randomBytes(saltSize)
	w, err := wrapSecret(secret, pass, defaultKDF)
	if err != nil {
		return nil, err
	}
	bucket := tx.Bucket(defaultNamespace)
	if err := w.put(bucket); err != nil {
		return nil, err
	}
	if err := bucket.Put([]byte(secretSaltKey), secretSalt); err != nil {
		return nil, fmt.Errorf("put secret salt: %w", err)
	}
	return newDataCipher(secret, secretSalt)
}

// RotatePassphrase re-wraps the data encryption key under a new passphrase,
// with key derivation parameters no weaker than the stored ones or
// [defaultKDF] (see [kdfParams.atLeast]). Only the key-wrapping metadata
// changes; encrypted data is untouched.
func (s *BoltStore) RotatePassphrase(old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Update(func(tx *bolt.Tx) error {
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
	})
	if err != nil {
		return fmt.Errorf("rotate passphrase: %w", err)
	}
	return nil
}

// RotateDataKey generates a new data encryption key, re-encrypts every
// encrypted value in every namespace with it, and wraps it under the new
// passphrase with the parameters [BoltStore.RotatePassphrase] uses. All of
// it happens in one write transaction, so it either completes or leaves the
// store unchanged.
func (s *BoltStore) RotateDataKey(old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newCipher *enigma.Enigma
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta, secret, err := unlock(tx, old)
		if err != nil {
			return fmt.Errorf("unlock with old passphrase: %w", err)
		}
		oldCipher, err := newDataCipher(secret, meta.secretSalt)
		if err != nil {
			return err
		}

		newSecret := randomBytes(secretSize)
		newSecretSalt := randomBytes(saltSize)
		newCipher, err = newDataCipher(newSecret, newSecretSalt)
		if err != nil {
			return err
		}
		newWrap, err := wrapSecret(
			newSecret, new, meta.wrap.kdf.atLeast(defaultKDF),
		)
		if err != nil {
			return fmt.Errorf("wrap with new passphrase: %w", err)
		}

		var roots [][]byte
		err = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			roots = append(roots, bytes.Clone(name))
			return nil
		})
		if err != nil {
			return err
		}
		for _, name := range roots {
			err := reencrypt(tx.Bucket(name), oldCipher, newCipher)
			if err != nil {
				return fmt.Errorf("namespace %q: %w", name, err)
			}
		}

		// Store all cipher metadata so future reads reconstruct the correct
		// cipher on restart.
		bucket := tx.Bucket(defaultNamespace)
		err = bucket.Put([]byte(secretSaltKey), newSecretSalt)
		if err != nil {
			return fmt.Errorf("put %s: %w", secretSaltKey, err)
		}
		return newWrap.put(bucket)
	})
	if err != nil {
		return fmt.Errorf("rotate data key: %w", err)
	}

	// Swap the in-memory cipher.
	s.cipher = newCipher

	return nil
}

// reencrypt replaces every value in bucket and its nested buckets that
// decrypts with oldCipher by its encryption under newCipher. Values that do
// not decrypt, such as the raw cipher metadata, are left as they are.
// Nested buckets are reached by handle, never by a joined path, so any byte
// may appear in a bucket name.
func reencrypt(bucket *bolt.Bucket, oldCipher, newCipher *enigma.Enigma) error {
	type update struct {
		key   []byte
		value []byte
	}
	var (
		updates []update
		nested  [][]byte
	)
	err := bucket.ForEach(func(k, v []byte) error {
		if bucket.Bucket(k) != nil {
			nested = append(nested, bytes.Clone(k))
			return nil
		}
		plaintext, err := oldCipher.Decrypt(v)
		if err != nil {
			return nil
		}
		updates = append(updates, update{
			key:   bytes.Clone(k),
			value: newCipher.Encrypt(plaintext),
		})
		return nil
	})
	if err != nil {
		return err
	}

	for _, u := range updates {
		if err := bucket.Put(u.key, u.value); err != nil {
			return fmt.Errorf("put %q: %w", u.key, err)
		}
	}
	for _, name := range nested {
		child := bucket.Bucket(name)
		if child == nil {
			return fmt.Errorf("%q: %w", name, ErrMissingNamespace)
		}
		if err := reencrypt(child, oldCipher, newCipher); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
	}
	return nil
}
