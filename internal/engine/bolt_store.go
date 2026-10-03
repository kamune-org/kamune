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

// navigateBucket walks a slash-separated path (e.g. "a/b/c") from the tx root,
// returning the deepest bucket or nil if any segment is missing.
func navigateBucket(tx *bolt.Tx, path []byte) *bolt.Bucket {
	parts := bytes.Split(path, []byte("/"))
	bucket := tx.Bucket(parts[0])
	for _, part := range parts[1:] {
		if bucket == nil {
			return nil
		}
		bucket = bucket.Bucket(part)
	}
	return bucket
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

// RotateDataKey generates a new data encryption key and re-encrypts all
// encrypted values across every namespace. This is expensive but atomic per
// bolt.Update transaction.
func (s *BoltStore) RotateDataKey(old, new []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify we can decrypt with the old passphrase.
	var (
		oldCipher *enigma.Enigma
		oldKDF    kdfParams
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		meta, secret, err := unlock(tx, old)
		if err != nil {
			return err
		}
		oldKDF = meta.wrap.kdf
		oldCipher, err = newDataCipher(secret, meta.secretSalt)
		return err
	})
	if err != nil {
		return fmt.Errorf("unlock with old passphrase: %w", err)
	}

	// Generate a fresh DEK and wrap it with the new passphrase.
	newSecret := randomBytes(secretSize)
	newSecretSalt := randomBytes(saltSize)
	newCipher, err := newDataCipher(newSecret, newSecretSalt)
	if err != nil {
		return err
	}
	newWrap, err := wrapSecret(newSecret, new, oldKDF.atLeast(defaultKDF))
	if err != nil {
		return fmt.Errorf("wrap with new passphrase: %w", err)
	}

	// Collect every (bucket-path, key, ciphertext) triple first, outside the
	// write transaction, to avoid holding a write lock while iterating.
	type entry struct {
		path  []byte
		key   []byte
		value []byte
	}
	var entries []entry

	var collect func(bucket *bolt.Bucket, path []byte) error
	collect = func(bucket *bolt.Bucket, path []byte) error {
		return bucket.ForEach(func(k, v []byte) error {
			sub := bucket.Bucket(k)
			if sub != nil {
				// Descend into nested sub-bucket.
				child := make([]byte, len(path)+len(k)+1)
				copy(child, path)
				child[len(path)] = '/'
				copy(child[len(path)+1:], k)
				return collect(sub, child)
			}
			entries = append(entries, entry{
				path:  bytes.Clone(path),
				key:   bytes.Clone(k),
				value: bytes.Clone(v),
			})
			return nil
		})
	}

	err = s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
			return collect(bucket, bytes.Clone(name))
		})
	})
	if err != nil {
		return fmt.Errorf("read phase: %w", err)
	}

	// Decrypt with old cipher, re-encrypt with new cipher, and store updated
	// cipher metadata — all in one write transaction.
	err = s.db.Update(func(tx *bolt.Tx) error {
		for _, e := range entries {
			plaintext, err := oldCipher.Decrypt(e.value)
			if err != nil {
				// Cipher metadata keys are stored as raw
				// bytes — skip values that fail to decrypt.
				continue
			}
			reencrypted := newCipher.Encrypt(plaintext)

			bucket := tx.Bucket(e.path)
			if bucket == nil {
				bucket = navigateBucket(tx, e.path)
			}
			if bucket == nil {
				continue
			}
			if err := bucket.Put(e.key, reencrypted); err != nil {
				return fmt.Errorf("put %s/%s: %w", e.path, e.key, err)
			}
		}

		// Store all cipher metadata so future reads reconstruct the correct
		// cipher on restart.
		bucket := tx.Bucket(defaultNamespace)
		err := bucket.Put([]byte(secretSaltKey), newSecretSalt)
		if err != nil {
			return fmt.Errorf("put %s: %w", secretSaltKey, err)
		}
		return newWrap.put(bucket)
	})
	if err != nil {
		return fmt.Errorf("write phase: %w", err)
	}

	// Swap the in-memory cipher.
	s.cipher = newCipher

	return nil
}
