package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/enigma"
)

const (
	wrappedSaltKey = "wrapped-salt"
	wrappedKey     = "wrapped-key"
	deriveSaltKey  = "derive-salt"
	secretSaltKey  = "secret-salt"
)

// BoltStore is the BoltDB implementation of [Store].
type BoltStore struct {
	db     *bolt.DB
	cipher *enigma.Enigma
}

// NewBoltDB creates a new BoltStore at the given path, encrypting values with
// the provided passphrase.
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
		return nil, fmt.Errorf("creating default bucket: %w", err)
	}

	cipher, _, err := extractCipher(db, passphrase)
	if errors.Is(err, ErrMissingItem) {
		// create if missing
		cipher, err = createCipher(db, passphrase)
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("cipher: %w", err)
	}

	return &BoltStore{db: db, cipher: cipher}, nil
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}

func (s *BoltStore) Query(f func(b Namespace) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher))
	})
}

func (s *BoltStore) Command(f func(b Namespace) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return f(newRootNamespace(tx, s.cipher))
	})
}

// cipherMeta holds the raw cipher-wrapping metadata stored in the DB.
type cipherMeta struct {
	secretSalt  []byte
	deriveSalt  []byte
	wrappedSalt []byte
	wrappedKey  []byte
}

func extractCipher(
	db *bolt.DB, pass []byte,
) (*enigma.Enigma, cipherMeta, error) {
	var meta cipherMeta
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(defaultNamespace)
		meta.wrappedKey = bytes.Clone(bucket.Get([]byte(wrappedKey)))
		meta.deriveSalt = bytes.Clone(bucket.Get([]byte(deriveSaltKey)))
		meta.wrappedSalt = bytes.Clone(bucket.Get([]byte(wrappedSaltKey)))
		meta.secretSalt = bytes.Clone(bucket.Get([]byte(secretSaltKey)))
		return nil
	})
	if err != nil {
		return nil, cipherMeta{}, fmt.Errorf("get values: %w", err)
	}
	if meta.secretSalt == nil || meta.deriveSalt == nil ||
		meta.wrappedSalt == nil || meta.wrappedKey == nil {
		return nil, cipherMeta{}, ErrMissingItem
	}
	derivedPass, err := enigma.Derive(
		pass, meta.deriveSalt, []byte(dpk), 32,
	)
	if err != nil {
		return nil, cipherMeta{}, fmt.Errorf("derive from pass: %w", err)
	}
	keyCipher, err := enigma.NewEnigma(
		derivedPass, meta.wrappedSalt, []byte(kek),
	)
	if err != nil {
		return nil, cipherMeta{}, fmt.Errorf("key cipher: %w", err)
	}
	secret, err := keyCipher.Decrypt(meta.wrappedKey)
	if err != nil {
		return nil, cipherMeta{}, fmt.Errorf("decrypt secret: %w", err)
	}
	dataCipher, err := enigma.NewEnigma(
		secret, meta.secretSalt, []byte(dek),
	)
	if err != nil {
		return nil, cipherMeta{}, fmt.Errorf("data cipher: %w", err)
	}
	return dataCipher, meta, nil
}

func createCipher(db *bolt.DB, pass []byte) (*enigma.Enigma, error) {
	var (
		secret      = randomBytes(32)
		secretSalt  = randomBytes(32)
		deriveSalt  = randomBytes(32)
		wrappedSalt = randomBytes(32)
	)

	derivedPass, err := enigma.Derive(pass, deriveSalt, []byte(dpk), 32)
	if err != nil {
		return nil, fmt.Errorf("derive from pass: %w", err)
	}
	keyCipher, err := enigma.NewEnigma(derivedPass, wrappedSalt, []byte(kek))
	if err != nil {
		return nil, fmt.Errorf("key cipher: %w", err)
	}
	wrapped := keyCipher.Encrypt(secret)
	dataCipher, err := enigma.NewEnigma(secret, secretSalt, []byte(dek))
	if err != nil {
		return nil, fmt.Errorf("data cipher: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(defaultNamespace)
		err = bucket.Put([]byte(wrappedKey), wrapped)
		if err != nil {
			return fmt.Errorf("put wrapped key: %w", err)
		}
		err = bucket.Put([]byte(wrappedSaltKey), wrappedSalt)
		if err != nil {
			return fmt.Errorf("put wrapped salt: %w", err)
		}
		err = bucket.Put([]byte(deriveSaltKey), deriveSalt)
		if err != nil {
			return fmt.Errorf("put derive salt: %w", err)
		}
		err = bucket.Put([]byte(secretSaltKey), secretSalt)
		if err != nil {
			return fmt.Errorf("put secret salt: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update db: %w", err)
	}

	return dataCipher, nil
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

// RotatePassphrase re-wraps the data encryption key with a new passphrase. Only
// the key-wrapping metadata changes; encrypted data is untouched.
func (s *BoltStore) RotatePassphrase(old, new []byte) error {
	// Decrypt the DEK secret using the old passphrase.
	_, meta, err := extractCipher(s.db, old)
	if err != nil {
		return fmt.Errorf("extract cipher with old passphrase: %w", err)
	}

	// Decrypt the raw DEK secret.
	oldDerivedPass, err := enigma.Derive(old, meta.deriveSalt, []byte(dpk), 32)
	if err != nil {
		return fmt.Errorf("derive old pass: %w", err)
	}
	oldKeyCipher, err := enigma.NewEnigma(
		oldDerivedPass, meta.wrappedSalt, []byte(kek),
	)
	if err != nil {
		return fmt.Errorf("old key cipher: %w", err)
	}
	secret, err := oldKeyCipher.Decrypt(meta.wrappedKey)
	if err != nil {
		return fmt.Errorf("decrypt secret: %w", err)
	}

	// Re-wrap with new passphrase using fresh salts.
	newDeriveSalt := randomBytes(32)
	newWrappedSalt := randomBytes(32)

	newDerivedPass, err := enigma.Derive(new, newDeriveSalt, []byte(dpk), 32)
	if err != nil {
		return fmt.Errorf("derive new pass: %w", err)
	}
	newKeyCipher, err := enigma.NewEnigma(
		newDerivedPass, newWrappedSalt, []byte(kek),
	)
	if err != nil {
		return fmt.Errorf("new key cipher: %w", err)
	}
	newWrapped := newKeyCipher.Encrypt(secret)

	// Write updated metadata.
	err = s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(defaultNamespace)
		if err := bucket.Put([]byte(wrappedKey), newWrapped); err != nil {
			return fmt.Errorf("put wrapped key: %w", err)
		}
		err := bucket.Put([]byte(wrappedSaltKey), newWrappedSalt)
		if err != nil {
			return fmt.Errorf("put wrapped salt: %w", err)
		}
		if err := bucket.Put([]byte(deriveSaltKey), newDeriveSalt); err != nil {
			return fmt.Errorf("put derive salt: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}

	// Swap the in-memory cipher.
	s.cipher, _, err = extractCipher(s.db, new)
	if err != nil {
		return fmt.Errorf("reload cipher: %w", err)
	}

	return nil
}

// RotateDataKey generates a new data encryption key and re-encrypts all
// encrypted values across every namespace. This is expensive but atomic per
// bolt.Update transaction.
func (s *BoltStore) RotateDataKey(old, new []byte) error {
	// Verify we can decrypt with the old passphrase.
	oldCipher, _, err := extractCipher(s.db, old)
	if err != nil {
		return fmt.Errorf("extract cipher with old passphrase: %w", err)
	}

	// Generate a fresh DEK.
	newSecret := randomBytes(32)
	newSecretSalt := randomBytes(32)
	newCipher, err := enigma.NewEnigma(newSecret, newSecretSalt, []byte(dek))
	if err != nil {
		return fmt.Errorf("new data cipher: %w", err)
	}

	// Wrap the new DEK with the new passphrase.
	newDeriveSalt := randomBytes(32)
	newWrappedSalt := randomBytes(32)
	newDerivedPass, err := enigma.Derive(new, newDeriveSalt, []byte(dpk), 32)
	if err != nil {
		return fmt.Errorf("derive new pass: %w", err)
	}
	newKeyCipher, err := enigma.NewEnigma(
		newDerivedPass, newWrappedSalt, []byte(kek),
	)
	if err != nil {
		return fmt.Errorf("new key cipher: %w", err)
	}
	newWrapped := newKeyCipher.Encrypt(newSecret)

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
		for _, kv := range [][2][]byte{
			{[]byte(secretSaltKey), newSecretSalt},
			{[]byte(wrappedKey), newWrapped},
			{[]byte(wrappedSaltKey), newWrappedSalt},
			{[]byte(deriveSaltKey), newDeriveSalt},
		} {
			if err := bucket.Put(kv[0], kv[1]); err != nil {
				return fmt.Errorf("put %s: %w", kv[0], err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("write phase: %w", err)
	}

	// Swap the in-memory cipher.
	s.cipher = newCipher

	return nil
}
