package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/enigma"
)

const (
	defaultBucket = "kamune-store"

	kek = "key-encryption-key"
	dek = "data-encryption-key"
	dpk = "derived-passphrase-key"

	wrappedSaltKey = "wrapped-salt"
	wrappedKey     = "wrapped-key"
	deriveSaltKey  = "derive-salt"
	secretSaltKey  = "secret-salt"
)

var (
	ErrMissing = errors.New("item not found")

	bucketName = []byte(defaultBucket)
)

type Store struct {
	db     *bolt.DB
	cipher *enigma.Enigma
}

func New(passphrase []byte, path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("creating bucket: %w", err)
	}

	cipher, err := extractCipher(db, passphrase)
	if errors.Is(err, ErrMissing) {
		cipher, err = createCipher(db, passphrase)
	}
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	return &Store{db: db, cipher: cipher}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Remove(key []byte) {
	_ = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func extractCipher(db *bolt.DB, pass []byte) (*enigma.Enigma, error) {
	var secretSalt, deriveSalt, wrappedSalt, wrapped []byte
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		wrapped = bucket.Get([]byte(wrappedKey))
		deriveSalt = bucket.Get([]byte(deriveSaltKey))
		wrappedSalt = bucket.Get([]byte(wrappedSaltKey))
		secretSalt = bucket.Get([]byte(secretSaltKey))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get values: %w", err)
	}
	if secretSalt == nil || deriveSalt == nil || wrappedSalt == nil || wrapped == nil {
		return nil, ErrMissing
	}
	derivedPass, err := enigma.Derive(pass, deriveSalt, []byte(dpk), 32)
	if err != nil {
		return nil, fmt.Errorf("derive from pass: %w", err)
	}
	keyCipher, err := enigma.NewEnigma(derivedPass, wrappedSalt, []byte(kek))
	if err != nil {
		return nil, fmt.Errorf("key cipher: %w", err)
	}
	secret, err := keyCipher.Decrypt(wrapped)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	dataCipher, err := enigma.NewEnigma(secret, secretSalt, []byte(dek))
	if err != nil {
		return nil, fmt.Errorf("data cipher: %w", err)
	}
	return dataCipher, nil
}

func createCipher(db *bolt.DB, pass []byte) (*enigma.Enigma, error) {
	var (
		secret      = randomBits(32)
		secretSalt  = randomBits(32)
		deriveSalt  = randomBits(32)
		wrappedSalt = randomBits(32)
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
		bucket := tx.Bucket(bucketName)
		err := bucket.Put([]byte(wrappedKey), wrapped)
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

func randomBits(bits int) []byte {
	src := make([]byte, bits)
	_, _ = rand.Read(src)
	return src
}

type Query struct {
	tx    *bolt.Tx
	store *Store
}

func (s *Store) Query(f func(q Query) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return f(Query{tx: tx, store: s})
	})
}

type Command struct {
	Query
}

func (s *Store) Command(f func(c Command) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return f(Command{Query{tx: tx, store: s}})
	})
}
