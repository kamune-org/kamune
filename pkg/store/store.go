package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/hossein1376/kamune/internal/enigma"
)

const (
	peersBucket    = "peers"
	identityBucket = "identity"
	authBucket     = "auth"

	kek = "key-encryption-key"
	dek = "data-encryption-key"
	dpk = "derived-passphrase-key"

	wrappedSaltKey = "wrapped-salt"
	wrappedKey     = "wrapped-key"
	deriveSaltKey  = "derive-salt"
	secretSaltKey  = "secret-salt"
)

var (
	ErrMissingBucket    = errors.New("bucket not found")
	ErrNotFound         = errors.New("item not found")
	ErrFailedDecryption = errors.New("decryption failed")
)

type Store struct {
	db     *bolt.DB
	cipher *enigma.Enigma
}

func open(pass []byte, db *bolt.DB) (*enigma.Enigma, error) {
	var secretSalt, deriveSalt, wrappedSalt, wrapped []byte
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
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
		return nil, ErrNotFound
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

func create(pass []byte, db *bolt.DB) (*enigma.Enigma, error) {
	secret, secretSalt := random32Bits(), random32Bits()
	deriveSalt, wrappedSalt := random32Bits(), random32Bits()

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
		bucket := tx.Bucket([]byte(authBucket))
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

func random32Bits() []byte {
	src := make([]byte, 32)
	rand.Read(src)
	return src
}

func New(passphrase []byte, path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	err = db.Update(
		func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(peersBucket))
			if err != nil {
				return fmt.Errorf("creating peers bucket: %s", err)
			}
			_, err = tx.CreateBucketIfNotExists([]byte(identityBucket))
			if err != nil {
				return fmt.Errorf("creating identity bucket: %s", err)
			}
			_, err = tx.CreateBucketIfNotExists([]byte(authBucket))
			if err != nil {
				return fmt.Errorf("creating auth bucket: %s", err)
			}
			return nil
		},
	)

	cipher, err := open(passphrase, db)
	if errors.Is(err, ErrNotFound) {
		cipher, err = create(passphrase, db)
	}
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	return &Store{db: db, cipher: cipher}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) AddPeer(peer []byte, expiryDate time.Time) error {
	e, err := expiryDate.UTC().MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshaling expiry date: %s", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(peersBucket))
		if bucket == nil {
			return ErrMissingBucket
		}
		if err := s.put(bucket, peer, e); err != nil {
			return fmt.Errorf("adding peer to bucket: %w", err)
		}
		return nil
	},
	)
}

func (s *Store) RemovePeer(peer []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(peersBucket))
		if bucket == nil {
			return ErrMissingBucket
		}
		s.delete(bucket, peer)
		return nil
	})
}

func (s *Store) PeerExists(peer []byte) bool {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(peersBucket))
		if bucket == nil {
			return ErrMissingBucket
		}
		b, err := s.get(bucket, peer)
		switch {
		case b == nil:
			return nil
		case err != nil:
			return fmt.Errorf("find peer: %w", err)
		}
		expiry := time.Time{}
		if err := expiry.UnmarshalBinary(b); err != nil {
			return fmt.Errorf("unmarshaling expiry date: %w", err)
		}
		if expiry.Before(time.Now().UTC()) {
			s.delete(bucket, peer)
			return nil
		}
		exists = true
		return nil
	})
	return err == nil && exists
}

func (s *Store) AddIdentity(algorithm, id []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(identityBucket))
		if bucket == nil {
			return ErrMissingBucket
		}
		if err := bucket.Put(algorithm, id); err != nil {
			return fmt.Errorf("adding identity to bucket: %w", err)
		}
		return nil
	})
}

func (s *Store) GetIdentity(algorithm []byte) ([]byte, error) {
	var id []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(identityBucket))
		if bucket == nil {
			return ErrMissingBucket
		}
		id = bucket.Get(algorithm)
		if id == nil {
			return ErrNotFound
		}
		return nil
	})
	return id, err
}

func (s *Store) IdentityExists(algorithm []byte) bool {
	_, err := s.GetIdentity(algorithm)
	return err == nil
}

func (s *Store) put(bucket *bolt.Bucket, key, value []byte) error {
	return bucket.Put(s.cipher.Encrypt(key), s.cipher.Encrypt(value))
}

func (s *Store) delete(bucket *bolt.Bucket, key []byte) {
	_ = bucket.Delete(s.cipher.Encrypt(key))
}

func (s *Store) get(bucket *bolt.Bucket, key []byte) ([]byte, error) {
	encryptedValue := bucket.Get(s.cipher.Encrypt(key))
	if encryptedValue == nil {
		return nil, nil
	}
	value, err := s.cipher.Decrypt(encryptedValue)
	if err != nil {
		return nil, ErrFailedDecryption
	}
	return value, nil
}
