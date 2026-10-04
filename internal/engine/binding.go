package engine

import (
	"encoding/binary"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/enigma"
)

// Every encrypted value is sealed with associated data that names where it
// is stored: the path of buckets that hold it and its key. A value copied to
// another key or bucket, by anyone who can write the file but does not hold
// the data key, then fails to open instead of being read as if it had been
// written there. This does not stop an old value from being put back at the
// key it came from.
//
// Values written before this binding existed carry no associated data, and
// would open wherever they were put. A store is bound once all its values
// are sealed with their location, which [bindingKey] records. A bound store
// opens a value only with its location. Only a store that has not been
// bound yet, because it was opened without its lock file or its upgrade
// failed, also opens values without associated data.
//
// The first open of an unbound store with its lock file binds it (see
// [BoltStore.upgrade]): it replaces the data key with a new one and
// re-seals every value under it with its location. No value without
// associated data is ever sealed under the new key, so one taken from an
// older copy of the file opens nowhere in the bound store, even when the
// marker is removed: the open that follows only replaces the data key
// again. Restoring the key-wrapping metadata of an older, unbound copy, with
// the same passphrase, makes the store unbound again with that copy's key,
// and so amounts to going back to that copy; the values written since then
// no longer open.

const (
	// valueADVersion is the first byte of the associated data, so that the
	// encoding can change.
	valueADVersion = 1
	// bindingKey, in the default bucket, marks a bound store. Its value is
	// the [valueADVersion] in use, sealed under the data key with
	// [bindingAD]. A missing marker, or one that does not open, makes the
	// next open with the lock file bind the store again under a new data
	// key, which leaves its bound values readable.
	bindingKey = "value-binding"
)

// bindingAD is the associated data of the [bindingKey] marker. It does not
// start with [valueADVersion], so it differs from the associated data of
// every value and the marker does not open as a value of the default
// namespace.
var bindingAD = []byte("kamune value binding")

// valueAD returns the associated data for the value of key in the bucket at
// path: the version byte, the number of buckets, each bucket name and then
// the key, every name and the key prefixed by its length as a big-endian
// uint32.
func valueAD(path [][]byte, key []byte) []byte {
	n := 1 + 4 + 4 + len(key)
	for _, name := range path {
		n += 4 + len(name)
	}
	ad := make([]byte, 0, n)
	ad = append(ad, valueADVersion)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(path)))
	for _, name := range path {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(name)))
		ad = append(ad, name...)
	}
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(key)))
	return append(ad, key...)
}

// sealValue encrypts value for key in the bucket at path.
func sealValue(c *enigma.Enigma, path [][]byte, key, value []byte) []byte {
	return c.EncryptWithAD(value, valueAD(path, key))
}

// openValue decrypts a value stored at key in the bucket at path. A value
// sealed for another location does not open. With legacy, a value written
// without associated data opens too; only an unbound store may allow it.
func openValue(
	c *enigma.Enigma, path [][]byte, key, sealed []byte, legacy bool,
) ([]byte, error) {
	plaintext, err := c.DecryptWithAD(sealed, valueAD(path, key))
	if err == nil || !legacy {
		return plaintext, err
	}
	if plaintext, legacyErr := c.Decrypt(sealed); legacyErr == nil {
		return plaintext, nil
	}
	return nil, err
}

// rebindValue returns the value of key in the bucket at path, opened under
// from as [openValue] does with legacy, sealed under to with its location.
// A value that does not open, such as the key-wrapping metadata, is
// returned unchanged.
func rebindValue(
	from, to *enigma.Enigma, path [][]byte, key, value []byte, legacy bool,
) []byte {
	plaintext, err := openValue(from, path, key, value, legacy)
	if err != nil {
		return value
	}
	return sealValue(to, path, key, plaintext)
}

// isBound reports whether the store in tx, whose data key c is, is bound.
func isBound(tx *bolt.Tx, c *enigma.Enigma) bool {
	sealed := tx.Bucket(defaultNamespace).Get([]byte(bindingKey))
	if sealed == nil {
		return false
	}
	v, err := c.DecryptWithAD(sealed, bindingAD)
	return err == nil && len(v) == 1 && v[0] >= valueADVersion
}

// putBinding records in bucket, the default bucket, that the store whose
// data key c is is bound.
func putBinding(bucket *bolt.Bucket, c *enigma.Enigma) error {
	sealed := c.EncryptWithAD([]byte{valueADVersion}, bindingAD)
	if err := bucket.Put([]byte(bindingKey), sealed); err != nil {
		return fmt.Errorf("put %s: %w", bindingKey, err)
	}
	return nil
}
