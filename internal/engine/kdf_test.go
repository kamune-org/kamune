package engine

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/enigma"
)

// writeStore builds a store the way an older release would have, with its
// secret wrapped under params, and stores one encrypted peer value. For
// legacyKDF it reproduces the pre-Argon2id code path and writes no
// kdf-params entry.
func writeStore(t *testing.T, path string, pass []byte, params kdfParams) {
	t.Helper()
	a := require.New(t)

	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()

	secret := randomBytes(secretSize)
	secretSalt := randomBytes(saltSize)
	data, err := enigma.NewEnigma(secret, secretSalt, []byte(dek))
	a.NoError(err)

	a.NoError(db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			defaultNamespace, settingsNamespace,
			peersNamespace, sessionsNamespace,
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		bucket := tx.Bucket(defaultNamespace)
		a.NoError(bucket.Put([]byte(secretSaltKey), secretSalt))

		if params == legacyKDF {
			deriveSalt := randomBytes(saltSize)
			wrappedSalt := randomBytes(saltSize)
			derived, err := enigma.Derive(pass, deriveSalt, []byte(dpk), 32)
			a.NoError(err)
			keyCipher, err := enigma.NewEnigma(
				derived, wrappedSalt, []byte(kek),
			)
			a.NoError(err)
			a.NoError(bucket.Put(
				[]byte(wrappedKey), keyCipher.Encrypt(secret),
			))
			a.NoError(bucket.Put([]byte(wrappedSaltKey), wrappedSalt))
			a.NoError(bucket.Put([]byte(deriveSaltKey), deriveSalt))
		} else {
			w, err := wrapSecret(secret, pass, params)
			a.NoError(err)
			a.NoError(w.put(bucket))
		}

		return tx.Bucket(peersNamespace).Put(
			[]byte("peer"), data.Encrypt([]byte("peer-data")),
		)
	}))
}

func readMeta(t *testing.T, path string) cipherMeta {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	var meta cipherMeta
	a.NoError(db.View(func(tx *bolt.Tx) error {
		var err error
		meta, err = readCipherMeta(tx.Bucket(defaultNamespace))
		return err
	}))
	return meta
}

func requirePeerData(t *testing.T, db *BoltStore) {
	t.Helper()
	a := require.New(t)
	a.NoError(db.Query(func(b Namespace) error {
		v, err := b.Sub([]byte(PeersNamespace)).GetEncrypted([]byte("peer"))
		a.NoError(err)
		a.Equal([]byte("peer-data"), v)
		return nil
	}))
}

func TestNewBoltDB_WrapsWithArgon2id(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	pass := []byte("correct horse")

	db, err := NewBoltDB(path, pass)
	a.NoError(err)
	a.NoError(db.Close())

	a.Equal(defaultKDF, readMeta(t, path).wrap.kdf)

	_, err = NewBoltDB(path, []byte("wrong"))
	a.Error(err)
	db, err = NewBoltDB(path, pass)
	a.NoError(err)
	a.NoError(db.Close())
}

func TestNewBoltDB_UpgradesWeakWrapping(t *testing.T) {
	cases := []struct {
		name   string
		params kdfParams
		want   kdfParams
	}{
		{"legacy hkdf", legacyKDF, defaultKDF},
		{
			"weak argon2id",
			kdfParams{alg: kdfArgon2id, time: 1, memory: 64, threads: 1},
			defaultKDF,
		},
		{
			// Raising the time must keep the larger memory cost.
			"low time high memory",
			kdfParams{
				alg: kdfArgon2id, time: 1, memory: 128 * 1024, threads: 4,
			},
			kdfParams{
				alg: kdfArgon2id, time: 3, memory: 128 * 1024, threads: 4,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			pass := []byte("old-store-pass")
			writeStore(t, path, pass, tc.params)
			before := readMeta(t, path)
			a.Equal(tc.params, before.wrap.kdf)

			// A wrong passphrase must not touch the wrapping.
			_, err := NewBoltDB(path, []byte("wrong"))
			a.Error(err)
			a.Equal(before, readMeta(t, path))

			db, err := NewBoltDB(path, pass)
			a.NoError(err)
			requirePeerData(t, db)
			a.NoError(db.Close())

			after := readMeta(t, path)
			a.Equal(tc.want, after.wrap.kdf)
			a.Equal(before.secretSalt, after.secretSalt)
			a.NotEqual(before.wrap.deriveSalt, after.wrap.deriveSalt)
			a.NotEqual(before.wrap.wrappedSalt, after.wrap.wrappedSalt)
			a.NotEqual(before.wrap.wrappedKey, after.wrap.wrappedKey)

			// The old cheap derivation no longer verifies a guess.
			stale := after.wrap
			stale.kdf = tc.params
			_, err = stale.unwrap(pass)
			a.Error(err)

			db, err = NewBoltDB(path, pass)
			a.NoError(err)
			requirePeerData(t, db)
			a.NoError(db.Close())
			a.Equal(after, readMeta(t, path), "no second upgrade")
		})
	}
}

func TestParseKDFParams(t *testing.T) {
	valid := defaultKDF.marshal()
	with := func(i int, v byte) []byte {
		b := append([]byte(nil), valid...)
		b[i] = v
		return b
	}
	argon := func(time, memory uint32, threads uint8) []byte {
		return kdfParams{
			alg: kdfArgon2id, time: time, memory: memory, threads: threads,
		}.marshal()
	}
	cases := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"default", valid, true},
		{"max memory", argon(1, maxKDFMemory, 4), true},
		{"max time", argon(maxKDFTime, 64*1024, 4), true},
		{"max work", argon(4, maxKDFMemory, 4), true},
		{"empty", []byte{}, false},
		{"short", valid[:9], false},
		{"long", append(append([]byte(nil), valid...), 0), false},
		{"legacy algorithm id", with(0, byte(kdfLegacyHKDF)), false},
		{"unknown algorithm", with(0, 7), false},
		{"zero time", kdfParams{
			alg: kdfArgon2id, time: 0, memory: 64, threads: 1,
		}.marshal(), false},
		{"huge time", kdfParams{
			alg: kdfArgon2id, time: maxKDFTime + 1, memory: 64, threads: 1,
		}.marshal(), false},
		{"zero threads", with(9, 0), false},
		{"memory below lanes", kdfParams{
			alg: kdfArgon2id, time: 1, memory: 15, threads: 2,
		}.marshal(), false},
		{"huge memory", kdfParams{
			alg: kdfArgon2id, time: 1, memory: maxKDFMemory + 1, threads: 1,
		}.marshal(), false},
		{"4 GiB memory", argon(1, 4<<20, 4), false},
		{"huge work", argon(5, maxKDFMemory, 4), false},
		{"max time and memory", argon(maxKDFTime, maxKDFMemory, 4), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			p, err := parseKDFParams(tc.raw)
			if tc.ok {
				a.NoError(err)
				a.Equal(tc.raw, p.marshal())
				return
			}
			a.ErrorIs(err, ErrCorruptMetadata)
		})
	}
}

func TestNewBoltDB_CorruptKDFParams(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	pass := []byte("pass")

	db, err := NewBoltDB(path, pass)
	a.NoError(err)
	a.NoError(db.Close())

	raw, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	a.NoError(raw.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(defaultNamespace).Put(
			[]byte(kdfParamsKey), []byte{byte(kdfArgon2id), 0, 0},
		)
	}))
	a.NoError(raw.Close())

	_, err = NewBoltDB(path, pass)
	a.ErrorIs(err, ErrCorruptMetadata)
}

func TestRotatePassphrase_SurvivesRestart(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")

	db, err := NewBoltDB(path, []byte("old"))
	a.NoError(err)
	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("peer"), []byte("peer-data"),
		)
	}))
	a.NoError(db.RotatePassphrase([]byte("old"), []byte("new")))
	a.NoError(db.Close())

	a.Equal(defaultKDF, readMeta(t, path).wrap.kdf)
	_, err = NewBoltDB(path, []byte("old"))
	a.Error(err)
	db, err = NewBoltDB(path, []byte("new"))
	a.NoError(err)
	requirePeerData(t, db)
	a.NoError(db.Close())
}

func TestKDFParams_AtLeast(t *testing.T) {
	argon := func(time, memory uint32, threads uint8) kdfParams {
		return kdfParams{
			alg: kdfArgon2id, time: time, memory: memory, threads: threads,
		}
	}
	cases := []struct {
		name   string
		stored kdfParams
		want   kdfParams
	}{
		{"legacy", legacyKDF, defaultKDF},
		{"default", defaultKDF, defaultKDF},
		{"weaker", argon(1, 64, 1), defaultKDF},
		{"low time high memory", argon(1, 1<<20, 4), argon(3, 1<<20, 4)},
		{"high time low memory", argon(10, 1024, 1), argon(10, 64*1024, 4)},
		{"more threads", argon(3, 64*1024, 8), argon(3, 64*1024, 8)},
		{"stronger", argon(4, 256*1024, 4), argon(4, 256*1024, 4)},
		{"max time", argon(maxKDFTime, 8, 1), argon(maxKDFTime, 64*1024, 4)},
		{"max memory", argon(1, maxKDFMemory, 1), argon(3, maxKDFMemory, 4)},
		{"max work", argon(4, maxKDFMemory, 4), argon(4, maxKDFMemory, 4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got := tc.stored.atLeast(defaultKDF)
			a.Equal(tc.want, got)
			parsed, err := parseKDFParams(got.marshal())
			a.NoError(err, "upgrade target must stay within bounds")
			a.Equal(got, parsed)
		})
	}
}

func TestRotation_KeepsStrongerKDF(t *testing.T) {
	strong := kdfParams{
		alg: kdfArgon2id, time: 4, memory: 64 * 1024, threads: 4,
	}
	cases := []struct {
		name   string
		rotate func(s *BoltStore, old, new []byte) error
	}{
		{"passphrase", (*BoltStore).RotatePassphrase},
		{"data key", (*BoltStore).RotateDataKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			writeStore(t, path, []byte("old"), strong)

			db, err := NewBoltDB(path, []byte("old"))
			a.NoError(err)
			a.Equal(strong, readMetaOf(t, db).wrap.kdf, "no downgrade on open")
			a.NoError(tc.rotate(db, []byte("old"), []byte("new")))
			requirePeerData(t, db)
			a.NoError(db.Close())

			a.Equal(strong, readMeta(t, path).wrap.kdf)
		})
	}
}

// readMetaOf reads the cipher metadata through an open store.
func readMetaOf(t *testing.T, db *BoltStore) cipherMeta {
	t.Helper()
	a := require.New(t)
	var meta cipherMeta
	a.NoError(db.db.View(func(tx *bolt.Tx) error {
		var err error
		meta, err = readCipherMeta(tx.Bucket(defaultNamespace))
		return err
	}))
	return meta
}
