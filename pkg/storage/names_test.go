package storage

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/engine"
	"github.com/kamune-org/kamune/pkg/attest"
)

// rawBucket calls fn with every key and value of the top-level bucket name
// in the bolt file at path.
func rawBucket(t *testing.T, path, name string, fn func(k, v []byte)) {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	a.NoError(db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(name)).ForEach(func(k, v []byte) error {
			fn(bytes.Clone(k), bytes.Clone(v))
			return nil
		})
	}))
}

// TestNamesAreKeyed stores a peer, a session and settings, and checks that
// the file holds neither the public key's hash, the session ID nor the
// setting names, and that settings of different lengths are stored at the
// same length.
func TestNamesAreKeyed(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
	a.NoError(err)

	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	const sessionID = "ABCDEFGHIJKLMNOPQRSTUVWX"
	a.NoError(s.StorePeer(&Peer{Name: "alice", PublicKey: pub}))
	a.NoError(s.CreateSession(sessionID, pub))
	a.NoError(s.AddChatEntry(sessionID, []byte("hi"), time.Now(), SenderPeer))
	a.NoError(s.SetSettings("bus", "incognito", "true"))
	a.NoError(s.SetSettings("bus", "verification_mode", "false"))

	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Equal([]string{sessionID}, sessions)
	found, err := s.FindSessionByPeer(pub)
	a.NoError(err)
	a.Equal(sessionID, found)
	peer, err := s.GetPeer(sessionID)
	a.NoError(err)
	a.Equal("alice", peer.Name)
	for key, want := range map[string]string{
		"incognito": "true", "verification_mode": "false", "missing": "",
	} {
		got, err := s.GetSettings("bus", key)
		a.NoError(err)
		a.Equal(want, got)
	}
	a.NoError(s.Close())

	raw, err := os.ReadFile(path)
	a.NoError(err)
	sum := sha3.Sum512(pub)
	for name, v := range map[string][]byte{
		"public key hash": sum[:],
		"session ID":      []byte(sessionID),
		"setting name":    []byte("bus:incognito"),
		"setting key":     []byte("verification_mode"),
	} {
		a.False(bytes.Contains(raw, v), "%s in file", name)
	}
	rawBucket(t, path, "peers", func(k, _ []byte) {
		a.Len(k, 32)
	})
	var lengths []int
	rawBucket(t, path, "settings", func(k, v []byte) {
		a.Len(k, 32)
		lengths = append(lengths, len(v))
	})
	a.Len(lengths, 2)
	a.Equal(lengths[0], lengths[1], "setting values differ in length")
}

// writeLegacyLayout stores peers, a session and settings in s as versions
// before keyed names did, and marks the database as written by them. A
// record of victim is also copied under the key of attacker.
func writeLegacyLayout(
	t *testing.T, s *Storage, sessionID string, peers map[string][]byte,
	victim, attacker []byte, tokens [][]byte,
) {
	t.Helper()
	a := require.New(t)
	a.NoError(s.engine.Command(func(b Namespace) error {
		def := b.Sub([]byte(engine.DefaultNamespace))
		for _, k := range []string{formatKey, nameKeyKey} {
			if err := def.Delete([]byte(k)); err != nil {
				return err
			}
		}

		ns := b.Sub([]byte(engine.PeersNamespace))
		for name, pub := range peers {
			data, err := proto.Marshal(&pb.Peer{
				Name:      name,
				PublicKey: pub,
				FirstSeen: timestamppb.Now(),
				LastSeen:  timestamppb.Now(),
			})
			a.NoError(err)
			sum := sha3.Sum512(pub)
			if err := ns.PutEncrypted(sum[:], data); err != nil {
				return err
			}
			if bytes.Equal(pub, victim) {
				sum := sha3.Sum512(attacker)
				if err := ns.PutEncrypted(sum[:], data); err != nil {
					return err
				}
			}
		}

		settings := b.Sub([]byte(engine.SettingsNamespace))
		for k, v := range map[string]string{
			"daemon:incognito": "true", "bus:theme": "dark",
		} {
			if err := settings.PutEncrypted([]byte(k), []byte(v)); err != nil {
				return err
			}
		}

		session := b.Ensure([]byte(engine.SessionsNamespace)).
			Ensure([]byte(sessionID))
		meta := session.Ensure([]byte("meta"))
		for k, v := range map[string][]byte{
			PeerKey:                victim,
			string(sessionMetaKey): []byte("work"),
			ResumptionTokensKey:    serializeList(tokens),
			EstablishedAtKey: binary.BigEndian.AppendUint64(
				nil, uint64(time.Now().UnixNano()),
			),
		} {
			if err := meta.PutEncrypted([]byte(k), v); err != nil {
				return err
			}
		}
		return putLegacyEntries(session.Ensure([]byte("chat")), []ChatEntry{
			{Timestamp: time.Unix(1_790_000_000, 0), Data: []byte("one")},
			{
				Timestamp: time.Unix(1_790_000_001, 0),
				Data:      []byte("two"),
				Sender:    SenderPeer,
			},
		})
	}))
}

// TestOpenStorageKeysLegacyNames opens a database whose peers, sessions
// and settings were stored under their plain names, and checks that they
// are all found under their keyed names afterwards, with the plain names
// gone from the file, and that a copied peer record is dropped.
func TestOpenStorageKeysLegacyNames(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	keys := map[string][]byte{}
	for _, name := range []string{"alice", "bob", "mallory"} {
		att, err := attest.New()
		a.NoError(err)
		keys[name] = att.MarshalPublicKey()
	}
	const sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
	tokens := [][]byte{makeToken(1, 32), makeToken(2, 32)}

	s := open()
	writeLegacyLayout(
		t, s, sessionID,
		map[string][]byte{"alice": keys["alice"], "bob": keys["bob"]},
		keys["alice"], keys["mallory"], tokens,
	)
	a.NoError(s.Close())

	s = open()
	peers, err := s.ListPeers()
	a.NoError(err)
	a.Len(peers, 2)
	for _, name := range []string{"alice", "bob"} {
		p, err := s.FindPeer(keys[name])
		a.NoError(err)
		a.Equal(name, p.Name)
	}
	_, err = s.FindPeer(keys["mallory"])
	a.Error(err)

	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Equal([]string{sessionID}, sessions)
	found, err := s.FindSessionByPeer(keys["alice"])
	a.NoError(err)
	a.Equal(sessionID, found)
	peer, err := s.GetPeer(sessionID)
	a.NoError(err)
	a.Equal("alice", peer.Name)
	name, err := s.GetSessionName(sessionID)
	a.NoError(err)
	a.Equal("work", name)
	tok, err := s.PopList(sessionID, ResumptionTokensKey)
	a.NoError(err)
	a.Equal(tokens[0], tok)
	_, err = s.GetEstablishedAt(sessionID)
	a.NoError(err)
	history, err := s.GetChatHistory(sessionID)
	a.NoError(err)
	a.Len(history, 2)
	a.Equal([]byte("one"), history[0].Data)
	a.Equal([]byte("two"), history[1].Data)
	_, _, count, err := s.SessionTimestamps(sessionID)
	a.NoError(err)
	a.Equal(2, count)

	for k, want := range map[[2]string]string{
		{"daemon", "incognito"}: "true", {"bus", "theme"}: "dark",
	} {
		got, err := s.GetSettings(k[0], k[1])
		a.NoError(err)
		a.Equal(want, got)
	}
	a.NoError(s.Close())

	raw, err := os.ReadFile(path)
	a.NoError(err)
	stale := map[string][]byte{
		"session ID":   []byte(sessionID),
		"setting name": []byte("daemon:incognito"),
	}
	for name, pub := range keys {
		sum := sha3.Sum512(pub)
		stale["hash of "+name] = sum[:]
	}
	for name, v := range stale {
		a.False(bytes.Contains(raw, v), "%s in file", name)
	}
}

// TestOpenStorageKeepsSessionValuesThatDoNotOpen upgrades a database
// whose legacy session holds a chat entry and a meta entry that do not
// open, and checks that both stay where they were, byte for byte, while
// everything that opens moves to the keyed session.
func TestOpenStorageKeepsSessionValuesThatDoNotOpen(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	keys := map[string][]byte{}
	for _, name := range []string{"alice", "mallory"} {
		att, err := attest.New()
		a.NoError(err)
		keys[name] = att.MarshalPublicKey()
	}
	const sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
	s := open()
	writeLegacyLayout(
		t, s, sessionID, map[string][]byte{"alice": keys["alice"]},
		keys["alice"], keys["mallory"], [][]byte{makeToken(1, 32)},
	)
	a.NoError(s.Close())

	junk := map[string][]byte{
		"chat": bytes.Repeat([]byte{0xa5}, 80),
		"meta": bytes.Repeat([]byte{0x5a}, 60),
	}
	junkKeys := map[string][]byte{
		"chat": chatKey(time.Unix(1_790_000_002, 0), SenderPeer, 9),
		"meta": []byte("custom_app_key"),
	}
	session := func(tx *bolt.Tx, sub string) *bolt.Bucket {
		b := tx.Bucket([]byte(engine.SessionsNamespace)).
			Bucket([]byte(sessionID))
		a.NotNil(b, "session under its old name")
		return b.Bucket([]byte(sub))
	}
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	a.NoError(db.Update(func(tx *bolt.Tx) error {
		for sub, v := range junk {
			if err := session(tx, sub).Put(junkKeys[sub], v); err != nil {
				return err
			}
		}
		return nil
	}))
	a.NoError(db.Close())

	s = open()
	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Equal([]string{sessionID}, sessions)
	history, err := s.GetChatHistory(sessionID)
	a.NoError(err)
	a.Len(history, 2)
	name, err := s.GetSessionName(sessionID)
	a.NoError(err)
	a.Equal("work", name)
	a.NoError(s.Close())

	db, err = bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	a.NoError(err)
	defer db.Close()
	a.NoError(db.View(func(tx *bolt.Tx) error {
		for sub, v := range junk {
			left := map[string][]byte{}
			b := session(tx, sub)
			a.NotNil(b, "%s under the old name", sub)
			err := b.ForEach(func(k, v []byte) error {
				left[string(k)] = bytes.Clone(v)
				return nil
			})
			a.NoError(err)
			a.Equal(
				map[string][]byte{string(junkKeys[sub]): v}, left,
				"%s left under the old name", sub,
			)
		}
		return nil
	}))
}

// TestOpenStorageFinishesKeyingNames opens a database in which some
// sessions are under keyed names and one is not, as an interrupted
// upgrade leaves it, and checks that both are found afterwards.
func TestOpenStorageFinishesKeyingNames(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}

	s := open()
	a.NoError(s.AddChatEntry("keyed", []byte("kept"), time.Now(), SenderPeer))
	a.NoError(s.engine.Command(func(b Namespace) error {
		err := b.Sub([]byte(engine.DefaultNamespace)).PutEncrypted(
			[]byte(formatKey), []byte{1},
		)
		if err != nil {
			return err
		}
		chat := b.Sub([]byte(engine.SessionsNamespace)).
			Ensure([]byte("plain")).
			Ensure([]byte("chat"))
		return chat.PutEncrypted(chatIndexKey(0), encodeChatValue(ChatEntry{
			Timestamp: time.Now(),
			Data:      []byte("moved"),
		}))
	}))
	a.NoError(s.Close())

	s = open()
	defer s.Close()
	sessions, err := s.ListSessions()
	a.NoError(err)
	a.ElementsMatch([]string{"keyed", "plain"}, sessions)
	for id, want := range map[string]string{"keyed": "kept", "plain": "moved"} {
		history, err := s.GetChatHistory(id)
		a.NoError(err)
		a.Len(history, 1)
		a.Equal(want, string(history[0].Data))
	}
}

func TestSettingCodec(t *testing.T) {
	cases := []struct {
		value string
		size  int
	}{
		{"", 64},
		{"true", 64},
		{"false", 64},
		{string(bytes.Repeat([]byte("x"), 55)), 64},
		{string(bytes.Repeat([]byte("x"), 56)), 128},
	}
	for _, tc := range cases {
		a := require.New(t)
		enc := encodeSetting([]byte(tc.value))
		a.Len(enc, tc.size, "value %q", tc.value)
		dec, ok := decodeSetting(enc)
		a.True(ok)
		a.Equal(tc.value, string(dec))
	}
	for _, bad := range [][]byte{
		nil,
		[]byte("true"),
		append(bytes.Clone(settingMagic), 0, 0, 0),
		append(bytes.Clone(settingMagic), 0, 0, 0, 2, 'x'),
	} {
		_, ok := decodeSetting(bad)
		require.New(t).False(ok, "%q", bad)
	}
}
