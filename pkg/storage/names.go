package storage

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/engine"
)

// Peers, sessions and settings are stored under keyed names: an HMAC of
// what identifies them, under a random name key that is itself sealed
// under the data key. Without that key, the file shows how many of each
// there are but not which public keys, session IDs or settings they are,
// and a guess cannot be checked against it. The name key is kept when the
// data key is replaced, so someone who learned it, with an old passphrase,
// can still check guesses against later copies of the file. Within a
// session, the names of the meta entries, such as resumption_tokens, and
// the lengths of their values are not hidden.
const (
	// nameKeyKey, in the default namespace, holds the name key.
	nameKeyKey  = "name-key"
	nameKeySize = 32

	// legacyPeerKeySize is the size of the SHA3-512 that older versions
	// stored peers under.
	legacyPeerKeySize = 64

	// sessionIDKey, in a session's meta namespace, holds the ID of the
	// session, which its keyed name does not give back.
	sessionIDKey = "session_id"

	peerLabel    = "kamune/storage/peer/v1"
	sessionLabel = "kamune/storage/session/v1"
	settingLabel = "kamune/storage/setting/v1"
)

// settingMagic starts a stored setting value, which is followed by the
// value length as a big-endian uint32, the value and zero padding up to a
// multiple of settingPadSize.
var settingMagic = []byte("KMNS\x01")

const (
	settingHeaderSize = 5 + 4
	settingPadSize    = 64
)

// keyedName returns the name under which the thing that data identifies,
// of the kind label names, is stored.
func keyedName(key []byte, label string, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil)
}

// peerKey returns the storage key for a peer identified by the given claim
// (typically the marshaled public key).
func (s *Storage) peerKey(claim []byte) []byte {
	return keyedName(s.nameKey, peerLabel, claim)
}

// sessionName returns the name of the namespace of the session id.
func (s *Storage) sessionName(id string) []byte {
	return keyedName(s.nameKey, sessionLabel, []byte(id))
}

// settingName returns the key for the setting fullKey, an app name and a
// key joined by a colon.
func (s *Storage) settingName(fullKey string) []byte {
	return keyedName(s.nameKey, settingLabel, []byte(fullKey))
}

// loadNameKey reads the name key, creating it in a database that has none.
func (s *Storage) loadNameKey() error {
	key := []byte(nameKeyKey)
	var stored []byte
	err := s.engine.Command(func(b engine.Namespace) error {
		ns := b.Ensure([]byte(engine.DefaultNamespace))
		var err error
		stored, err = ns.GetEncrypted(key)
		if !errors.Is(err, engine.ErrMissingItem) {
			return err
		}
		stored = make([]byte, nameKeySize)
		if _, err := rand.Read(stored); err != nil {
			return err
		}
		return ns.PutEncrypted(key, stored)
	})
	if err != nil {
		return fmt.Errorf("load name key: %w", err)
	}
	if len(stored) != nameKeySize {
		return fmt.Errorf("name key is %d bytes", len(stored))
	}
	s.nameKey = stored
	return nil
}

// encodeSetting returns the stored form of a setting value.
func encodeSetting(value []byte) []byte {
	n := settingHeaderSize + len(value)
	v := make([]byte, (n+settingPadSize-1)/settingPadSize*settingPadSize)
	copy(v, settingMagic)
	binary.BigEndian.PutUint32(v[5:], uint32(len(value)))
	copy(v[settingHeaderSize:], value)
	return v
}

// decodeSetting parses a value made by [encodeSetting].
func decodeSetting(v []byte) ([]byte, bool) {
	if len(v) < settingHeaderSize || !bytes.HasPrefix(v, settingMagic) {
		return nil, false
	}
	n := binary.BigEndian.Uint32(v[5:])
	if uint64(n) > uint64(len(v)-settingHeaderSize) {
		return nil, false
	}
	return v[settingHeaderSize : settingHeaderSize+int(n)], true
}

// keyNames moves peers, sessions and settings stored under the names of
// older versions to their keyed names. Peers were keyed by the SHA3-512
// of their public key, sessions by their ID and settings by their full
// key, with the bare value. It returns how many records it moved or
// dropped. Records already under keyed names are left alone, so it can
// run again after an interruption. Values that do not open are not seen,
// and stay where they are.
func (s *Storage) keyNames() (int, error) {
	var changed int
	err := s.engine.Command(func(b engine.Namespace) error {
		n, err := s.keyPeerNames(b.Sub([]byte(engine.PeersNamespace)))
		changed += n
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("peers: %w", err)
	}
	err = s.engine.Command(func(b engine.Namespace) error {
		n, err := s.keySettingNames(b.Sub([]byte(engine.SettingsNamespace)))
		changed += n
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("settings: %w", err)
	}

	var names []string
	err = s.engine.Query(func(b engine.Namespace) error {
		names = b.Sub([]byte(engine.SessionsNamespace)).ListSubNamespaces()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sessions: %w", err)
	}
	for _, name := range names {
		err := s.engine.Command(func(b engine.Namespace) error {
			moved, err := s.keySessionName(b, []byte(name))
			if moved {
				changed++
			}
			return err
		})
		if err != nil {
			return 0, fmt.Errorf("session %q: %w", name, err)
		}
	}
	return changed, nil
}

// keyPeerNames moves every peer under a legacy key to its keyed name. A
// record that does not parse, or is not stored under the hash of its own
// public key, was never trusted and is dropped.
func (s *Storage) keyPeerNames(peers engine.Namespace) (int, error) {
	type record struct{ key, value, pub []byte }
	var legacy []record
	for k, v := range peers.IterateEncrypted() {
		if len(k) != legacyPeerKeySize {
			continue
		}
		var p pb.Peer
		r := record{key: k, value: v}
		if err := proto.Unmarshal(v, &p); err == nil {
			if sum := sha3.Sum512(p.GetPublicKey()); bytes.Equal(sum[:], k) {
				r.pub = p.GetPublicKey()
			}
		}
		legacy = append(legacy, r)
	}
	for _, r := range legacy {
		if err := s.moveLegacyPeer(peers, r.key, r.value, r.pub); err != nil {
			return 0, err
		}
	}
	return len(legacy), nil
}

// moveLegacyPeer stores value, the record of the peer pub, under its keyed
// name, unless a record is there already, and deletes it from key. A nil
// pub drops the record.
func (s *Storage) moveLegacyPeer(
	peers engine.Namespace, key, value, pub []byte,
) error {
	if pub == nil {
		slog.Warn("dropping peer record that does not match its key")
		return peers.Delete(key)
	}
	keyed := s.peerKey(pub)
	_, err := peers.GetEncrypted(keyed)
	if isMissing(err) {
		if err := peers.PutEncrypted(keyed, value); err != nil {
			return err
		}
	}
	return peers.Delete(key)
}

// keySettingNames moves every setting with a bare value to its keyed name,
// with its value padded.
func (s *Storage) keySettingNames(settings engine.Namespace) (int, error) {
	type setting struct{ key, value []byte }
	var legacy []setting
	for k, v := range settings.IterateEncrypted() {
		if _, ok := decodeSetting(v); !ok {
			legacy = append(legacy, setting{key: k, value: v})
		}
	}
	for _, st := range legacy {
		err := settings.PutEncrypted(
			s.settingName(string(st.key)), encodeSetting(st.value),
		)
		if err != nil {
			return 0, err
		}
		if err := settings.Delete(st.key); err != nil {
			return 0, err
		}
	}
	return len(legacy), nil
}

// keySessionName moves the session stored under name, its ID, to its
// keyed name, and records the ID in its meta namespace. It does nothing,
// and reports false, when name is already the keyed name of the session
// recorded there. Chat entries are appended to those already under the
// keyed name, if any, and meta entries already there are kept.
func (s *Storage) keySessionName(b engine.Namespace, name []byte) (
	bool, error,
) {
	sessions := b.Sub([]byte(engine.SessionsNamespace))
	old := sessions.Sub(name)
	oldMeta := old.Sub([]byte("meta"))
	id, err := oldMeta.GetEncrypted([]byte(sessionIDKey))
	if err == nil && hmac.Equal(s.sessionName(string(id)), name) {
		return false, nil
	}

	session, err := s.ensureSession(b, string(name))
	if err != nil {
		return false, err
	}
	meta := session.Ensure([]byte("meta"))
	for k, v := range oldMeta.IterateEncrypted() {
		if string(k) == sessionIDKey {
			continue
		}
		if _, err := meta.GetEncrypted(k); !isMissing(err) {
			continue
		}
		if err := meta.PutEncrypted(k, v); err != nil {
			return false, err
		}
	}

	chat := session.Ensure([]byte("chat"))
	next, _, err := nextChatIndex(chat)
	if err != nil {
		return false, err
	}
	for k, v := range old.Sub([]byte("chat")).IterateEncrypted() {
		entry, ok := decodeChatEntry(k, v)
		if !ok {
			continue
		}
		err := chat.PutEncrypted(chatIndexKey(next), encodeChatValue(entry))
		if err != nil {
			return false, err
		}
		next++
	}
	if _, ok := messageCount(meta); ok {
		if err := putMessageCount(meta, chat.KeyCount()); err != nil {
			return false, err
		}
	}
	return true, sessions.DeleteNamespace(name)
}
