package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/internal/engine"
)

// Chat entries are keyed by chatKeyPrefix and a big-endian uint64 index,
// one more than that of the last entry. The key gives away only the order
// in which entries were stored, which their number already shows. Entries
// stored before this format are keyed by their receive time and sender
// (see [decodeChatEntry]). Index keys sort after those of every receive
// time from 1970 on, so the last key of a chat is an index key whenever
// the chat has any.
const (
	chatKeyPrefix     = 0xff
	chatKeySize       = 1 + 8
	legacyChatKeySize = 14
)

// chatValueMagic starts the value of an entry under an index key. It is
// followed by the local receive time, the sender's timestamp, the sender,
// the payload length, the payload and zero padding (see [encodeChatValue]).
var chatValueMagic = []byte("KMNE\x02")

const chatHeaderSize = 5 + 8 + 8 + 2 + 4

// chatPadSizes are the sizes chat values are padded to before they are
// sealed: the smallest that fits, or a multiple of the last one. They are
// about the padding buckets of the wire, so the stored length shows only
// which of these sizes a message needed, as the wire length does.
var chatPadSizes = []int{512, 1 << 10, 4 << 10, 16 << 10, 32 << 10, 64 << 10}

// paddedSize returns the size a chat value of n bytes is padded to.
func paddedSize(n int) int {
	for _, size := range chatPadSizes {
		if n <= size {
			return size
		}
	}
	last := chatPadSizes[len(chatPadSizes)-1]
	return (n + last - 1) / last * last
}

// isChatIndexKey reports whether key is an index key.
func isChatIndexKey(key []byte) bool {
	return len(key) == chatKeySize && key[0] == chatKeyPrefix
}

// chatIndexKey returns the index key for index i.
func chatIndexKey(i uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte{chatKeyPrefix}, i)
}

// encodeChatValue returns the value of a chat entry under an index key:
//   - 5 bytes: [chatValueMagic]
//   - 8 bytes: local receive time, UnixNano (big-endian)
//   - 8 bytes: sender's timestamp, UnixNano (big-endian), 0 when zero
//   - 2 bytes: sender (big-endian)
//   - 4 bytes: payload length (big-endian)
//   - the payload, then zero bytes up to [paddedSize]
func encodeChatValue(e ChatEntry) []byte {
	v := make([]byte, paddedSize(chatHeaderSize+len(e.Data)))
	copy(v, chatValueMagic)
	binary.BigEndian.PutUint64(v[5:], uint64(e.Timestamp.UnixNano()))
	var sentAt int64
	if !e.SentAt.IsZero() {
		sentAt = e.SentAt.UnixNano()
	}
	binary.BigEndian.PutUint64(v[13:], uint64(sentAt))
	binary.BigEndian.PutUint16(v[21:], uint16(e.Sender))
	binary.BigEndian.PutUint32(v[23:], uint32(len(e.Data)))
	copy(v[chatHeaderSize:], e.Data)
	return v
}

// decodeChatValue parses a value made by [encodeChatValue].
func decodeChatValue(v []byte) (ChatEntry, bool) {
	if len(v) < chatHeaderSize || !bytes.HasPrefix(v, chatValueMagic) {
		return ChatEntry{}, false
	}
	n := binary.BigEndian.Uint32(v[23:])
	if uint64(n) > uint64(len(v)-chatHeaderSize) {
		return ChatEntry{}, false
	}
	e := ChatEntry{
		Timestamp: time.Unix(0, int64(binary.BigEndian.Uint64(v[5:]))),
		Sender:    Sender(binary.BigEndian.Uint16(v[21:])),
		Data:      bytes.Clone(v[chatHeaderSize : chatHeaderSize+int(n)]),
	}
	if sentAt := int64(binary.BigEndian.Uint64(v[13:])); sentAt != 0 {
		e.SentAt = time.Unix(0, sentAt)
	}
	return e, true
}

// nextChatIndex returns the index for the next entry of chat. A chat whose
// last key is not an index key is converted first with
// [convertLegacyChat], and dropped tells how many entries that removed.
func nextChatIndex(chat engine.Namespace) (
	next uint64, dropped int, err error,
) {
	last := chat.LastKey()
	switch {
	case last == nil:
		return 0, 0, nil
	case isChatIndexKey(last):
		return binary.BigEndian.Uint64(last[1:]) + 1, 0, nil
	}
	_, next, dropped, err = convertLegacyChat(chat)
	return next, dropped, err
}

// convertLegacyChat stores every entry of chat that is not under an index
// key again under one, after the existing index keys, in the order of
// their old keys, and deletes the old keys. Entries that do not decode
// are deleted too; they never showed in history. It returns how many
// entries it converted, the index for the next entry and how many it
// dropped. Values that do not open are not seen, and stay as they are.
func convertLegacyChat(chat engine.Namespace) (
	converted int, next uint64, dropped int, err error,
) {
	type legacy struct {
		key   []byte
		entry ChatEntry
		ok    bool
	}
	var old []legacy
	for k, v := range chat.IterateEncrypted() {
		if isChatIndexKey(k) {
			next = max(next, binary.BigEndian.Uint64(k[1:])+1)
			continue
		}
		e, ok := decodeChatEntry(k, v)
		old = append(old, legacy{key: k, entry: e, ok: ok})
	}
	for _, o := range old {
		if o.ok {
			key, value := chatIndexKey(next), encodeChatValue(o.entry)
			if err := chat.PutEncrypted(key, value); err != nil {
				return 0, 0, 0, fmt.Errorf("store converted entry: %w", err)
			}
			next++
			converted++
		} else {
			dropped++
		}
		if err := chat.Delete(o.key); err != nil {
			return 0, 0, 0, fmt.Errorf("delete legacy entry: %w", err)
		}
	}
	return converted, next, dropped, nil
}
