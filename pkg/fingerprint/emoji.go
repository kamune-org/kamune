package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
)

var emojiList = []string{
	"😎", "👻", "👍", "👑", "🎃", "🎯", "🧬", "🧨",
	"🐶", "🐱", "🦁", "🐹", "🐰", "🦊", "🐻", "🐼",
	"🌸", "🥁", "🪷", "🌹", "🪩", "🍁", "🌳", "🌵",
	"🍎", "🍌", "🍇", "🍓", "🥝", "🍕", "🍔", "🍟",
	"☕️", "🍦", "🥕", "☀️", "🌙", "❄️", "☁️", "🧂",
	"💡", "🎹", "💎", "📷", "🏀", "🎮", "🎲", "🎩",
	"❤️", "🎁", "⏰", "🧩", "🧲", "🔑", "🚗️", "🚀",
	"✨", "🔥", "🌈", "🎉", "🎶", "🔒", "📌", "✅",
	"🤖", "🪐", "🦴", "🍩", "🎪", "🔮", "⛱️", "👽",
	"🦄", "🐧", "🦋", "🐙", "🦈", "🦅", "🦀", "🪲",
	"🌻", "🍀", "🌊", "⛰️", "🍄", "🌋", "🌪️", "🥑",
	"🎸", "🔭", "🧭", "🎨", "⚡", "🗝️", "🧿", "🛡️",
}

// Emoji returns 8 emojis deterministically derived from the input bytes:
// each is one of 96 emojis, picked by a 32-bit chunk of the SHA-256 of b.
//
// The 96⁸ combinations carry only about 52.7 bits. Finding another key with
// the same emojis as a given key takes about 2^52.7 tries, within reach of
// a well-funded attacker, and the result serves for every later first
// contact with that key. Emoji alone therefore does not protect a key
// comparison against a man in the middle; use [Numeric], which carries
// about 132.9 bits. The list also holds look-alikes such as 🔑 and 🗝️.
// The output stays the same across versions, so that peers on different
// versions see the same emojis for a key.
func Emoji(s []byte) []string {
	hash := sha256.Sum256(s)
	offset := 0
	l := uint32(len(emojiList))
	emojis := make([]string, 8)
	for i := range 8 {
		offset = i * 4
		num := binary.BigEndian.Uint32(hash[offset : offset+4])
		emojis[i] = emojiList[num%l]
	}
	return emojis
}
