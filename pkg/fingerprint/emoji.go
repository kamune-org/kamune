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

// Emoji returns 8 emojis deterministically derived from the input bytes.
// There are 96 distinct emojis, giving 96⁸ ≈ 7.2 quadrillion possible
// combinations (~50% collision at 100 million sessions).
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
