package fingerprint

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase64(t *testing.T) {
	a := assert.New(t)

	input := []byte("hello world")
	expected := base64.RawURLEncoding.EncodeToString([]byte("hello world")) // aGVsbG8gd29ybGQ
	result := Base64(input)
	a.Equal(expected, result)

	// Test empty
	a.Equal("", Base64([]byte{}))

	// Test single byte
	a.Equal("AA", Base64([]byte{0}))
}

func TestEmoji(t *testing.T) {
	a := assert.New(t)

	input := []byte("test")
	emojis := Emoji(input)
	a.Len(emojis, 8)
	for _, e := range emojis {
		a.Contains(emojiList, e)
	}

	// Same input should give same result
	emojis2 := Emoji(input)
	a.Equal(emojis, emojis2)

	// Different input different result (likely)
	emojis3 := Emoji([]byte("different"))
	a.NotEqual(emojis, emojis3)
}

func TestHex(t *testing.T) {
	a := assert.New(t)

	input := []byte{0xAB, 0xCD, 0xEF}
	expected := "AB:CD:EF"
	result := Hex(input)
	a.Equal(expected, result)

	// Single byte
	a.Equal("00", Hex([]byte{0}))

	// Empty
	a.Equal("", Hex([]byte{}))

	// Two bytes
	a.Equal("FF:00", Hex([]byte{0xFF, 0x00}))
}

func TestPseudonym(t *testing.T) {
	a := assert.New(t)

	result := Pseudonym()
	a.NotEmpty(result)
	parts := strings.Split(result, " ")
	a.Len(parts, 2)
	a.Contains(adjectives, parts[0])
	a.Contains(nouns, parts[1])
}
