package fingerprint

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBase64(t *testing.T) {
	a := require.New(t)

	input := []byte("hello world")
	expected := base64.RawURLEncoding.EncodeToString([]byte("hello world")) // aGVsbG8gd29ybGQ
	result := Base64(input)
	a.Equal(expected, result)

	// Test empty
	a.Equal("", Base64([]byte{}))

	// Test single byte
	a.Equal("AA", Base64([]byte{0}))
}

func TestEmojiListDistinct(t *testing.T) {
	a := require.New(t)

	a.Len(emojiList, 96)
	seen := make(map[string]bool, len(emojiList))
	for _, e := range emojiList {
		a.NotEmpty(e)
		a.False(seen[e], "duplicate emoji: %s", e)
		seen[e] = true
	}
}

func TestEmoji(t *testing.T) {
	a := require.New(t)

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
	a := require.New(t)

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
	a := require.New(t)

	input := []byte("test")
	result := Pseudonym(input)
	a.NotEmpty(result)
	parts := strings.Split(result, " ")
	a.Len(parts, 4, "expected format: <adj> <adj> <noun> <num>")
	a.Contains(adjectives, parts[0])
	a.Contains(adjectives, parts[1])
	a.Contains(nouns, parts[2])
	num, err := strconv.Atoi(parts[3])
	a.NoError(err, "last part should be a number")
	a.GreaterOrEqual(num, 1)
	a.LessOrEqual(num, 99)

	// Same seed → same result
	a.Equal(Pseudonym(input), Pseudonym(input))

	// Different seed → different result (astronomically likely)
	a.NotEqual(Pseudonym([]byte("a")), Pseudonym([]byte("b")))
}

func TestNumeric(t *testing.T) {
	// The expected values come from an independent implementation; a
	// change to them changes what peers on different versions compare.
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			"test",
			[]byte("test"),
			"41642 86682 35305 82016 29480 54574 64229 44344",
		},
		{
			"empty",
			[]byte{},
			"04862 39572 21856 50821 90755 86540 92977 97264",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.want, Numeric(tt.input))
		})
	}
}

func TestNumericFormat(t *testing.T) {
	a := require.New(t)
	for i := range 256 {
		got := Numeric([]byte{byte(i)})
		groups := strings.Split(got, " ")
		a.Len(groups, numericGroups)
		for _, g := range groups {
			a.Len(g, numericGroupDigits)
			_, err := strconv.Atoi(g)
			a.NoError(err)
		}
	}
	a.NotEqual(Numeric([]byte("a")), Numeric([]byte("b")))
}
