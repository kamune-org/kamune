package kamune

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// persian is a Persian name with a zero-width non-joiner between two
// letters, as Persian writes compound names.
const persian = "\u0639\u0644\u06cc\u200c\u0631\u0636\u0627"

func TestValidatePeerName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"empty", "", true},
		{"ascii", "alice", true},
		{"default fingerprint", strings.Repeat("A", 43), true},
		{"at the limit", strings.Repeat("a", MaxPeerNameLength), true},
		{"persian with zwnj", persian, true},
		{"zwnj after a mark", "\u0628\u064e\u200c\u0628", true},
		{"zwnj before a mark", "\u0628\u200c\u064e\u0628", true},
		{"zwnj after virama", "\u0915\u094d\u200c\u0937", true},
		{"zwj after virama", "\u0915\u094d\u200d\u0937", true},
		{"zwj after virama before a mark", "\u0915\u094d\u200d\u093c\u0937", true},
		{"zwj after virama at the end", "\u0d28\u0d4d\u200d", true},
		{"zwnj after virama at the end", "\u0915\u094d\u200c", true},
		{"zwj after virama before a space", "\u0d28\u0d4d\u200d \u0d15", true},
		{"zwj after virama before a digit", "\u0915\u094d\u200d1", true},
		{"zwj after virama before an emoji", "\u0915\u094d\u200d\U0001f4bb", true},
		{"malayalam initials", "\u0d15\u0d46. \u0d06\u0d30\u0d4d\u200d. \u0d28\u0d3e\u0d30\u0d3e\u0d2f\u0d23\u0d28\u0d4d\u200d", true},
		{"chillu before a comma", "\u0d30\u0d3e\u0d1c\u0d28\u0d4d\u200d, \u0d15", true},
		{"chillu in parentheses", "(\u0d30\u0d3e\u0d1c\u0d28\u0d4d\u200d)", true},
		{"bengali khanda ta before a period", "\u09b6\u09b0\u09a4\u09cd\u200d.", true},
		{"devanagari half form before a danda", "\u0915\u094d\u200d\u0964", true},
		{"zwj after virama before a zwj", "\u0915\u094d\u200d\u200d", false},
		{"zwj after virama before a hangul filler", "\u0915\u094d\u200d\u3164", false},
		{"bengali ra-phala", "\u09b0\u200d\u09cd\u09af\u09be\u09ac", true},
		{"sinhala touching letters", "\u0dc3\u0dd2\u0daf\u200d\u0dca\u0db0", true},
		{"zwj before virama after latin", "b\u200d\u094d", false},
		{"zwj before virama at the start", "\u200d\u094d\u0915", false},
		{"zwnj before virama", "\u09b0\u200c\u09cd\u09af", false},
		{"zwj before a virama of another script", "\u0915\u200d\u09cd", false},
		{"emoji with zwj", "\U0001f469\u200d\U0001f4bb dev", true},
		{"skin tone with zwj", "\U0001f469\U0001f3fd\u200d\U0001f4bb", true},
		{"flag with zwj", "\U0001f3f3\ufe0f\u200d\U0001f308", true},
		{"emoji with selector", "\u2764\ufe0f bob", true},
		{"arrow with selector", "\u2194\ufe0f", true},
		{"keycap", "1\ufe0f\u20e3", true},
		{"information with selector", "\u2139\ufe0f", true},
		{"wavy dash with selector", "\u3030\ufe0f", true},
		{"part alternation mark with selector", "\u303d\ufe0f", true},
		{"ideographic variation", "\u845b\U000e0100", true},
		{"mongolian selector", "\u1820\u180b", true},
		{"over the limit", strings.Repeat("a", MaxPeerNameLength+1), false},
		{"multi-byte over the limit", strings.Repeat("\u00e9", 33), false},
		{"invalid utf-8", "bob\xff", false},
		{"newline", "bob\nalice", false},
		{"tab", "bob\talice", false},
		{"nul", "bob\x00", false},
		{"ansi escape", "\x1b[31mbob", false},
		{"del", "bob\x7f", false},
		{"c1 control", "bob\u009b", false},
		{"right-to-left override", "bob\u202egnp.exe", false},
		{"right-to-left isolate", "bob\u2067", false},
		{"pop directional isolate", "bob\u2069", false},
		{"left-to-right mark", "bob\u200e", false},
		{"arabic letter mark", "bob\u061c", false},
		{"zero-width space", "b\u200bob", false},
		{"word joiner", "b\u2060ob", false},
		{"invisible times", "bob\u2062", false},
		{"byte order mark", "\ufeffbob", false},
		{"soft hyphen", "bo\u00adb", false},
		{"tag character", "bob\U000e0041", false},
		{"line separator", "bob\u2028alice", false},
		{"paragraph separator", "bob\u2029alice", false},
		{"mongolian vowel separator", "bob\u180e", false},
		{"zwj after latin", "Bob\u200d", false},
		{"zwnj after latin", "Bob\u200c", false},
		{"zwnj inside latin", "Bo\u200cb", false},
		{"zwj before latin", "\U0001f469\u200db", false},
		{"leading zwnj", "\u200c\u0639\u0644\u06cc", false},
		{"trailing zwnj", "\u0639\u0644\u06cc\u200c", false},
		{"zwnj between scripts", "\u0639\u200cb", false},
		{"zwj between arabic letters", "\u0628\u200d\u0628", false},
		{"zwnj between devanagari letters", "\u0915\u200c\u0937", false},
		{"two joiners", "\U0001f469\u200d\u200d\U0001f4bb", false},
		{"zwj before a skin tone", "\U0001f469\u200d\U0001f3fd", true},
		{"head shaking horizontally", "\U0001f642\u200d\u2194\ufe0f", true},
		{"emoji newer than the go tables", "\U0001f9d1\U0001f3fb\u200d\U0001faef\u200d\U0001f9d1\U0001f3fc", true},
		{"flag of england", "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f", true},
		{"flag of wales after a name", "Bob \U0001f3f4\U000e0067\U000e0062\U000e0077\U000e006c\U000e0073\U000e007f", true},
		{"unknown subdivision flag", "\U0001f3f4\U000e0067\U000e0062\U000e0078\U000e0078\U000e0078\U000e007f", false},
		{"flag without cancel tag", "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067", false},
		{"flag with hidden text", "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e0061\U000e007f", false},
		{"cancel tag alone", "Bob\U000e007f", false},
		{"tags after a latin letter", "B\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f", false},
		{"mongolian vowel separator before final a", "\u1830\u1820\u1837\u180e\u1820", true},
		{"mongolian vowel separator before a consonant", "\u1830\u1820\u180e\u1837", false},
		{"object replacement character", "Bob\ufffc", false},
		{"selector after latin", "Bob\ufe0f", false},
		{"selector after digit", "Bob1\ufe0f", false},
		{"selector after ascii symbol", "Bob+\ufe0f", false},
		{"two selectors", "\u2764\ufe0f\ufe0f", false},
		{"leading selector", "\ufe0fBob", false},
		{"ideographic selector after latin", "Bob\U000e0100", false},
		{"mongolian selector after latin", "Bob\u180b", false},
		{"mongolian selector after han", "\u845b\u180b", false},
		{"emoji selector after han", "\u845b\ufe0f", false},
		{"combining grapheme joiner", "Bo\u034fb", false},
		{"hangul filler", "Bob\u3164", false},
		{"halfwidth hangul filler", "Bob\uffa0", false},
		{"hangul choseong filler", "Bob\u115f", false},
		{"khmer inherent vowel", "Bob\u17b4", false},
		{"braille blank", "Bob\u2800", false},
		{"khitan filler", "Bob\U00016fe4", false},
		{"musical null notehead", "Bob\U0001d159", false},
		{"musical begin beam", "Bob\U0001d173", false},
		{"zwj before null notehead", "\U0001f469\u200d\U0001d159", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			err := ValidatePeerName(tt.input)
			if tt.valid {
				a.NoError(err)
				return
			}
			a.ErrorIs(err, ErrInvalidPeerName)
		})
	}
}

func TestSamePeerName(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		same bool
	}{
		{"equal", "Bob", "Bob", true},
		{"case", "Bob", "bOB", true},
		{"spaces at the ends", "Bob", " Bob\u00a0", true},
		{"spaces inside", "Bob Lee", "Bob \t Lee", true},
		{"no space inside", "Bob Lee", "BobLee", true},
		{"space inside", "Bob", "Bo b", true},
		{"hair space", "Bob", "Bo\u200ab", true},
		{"thin space", "Bob Lee", "Bob\u2009Lee", true},
		{"narrow no-break space", "Bob Lee", "Bob\u202fLee", true},
		{"medium mathematical space", "Bob", "B\u205fob", true},
		{"trailing zwj", "Bob", "Bob\u200d", true},
		{"zwnj inside", "Bob", "Bo\u200cb", true},
		{"hangul filler", "Bob", "Bob\u3164", true},
		{"braille blank", "Bob", "Bob\u2800", true},
		{"null notehead", "Bob", "Bob\U0001d159", true},
		{"musical begin beam", "Bob", "Bob\U0001d173", true},
		{"khitan filler", "Bob", "Bob\U00016fe4", true},
		{"object replacement character", "Bob", "Bob\ufffc", true},
		{"selector", "\u2764 bob", "\u2764\ufe0f Bob", true},
		{"tag character", "Bob", "Bob\U000e0041", true},
		{"control", "Bob", "B\x00ob", true},
		{"persian zwnj", persian, strings.ReplaceAll(persian, "\u200c", ""), true},
		{"both empty", "", "\u200d ", true},
		{"different letter", "Bob", "Rob", false},
		{"accent", "Bob", "B\u00f6b", false},
		{"cyrillic", "Bob", "B\u043eb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.same, SamePeerName(tt.x, tt.y))
			a.Equal(tt.same, SamePeerName(tt.y, tt.x))
		})
	}
}

func TestSanitizePeerName(t *testing.T) {
	const repl = "\ufffd"
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"valid", "Bob", "Bob"},
		{"valid persian", persian, persian},
		{
			"valid emoji",
			"\U0001f469\u200d\U0001f4bb",
			"\U0001f469\u200d\U0001f4bb",
		},
		{"newline", "Bob\n[INFO] forged", "Bob" + repl + "[INFO] forged"},
		{"bidi override", "\u202eboB", repl + "boB"},
		{"invalid utf-8", "Bob\xff\xfe", "Bob" + repl + repl},
		{"trailing zwj", "Bob\u200d", "Bob" + repl},
		{"selector after latin", "Bob\ufe0f", "Bob" + repl},
		{"hangul filler", "Bob\u3164", "Bob" + repl},
		{"valid chillu", "\u0d28\u0d4d\u200d", "\u0d28\u0d4d\u200d"},
		{
			// A Hangul filler is a letter, but a rejected one, so the
			// joiner before it goes too.
			"zwj after virama before a hangul filler",
			"\u0915\u094d\u200d\u3164",
			"\u0915\u094d" + repl + repl,
		},
		{
			"zwnj after virama before a choseong filler",
			"\u0915\u094d\u200c\u115f",
			"\u0915\u094d" + repl + repl,
		},
		{
			"zwj after virama before a halfwidth filler",
			"\u0915\u094d\u200d\uffa0x",
			"\u0915\u094d" + repl + repl + "x",
		},
		{
			"zwj after virama before a newline",
			"\u0915\u094d\u200d\n",
			"\u0915\u094d" + repl + repl,
		},
		{
			"zwj before null notehead",
			"\U0001f469\u200d\U0001d159",
			"\U0001f469" + repl + repl,
		},
		{
			// U+FFFD is a symbol, so a joiner between it and an emoji
			// stays.
			"joiner after a replaced code point",
			"\u202e\u200d\U0001f4bb",
			repl + "\u200d\U0001f4bb",
		},
		{
			"long",
			strings.Repeat("a", MaxPeerNameLength+1),
			strings.Repeat("a", MaxPeerNameLength-3) + "\u2026",
		},
		{
			"long multi-byte",
			strings.Repeat("\u0628", 40),
			strings.Repeat("\u0628", 30) + "\u2026",
		},
		{
			// The cut leaves a non-joiner with no letter after it.
			"cut after a joiner",
			strings.Repeat("a", 56) + "\u0628\u200c\u0628\u0628",
			strings.Repeat("a", 56) + "\u0628" + repl + "\u2026",
		},
		{
			"long after replacing",
			strings.Repeat("\x00", MaxPeerNameLength),
			strings.Repeat(repl, 20) + "\u2026",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := SanitizePeerName(tt.input)
			a.Equal(tt.want, got)
			a.NoError(ValidatePeerName(got))
		})
	}
}

func FuzzSanitizePeerName(f *testing.F) {
	for _, seed := range []string{
		"Bob",
		"Bob\u200d",
		persian,
		"\U0001f3f3\ufe0f\u200d\U0001f308",
		"1\ufe0f\u20e3",
		strings.Repeat("a", 56) + "\u0628\u200c\u0628\u0628",
		strings.Repeat("\u0915\u094d\u200d", 30),
		"\xff\u200d\U0001f4bb",
		"\u0628\u064e\xff\u200c\u0628",
		"\u0915\u094d\u200d\u3164",
		"\u0915\u094d\u200c\u115f",
		"\u0915\u094d\u200d\uffa0x",
		"\u0d28\u0d4d\u200d \u0d15\u0d4d\u200d",
		"\u0915\u094d\u200d\n",
		"\U0001f469\u200d\U0001d159",
		"\u09b0\u200d\u09cd\u09af",
		"a\u200d\u094d",
		"\u0d30\u0d4d\u200d, \u0d15",
		"\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f",
		"\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067",
		"\u1830\u1820\u180e\u1820",
		"Bob\ufffc",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		a := require.New(t)
		got := SanitizePeerName(name)
		a.NoError(ValidatePeerName(got))
		a.LessOrEqual(len(got), MaxPeerNameLength)
		a.True(utf8.ValidString(got))
		if ValidatePeerName(name) == nil {
			a.Equal(name, got)
		}
	})
}

// TestSanitizePeerNameIsValid sanitizes every string of up to three
// fragments drawn from the code points that the rules for joiners,
// selectors and blank code points look at, and long names that end in up
// to two of them, and checks that each result passes ValidatePeerName.
func TestSanitizePeerNameIsValid(t *testing.T) {
	a := require.New(t)
	fragments := []string{
		"a", "1", "#", " ", "\u2009", "\n", "\xff", "\u2026",
		"\u0915", "\u0915\u094d", "\u094d", "\u0d4d", "\u093c",
		"\u09b0", "\u09cd", ".", "\u1830", "\u1820", "\u180e",
		"\U0001f3f4", "\U000e0067", "\U000e007f", "\ufffc", "\U0001faef",
		"\u0628", "\u064e", "\u1820", "\u845b",
		"\u200c", "\u200d", "\ufe0f", "\U000e0100", "\u180b", "\u20e3",
		"\u034f", "\u202e", "\u3164", "\u115f", "\uffa0",
		"\U00016fe4", "\u2800", "\U0001d159",
		"\U0001f469", "\U0001f3fd", "\u2194", "\ufffd",
	}
	var walk func(name string, depth int)
	walk = func(name string, depth int) {
		got := SanitizePeerName(name)
		a.NoError(ValidatePeerName(got), "%+q sanitized to %+q", name, got)
		if ValidatePeerName(name) == nil {
			a.Equal(name, got)
		}
		if depth == 0 {
			return
		}
		for _, f := range fragments {
			walk(name+f, depth-1)
		}
	}
	walk("", 3)
	// Names that end near the length limit, so that the cut lands on
	// every fragment.
	for n := MaxPeerNameLength - 12; n < MaxPeerNameLength; n++ {
		walk(strings.Repeat("a", n), 2)
	}
}

func TestViramasSorted(t *testing.T) {
	require.New(t).IsIncreasing(viramas)
}
