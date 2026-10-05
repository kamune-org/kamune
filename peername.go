package kamune

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxPeerNameLength is the longest name, in bytes, that a peer may introduce
// itself with. See [ValidatePeerName].
const MaxPeerNameLength = 64

const (
	zwnj         = '\u200C' // zero-width non-joiner
	zwj          = '\u200D' // zero-width joiner
	keycap       = '\u20E3' // combining enclosing keycap
	blankBraille = '\u2800' // braille pattern blank
	khitanFiller = '\U00016FE4'
	nullNotehead = '\U0001D159' // musical symbol null notehead
	objectRepl   = '\uFFFC'     // object replacement character
	blackFlag    = '\U0001F3F4'
	cancelTag    = '\U000E007F'
	mongolianVS  = '\u180E' // Mongolian vowel separator
)

// ValidatePeerName checks a name that a peer introduces itself with. It
// returns an error wrapping [ErrInvalidPeerName] when name is longer than
// [MaxPeerNameLength] bytes, is not valid UTF-8, or holds a code point that
// shows nothing or can change how the name, or the text shown around it,
// looks:
//   - control characters (C0, DEL and C1), such as line breaks and the
//     escape character that starts terminal escape sequences;
//   - line and paragraph separators;
//   - format characters, which include the bidirectional controls that
//     reorder text and invisible ones such as the zero-width space, the
//     word joiner, the byte order mark and tag characters;
//   - the other default ignorable code points, such as the combining
//     grapheme joiner and the Hangul fillers;
//   - the other code points known to be drawn blank: the Khitan filler,
//     the blank Braille pattern, the musical null notehead and the object
//     replacement character. A font can draw more code points blank, such
//     as private-use ones, and those pass.
//
// The zero-width non-joiner and joiner (U+200C and U+200D), the
// variation selectors, the tag characters and the Mongolian vowel
// separator are format characters too. They are allowed only where
// scripts and emoji use them:
//   - either joiner after a virama and before a code point that shows, a
//     space or the end of the name, as in Indic scripts, in Bengali khanda
//     ta and in Malayalam chillu letters written the way text did before
//     Unicode 5.1;
//   - the joiner after a letter and right before a virama of its script,
//     as in Bengali ra-phala and Sinhala touching letters;
//   - the non-joiner between two letters of a script whose letters join,
//     such as Arabic, as Persian needs;
//   - the joiner between two emoji or other symbols, as in emoji
//     sequences; the emoji blocks from U+1F000 count whole, so that emoji
//     newer than Go's Unicode tables pass;
//   - U+FE0E and U+FE0F right after an emoji or another symbol, or after
//     a digit, # or * that the keycap mark U+20E3 follows;
//   - U+FE00 to U+FE02 and the ideographic variation selectors right after
//     a CJK ideograph, and the Mongolian selectors right after a Mongolian
//     letter;
//   - tag characters only in the flags of England, Scotland and Wales: the
//     black flag, a tag sequence and the cancel tag;
//   - the Mongolian vowel separator between a Mongolian letter and the
//     vowel a or e.
//
// Anywhere else, such as after a Latin letter or at the start of the name,
// they are rejected. An empty name is valid.
//
// Names that pass can still look alike: letters of different scripts can
// share a shape, spaces are allowed, including at either end, and a joiner
// or selector does not change every letter or symbol it is allowed after.
// Applications that compare names should do so after trimming spaces,
// folding case and dropping joiners and selectors. A peer's name is its
// own claim and proves nothing about its identity, which only the key
// fingerprint shows.
//
// The server and the dialer reject an introduction whose name fails this
// check before the [RemoteVerifier] runs, and [ServeWithServerName] and
// [DialWithClientName] reject such a local name. Applications can use it to
// check names that users type, and [SanitizePeerName] to show names that
// were stored without the check.
func ValidatePeerName(name string) error {
	if len(name) > MaxPeerNameLength {
		return fmt.Errorf(
			"%w: %d bytes, the limit is %d",
			ErrInvalidPeerName, len(name), MaxPeerNameLength,
		)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidPeerName)
	}
	for i, r := range name {
		if !nameRuneAllowed(name[:i], r, name[i+utf8.RuneLen(r):]) {
			return fmt.Errorf(
				"%w: code point %U at byte %d", ErrInvalidPeerName, r, i,
			)
		}
	}
	return nil
}

// SanitizePeerName makes a name that may fail [ValidatePeerName], such as
// one stored by an older version, safe to show. Each invalid UTF-8
// sequence and each code point that the check rejects becomes U+FFFD, so
// a hidden character shows as a mark rather than not at all. A name still
// longer than [MaxPeerNameLength] bytes is cut on a code point boundary
// and ends with an ellipsis. The result always passes ValidatePeerName,
// and a name that passes is returned unchanged.
func SanitizePeerName(name string) string {
	s := replaceRejectedRunes(name)
	if len(s) <= MaxPeerNameLength {
		return s
	}
	const ellipsis = "\u2026"
	cut := MaxPeerNameLength - len(ellipsis)
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	// Cutting can take away what a joiner or selector at the new end
	// needs after it. Replacing one keeps its length or shortens it.
	return replaceRejectedRunes(s[:cut] + ellipsis)
}

// replaceRejectedRunes replaces each invalid UTF-8 sequence and each code
// point of s that [ValidatePeerName] rejects with U+FFFD. It does not cut
// s to length.
func replaceRejectedRunes(s string) string {
	if ValidatePeerName(s) == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		// The context before a code point is what has been written so
		// far, replacements included. The context after it is the input,
		// which stays as it is where it matters: what a joiner or
		// selector needs after it is never replaced, as the letters,
		// emoji, spaces and keycap marks it needs are never rejected.
		if r == utf8.RuneError && size == 1 ||
			!nameRuneAllowed(b.String(), r, s[i+size:]) {
			r = unicode.ReplacementChar
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// nameRuneAllowed reports whether r may appear in a peer's name between
// before and after. See [ValidatePeerName].
func nameRuneAllowed(before string, r rune, after string) bool {
	switch {
	case r == zwnj:
		return afterVirama(before, after) || joinsLetters(before, after)
	case r == zwj:
		return afterVirama(before, after) || beforeVirama(before, after) ||
			joinsEmoji(before, after)
	case unicode.Is(unicode.Variation_Selector, r):
		return selectorAllowed(before, r, after)
	case isTag(r):
		return inSubdivisionFlag(before, r, after)
	case r == mongolianVS:
		return beforeFinalVowel(before, after)
	case unicode.IsControl(r), blank(r):
		return false
	default:
		return !unicode.In(
			r,
			unicode.Cf,
			unicode.Zl,
			unicode.Zp,
			unicode.Other_Default_Ignorable_Code_Point,
		)
	}
}

// blank reports whether r is one of the code points that are drawn as
// blank space but are not default ignorable, which [nameRuneAllowed]
// rejects.
func blank(r rune) bool {
	return r == khitanFiller || r == blankBraille || r == nullNotehead ||
		r == objectRepl
}

// hidden reports whether r is a code point that shows nothing on its own
// and that [nameRuneAllowed] rejects, or allows only in some places.
func hidden(r rune) bool {
	return r == zwnj || r == zwj || blank(r) ||
		unicode.In(
			r,
			unicode.Cf,
			unicode.Variation_Selector,
			unicode.Other_Default_Ignorable_Code_Point,
		)
}

// lastBase returns the last code point of s that is not a nonspacing
// mark, or -1 when there is none.
func lastBase(s string) rune {
	for s != "" {
		r, size := utf8.DecodeLastRuneInString(s)
		if !unicode.Is(unicode.Mn, r) {
			return r
		}
		s = s[:len(s)-size]
	}
	return -1
}

// firstBase returns the first code point of s that is not a nonspacing
// mark, or -1 when there is none. Marks that show nothing, such as
// variation selectors, end the search like any other code point.
func firstBase(s string) rune {
	for _, r := range s {
		if !unicode.Is(unicode.Mn, r) || hidden(r) {
			return r
		}
	}
	return -1
}

// joiningScripts are the scripts whose letters join to their neighbours,
// so that a zero-width non-joiner between two of them changes how they
// are drawn.
var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic,
	unicode.Syriac,
	unicode.Nko,
	unicode.Mongolian,
	unicode.Mandaic,
	unicode.Manichaean,
	unicode.Psalter_Pahlavi,
	unicode.Adlam,
	unicode.Hanifi_Rohingya,
	unicode.Sogdian,
	unicode.Old_Uyghur,
	unicode.Phags_Pa,
	unicode.Chorasmian,
}

// visibleLetter reports whether r is a letter that shows, unlike the
// Hangul fillers.
func visibleLetter(r rune) bool {
	return unicode.IsLetter(r) && !hidden(r)
}

// joinsLetters reports whether a zero-width non-joiner between before and
// after stands between two letters of one joining script, marks aside.
func joinsLetters(before, after string) bool {
	p, n := lastBase(before), firstBase(after)
	if !visibleLetter(p) || !visibleLetter(n) {
		return false
	}
	for _, script := range joiningScripts {
		if unicode.Is(script, p) {
			return unicode.Is(script, n)
		}
	}
	return false
}

// pictograph reports whether r can stand in an emoji sequence: a code
// point of the emoji blocks from U+1F000 to U+1FFFD, skin tone modifiers
// among them, whether or not Go's Unicode tables assign it yet, or another
// non-ASCII symbol that is not drawn blank.
func pictograph(r rune) bool {
	if r >= 0x1F000 && r <= 0x1FFFD {
		return true
	}
	return r > unicode.MaxASCII && !blank(r) &&
		unicode.In(r, unicode.So, unicode.Sm)
}

// joinsEmoji reports whether a zero-width joiner between before and after
// joins two emoji. The one before may carry a variation selector.
func joinsEmoji(before, after string) bool {
	n, size := utf8.DecodeRuneInString(after)
	return size > 0 && pictograph(lastBase(before)) && pictograph(n)
}

// selectorAllowed reports whether the variation selector r may follow
// before, with after following it.
func selectorAllowed(before string, r rune, after string) bool {
	p, size := utf8.DecodeLastRuneInString(before)
	switch {
	case size == 0:
		return false
	case r >= '\u180B' && r <= '\u180F':
		return unicode.Is(unicode.Mongolian, p) && unicode.IsLetter(p)
	case unicode.Is(unicode.Han, p):
		// Standardized variation sequences of the CJK compatibility
		// ideographs, and ideographic variation sequences.
		return r <= '\uFE02' || r >= '\U000E0100'
	case r != '\uFE0E' && r != '\uFE0F':
		return false
	case pictograph(p), p > unicode.MaxASCII && unicode.Is(unicode.Sm, p),
		p == '\u203C', p == '\u2049', p == '\u2139', p == '\u3030',
		p == '\u303D':
		// Emoji presentation sequences whose base is not a symbol of its
		// own, such as U+2139 (a letter) and U+3030 (a dash), are listed.
		return true
	case p == '#', p == '*', p >= '0' && p <= '9':
		// Keycap sequences, such as 1 U+FE0F U+20E3.
		n, _ := utf8.DecodeRuneInString(after)
		return n == keycap
	default:
		return false
	}
}

// viramas are the code points of Unicode canonical combining class 9, the
// viramas and similar signs after which a joiner or non-joiner picks how
// a consonant cluster is drawn. Sorted.
var viramas = []rune{
	0x094D, 0x09CD, 0x0A4D, 0x0ACD, 0x0B4D, 0x0BCD, 0x0C4D, 0x0CCD,
	0x0D3B, 0x0D3C, 0x0D4D, 0x0DCA, 0x0E3A, 0x0EBA, 0x0F84, 0x1039,
	0x103A, 0x1714, 0x1715, 0x1734, 0x17D2, 0x1A60, 0x1B44, 0x1BAA,
	0x1BAB, 0x1BF2, 0x1BF3, 0x2D7F, 0xA806, 0xA82C, 0xA8C4, 0xA953,
	0xA9C0, 0xAAF6, 0xABED, 0x10A3F, 0x11046, 0x11070, 0x1107F,
	0x110B9, 0x11133, 0x11134, 0x111C0, 0x11235, 0x112EA, 0x1134D,
	0x11442, 0x114C2, 0x115BF, 0x1163F, 0x116B6, 0x1172B, 0x11839,
	0x1193D, 0x1193E, 0x119E0, 0x11A34, 0x11A47, 0x11A99, 0x11C3F,
	0x11D44, 0x11D45, 0x11D97, 0x11F41, 0x11F42,
}

// afterVirama reports whether a joiner between before and after follows
// a virama and comes, marks aside, before a code point that shows or at
// the end of the name. A joiner that ends a word, before a space,
// punctuation, a digit or an emoji, writes Malayalam chillu letters the
// way text did before Unicode 5.1, and Bengali khanda ta.
func afterVirama(before, after string) bool {
	p, size := utf8.DecodeLastRuneInString(before)
	if size == 0 {
		return false
	}
	if _, found := slices.BinarySearch(viramas, p); !found {
		return false
	}
	n := firstBase(after)
	return n < 0 || shows(n)
}

// shows reports whether r shows and [nameRuneAllowed] never rejects it:
// it is not a control, a line or paragraph separator, or a code point
// that shows nothing. A joiner may therefore rely on it being there in
// the sanitized name too.
func shows(r rune) bool {
	return !hidden(r) && !unicode.IsControl(r) &&
		!unicode.In(r, unicode.Zl, unicode.Zp)
}

// beforeVirama reports whether a joiner between before and after comes
// right before a virama and after a letter of the virama's script, marks
// aside, as in Bengali ra-phala and Sinhala touching letters. A virama is
// never rejected, so [SanitizePeerName] keeps such a joiner only where the
// result validates.
func beforeVirama(before, after string) bool {
	n, size := utf8.DecodeRuneInString(after)
	if size == 0 {
		return false
	}
	if _, found := slices.BinarySearch(viramas, n); !found {
		return false
	}
	p := lastBase(before)
	return visibleLetter(p) && sameScript(p, n)
}

// sameScript reports whether p belongs to the Unicode script of n.
func sameScript(p, n rune) bool {
	for _, script := range unicode.Scripts {
		if unicode.Is(script, n) {
			return unicode.Is(script, p)
		}
	}
	return false
}

// subdivisionFlags are the tag sequences of the emoji flags Unicode
// recommends, England, Scotland and Wales, without the cancel tag.
var subdivisionFlags = []string{"gbeng", "gbsct", "gbwls"}

// isTag reports whether r is a tag character, U+E0020 to U+E007F.
func isTag(r rune) bool {
	return r >= 0xE0020 && r <= cancelTag
}

// inSubdivisionFlag reports whether the tag character r between before
// and after belongs to one of [subdivisionFlags]: the black flag, then the
// tag characters of the sequence, then the cancel tag. Every tag of one
// run sees the same run, so a run is allowed or rejected whole.
func inSubdivisionFlag(before string, r rune, after string) bool {
	const longest = 6 // the tags of "gbeng", and the cancel tag
	var tags []rune
	for s := before; ; {
		p, size := utf8.DecodeLastRuneInString(s)
		if p == blackFlag {
			break
		}
		if size == 0 || !isTag(p) || p == cancelTag ||
			len(tags) == longest {
			return false
		}
		tags = append(tags, p)
		s = s[:len(s)-size]
	}
	slices.Reverse(tags)
	tags = append(tags, r)
	for _, n := range after {
		if r == cancelTag || tags[len(tags)-1] == cancelTag {
			break
		}
		if !isTag(n) || len(tags) == longest {
			return false
		}
		tags = append(tags, n)
	}
	if tags[len(tags)-1] != cancelTag {
		return false
	}
	var b strings.Builder
	for _, t := range tags[:len(tags)-1] {
		b.WriteRune(t - 0xE0000)
	}
	return slices.Contains(subdivisionFlags, b.String())
}

// beforeFinalVowel reports whether the Mongolian vowel separator between
// before and after follows a Mongolian letter, marks aside, and comes
// right before the vowel a or e, as traditional orthography writes a
// word-final a or e.
func beforeFinalVowel(before, after string) bool {
	p := lastBase(before)
	n, _ := utf8.DecodeRuneInString(after)
	return unicode.Is(unicode.Mongolian, p) && unicode.IsLetter(p) &&
		(n == '\u1820' || n == '\u1821')
}
