package fingerprint

import (
	"crypto/sha512"
	"strconv"
	"strings"
)

const (
	// numericGroups is the number of groups in a [Numeric] fingerprint.
	numericGroups = 8
	// numericGroupBytes is how many bytes of the hash make up one group.
	numericGroupBytes = 5
	// numericGroupDigits is the number of decimal digits in one group.
	numericGroupDigits = 5
	// numericGroupModulus is 10^numericGroupDigits.
	numericGroupModulus = 100000
)

// Numeric returns a fingerprint of b for people to compare when they verify
// a key: 40 decimal digits in eight groups of five, separated by spaces,
// such as "41642 86682 35305 82016 29480 54574 64229 44344".
//
// Each group is a 40-bit big-endian chunk of the SHA-512 of b, taken modulo
// 100000, so the fingerprint carries about 132.9 bits (8 × log2(100000)).
// Finding another key with the same fingerprint takes about 2^132 hashes,
// out of reach of any attacker, unlike [Emoji], which carries about 52.7
// bits. Both peers must compute it over the same bytes, such as the PKIX
// encoding of the key that the kamune protocol uses, for the values to
// match.
func Numeric(b []byte) string {
	sum := sha512.Sum512(b)
	var sb strings.Builder
	sb.Grow(numericGroups*(numericGroupDigits+1) - 1)
	for i := range numericGroups {
		chunk := sum[i*numericGroupBytes:][:numericGroupBytes]
		var v uint64
		for _, c := range chunk {
			v = v<<8 | uint64(c)
		}
		group := strconv.FormatUint(v%numericGroupModulus, 10)
		if i > 0 {
			sb.WriteByte(' ')
		}
		for range numericGroupDigits - len(group) {
			sb.WriteByte('0')
		}
		sb.WriteString(group)
	}
	return sb.String()
}
