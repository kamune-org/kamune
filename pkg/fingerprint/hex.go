package fingerprint

const hex = "0123456789ABCDEF"

// Hex returns an uppercase colon-separated hex representation of b
// (e.g. "AB:CD:EF"). For the PKIX encoding of an Ed25519 key, as the kamune
// protocol uses, the first 12 bytes are the same for every key; only the
// last 32, the raw key, tell keys apart. To verify a key, compare [Numeric].
func Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := make([]byte, len(b)*3-1)
	for i, v := range b {
		pos := i * 3
		s[pos] = hex[v>>4]
		s[pos+1] = hex[v&0x0F]
		if i != len(b)-1 {
			s[pos+2] = ':'
		}
	}
	return string(s)
}
