package fingerprint

const hex = "0123456789ABCDEF"

func Hex(b []byte) string {
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
