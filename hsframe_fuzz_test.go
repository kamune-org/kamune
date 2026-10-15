package kamune

import "testing"

func FuzzParseClientHello(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, clientHelloSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _ = parseClientHello(b)
	})
}

func FuzzParseServerHello(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, serverHelloSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseServerHello(b)
	})
}

func FuzzParseAuthPlain(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, responderAuthPlain))
	f.Add(make([]byte, initiatorAuthPlain))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _ = parseResponderAuth(b)
		_, _, _, _, _ = parseInitiatorAuth(b)
	})
}

func FuzzParseConfirmPlain(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, confirmPlain))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _, _, _ = parseConfirm(b)
	})
}
