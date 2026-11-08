package relayleg

import (
	"testing"
)

func FuzzAccept(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	psk, err := GeneratePSK()
	if err != nil {
		f.Fatal(err)
	}
	pk := key.PublicKey()
	chNo, err := prepareClient(ClientConfig{RelayKey: pk})
	if err != nil {
		f.Fatal(err)
	}
	chYes, err := prepareClient(ClientConfig{RelayKey: pk, PSK: &psk})
	if err != nil {
		f.Fatal(err)
	}
	kr := keyRequestFrame()
	f.Add(kr, chNo.ch, false)
	f.Add(kr, []byte(nil), false)
	f.Add(chNo.ch, []byte(nil), false)
	f.Add(chYes.ch, []byte(nil), true)
	f.Add([]byte("nope"), []byte("nope"), false)
	f.Add([]byte("nope"), []byte("nope"), true)
	f.Add([]byte(nil), []byte(nil), true)

	f.Fuzz(func(t *testing.T, first, second []byte, withPSK bool) {
		var sp *PSK
		if withPSK {
			cp := psk
			sp = &cp
		}
		rw := &scriptRW{reads: [][]byte{first, second}}
		_, _ = Accept(rw, ServerConfig{Key: key, PSK: sp})
		// A public relay answers KeyRequest and may then write
		// one more frame. Every other path writes at most one.
		if len(rw.writes) > 2 {
			t.Fatalf("wrote %d frames", len(rw.writes))
		}
		krOK := exact(first, typeKeyRequest, sizeKeyRequest)
		if len(rw.writes) == 2 && (withPSK || !krOK) {
			t.Fatalf("two responses, psk=%v key request=%v",
				withPSK, krOK)
		}
		if withPSK && !pskFrameOK(&psk, first) && rw.written() != 0 {
			t.Fatalf("psk relay wrote %d bytes", rw.written())
		}
		for _, w := range rw.writes {
			if len(w) > MaxHandshakeFrame {
				t.Fatalf("response is %d bytes", len(w))
			}
		}
	})
}

func FuzzInitiate(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	st, err := prepareClient(ClientConfig{RelayKey: key.PublicKey()})
	if err != nil {
		f.Fatal(err)
	}
	rw := &scriptRW{reads: [][]byte{st.ch}}
	if _, err := Accept(rw, ServerConfig{Key: key}); err != nil {
		f.Fatal(err)
	}
	if len(rw.writes) != 1 {
		f.Fatal("expected one server hello")
	}
	f.Add(rw.writes[0])
	f.Add(alertFrame(alertBadMessage))
	f.Add([]byte{magic0, magic1, 0x01, typeAlert, alertBadMessage})
	f.Add([]byte(nil))
	f.Add([]byte("garbage"))

	pk := key.PublicKey()
	f.Fuzz(func(t *testing.T, reply []byte) {
		rw := &scriptRW{reads: [][]byte{reply}}
		_, _ = Initiate(rw, ClientConfig{RelayKey: pk})
		if len(rw.writes) > 1 {
			t.Fatalf("client wrote %d frames", len(rw.writes))
		}
		for _, w := range rw.writes {
			if len(w) < headerLen || w[0] != magic0 || w[1] != magic1 {
				t.Fatalf("client wrote a record (%d bytes)", len(w))
			}
		}
	})
}
