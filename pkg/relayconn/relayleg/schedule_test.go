package relayleg

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var updateVectors = flag.Bool(
	"update", false, "rewrite testdata/relayleg_v2.json",
)

func TestLabelStrings(t *testing.T) {
	a := require.New(t)
	a.Equal("kamune relayleg v2 ", labelPrefix)
	a.Equal("kamune relayleg v2 prologue", prologueLabel)
	a.Equal("kamune relayleg v2 static", infoStatic)
	a.Equal("kamune relayleg v2 ephemeral", infoEphemeral)
	a.Equal("kamune relayleg v2 ss", exportContext)
	a.Equal(64, hashLen)
	a.Equal(32, ssLen)
}

type vectorCase struct {
	Name        string `json:"name"`
	PSK         string `json:"psk"`
	RelayPK     string `json:"relay_pk"`
	ClientHello string `json:"client_hello"`
	ServerHello string `json:"server_hello"`
	SSS         string `json:"ss_s"`
	SSE         string `json:"ss_e"`
	Binder      string `json:"binder"`
	FinishedR   string `json:"finished_r"`
	TH3         string `json:"th3"`
	C2RKey      string `json:"c2r_key"`
	C2RIV       string `json:"c2r_iv"`
	R2CKey      string `json:"r2c_key"`
	R2CIV       string `json:"r2c_iv"`
}

func vectorPath() string {
	return filepath.Join("testdata", "relayleg_v2.json")
}

func buildVectors(t *testing.T) []vectorCase {
	t.Helper()
	a := require.New(t)
	specs := []struct {
		name string
		fill byte
		psk  bool
	}{
		{name: "psk", fill: 0x5a, psk: true},
		{name: "none", fill: 0x3c, psk: false},
	}
	out := make([]vectorCase, 0, len(specs))
	for _, sp := range specs {
		var pk PublicKey
		for i := range pk {
			pk[i] = sp.fill + byte(i) + 1
		}
		var psk *PSK
		pskHex := ""
		if sp.psk {
			var p PSK
			for i := range p {
				p[i] = 0x11 + byte(i)
			}
			psk = &p
			pskHex = hex.EncodeToString(p[:])
		}
		ch := bytes.Repeat([]byte{sp.fill}, sizeClientHello)
		sh := bytes.Repeat([]byte{sp.fill ^ 0xff}, sizeServerHello)
		putHeader(ch, typeClientHello)
		putHeader(sh, typeServerHello)
		if sp.psk {
			ch[flagOffset] = pskFlag
		}
		hint := KeyHint(pk)
		copy(ch[hintOffset:], hint[:])
		clear(ch[binderOffset:])
		clear(sh[finishedOffset:])
		ssS := bytes.Repeat([]byte{sp.fill + 1}, ssLen)
		ssE := bytes.Repeat([]byte{sp.fill + 2}, ssLen)
		if sp.psk {
			b, err := computeBinder(psk, ch)
			a.NoError(err)
			copy(ch[binderOffset:], b)
		}
		binder, fin, th3, keys, err := schedule(
			psk, pk, ch, sh, ssS, ssE,
		)
		a.NoError(err)
		copy(sh[finishedOffset:], fin)
		out = append(out, vectorCase{
			Name:        sp.name,
			PSK:         pskHex,
			RelayPK:     hex.EncodeToString(pk[:]),
			ClientHello: hex.EncodeToString(ch),
			ServerHello: hex.EncodeToString(sh),
			SSS:         hex.EncodeToString(ssS),
			SSE:         hex.EncodeToString(ssE),
			Binder:      hex.EncodeToString(binder),
			FinishedR:   hex.EncodeToString(fin),
			TH3:         hex.EncodeToString(th3),
			C2RKey:      hex.EncodeToString(keys.c2rKey[:]),
			C2RIV:       hex.EncodeToString(keys.c2rIV[:]),
			R2CKey:      hex.EncodeToString(keys.r2cKey[:]),
			R2CIV:       hex.EncodeToString(keys.r2cIV[:]),
		})
	}
	return out
}

func saveVectors(t *testing.T, cases []vectorCase) {
	t.Helper()
	a := require.New(t)
	raw, err := json.MarshalIndent(cases, "", "  ")
	a.NoError(err)
	raw = append(raw, '\n')
	a.NoError(os.MkdirAll("testdata", 0o755))
	a.NoError(os.WriteFile(vectorPath(), raw, 0o644))
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	a := require.New(t)
	raw, err := os.ReadFile(vectorPath())
	a.NoError(err)
	var cases []vectorCase
	a.NoError(json.Unmarshal(raw, &cases))
	a.NotEmpty(cases)
	return cases
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	require.New(t).NoError(err)
	return b
}

func pskFromHex(t *testing.T, s string) *PSK {
	t.Helper()
	if s == "" {
		return nil
	}
	raw := decodeHex(t, s)
	require.New(t).Len(raw, 32)
	var p PSK
	copy(p[:], raw)
	return &p
}

func TestScheduleVectors(t *testing.T) {
	if *updateVectors {
		saveVectors(t, buildVectors(t))
	}
	a := require.New(t)
	for _, c := range loadVectors(t) {
		t.Run(c.Name, func(t *testing.T) {
			a := require.New(t)
			psk := pskFromHex(t, c.PSK)
			var pk PublicKey
			copy(pk[:], decodeHex(t, c.RelayPK))
			ch := decodeHex(t, c.ClientHello)
			sh := decodeHex(t, c.ServerHello)
			ssS := decodeHex(t, c.SSS)
			ssE := decodeHex(t, c.SSE)
			binder, fin, th3, keys, err := schedule(
				psk, pk, ch, sh, ssS, ssE,
			)
			a.NoError(err)
			a.Equal(decodeHex(t, c.Binder), binder)
			a.Equal(decodeHex(t, c.FinishedR), fin)
			a.Equal(decodeHex(t, c.TH3), th3)
			a.Equal(decodeHex(t, c.C2RKey), keys.c2rKey[:])
			a.Equal(decodeHex(t, c.C2RIV), keys.c2rIV[:])
			a.Equal(decodeHex(t, c.R2CKey), keys.r2cKey[:])
			a.Equal(decodeHex(t, c.R2CIV), keys.r2cIV[:])
			a.Equal(fin, sh[finishedOffset:])
			if psk == nil {
				a.True(isZero(ch[binderOffset:]))
			} else {
				a.Equal(binder, ch[binderOffset:])
			}
		})
	}
	a.NotEmpty(loadVectors(t))
}

// TestScheduleMatchesFormula recomputes section 8 with crypto/hkdf
// and crypto/hmac, not with expandLabel or schedule, and checks the
// vector file against that result.
func TestScheduleMatchesFormula(t *testing.T) {
	for _, c := range loadVectors(t) {
		t.Run(c.Name, func(t *testing.T) {
			checkFormula(t, c)
		})
	}
}

func checkFormula(t *testing.T, c vectorCase) {
	t.Helper()
	a := require.New(t)
	psk := pskFromHex(t, c.PSK)
	pk := decodeHex(t, c.RelayPK)
	ch := decodeHex(t, c.ClientHello)
	sh := decodeHex(t, c.ServerHello)
	ssS := decodeHex(t, c.SSS)
	ssE := decodeHex(t, c.SSE)
	a.Len(pk, 32)
	a.Len(ch, sizeClientHello)
	a.Len(sh, sizeServerHello)

	ikm := make([]byte, 32)
	if psk != nil {
		copy(ikm, psk[:])
	}
	var salt0 [64]byte
	// Go's Extract takes (hash, secret, salt). The spec writes
	// HKDF-Extract(salt, ikm). secret is the ikm.
	es, err := hkdf.Extract(sha512.New, ikm, salt0[:])
	a.NoError(err)

	th0 := specHash([]byte("kamune relayleg v2 prologue"), pk)
	th1 := specHash(ch[:binderOffset])
	binderKey := specExpand(t, es, "binder", nil, 64)
	binder := specHMAC(binderKey, th1)
	a.Equal(decodeHex(t, c.Binder), binder)

	derived := specExpand(t, es, "derived", nil, 64)
	ss, err := hkdf.Extract(sha512.New, ssS, derived)
	a.NoError(err)
	derived = specExpand(t, ss, "derived", nil, 64)
	hs, err := hkdf.Extract(sha512.New, ssE, derived)
	a.NoError(err)

	th2 := specHash(th0, ch, sh[:finishedOffset])
	fk := specExpand(t, hs, "relay finished", nil, 64)
	finished := specHMAC(fk, th2)
	a.Equal(decodeHex(t, c.FinishedR), finished)
	a.Equal(finished, sh[finishedOffset:])

	th3 := specHash(th0, ch, sh)
	a.Equal(decodeHex(t, c.TH3), th3)
	a.Equal(decodeHex(t, c.C2RKey), specExpand(t, hs, "c2r key", th3, 32))
	a.Equal(decodeHex(t, c.C2RIV), specExpand(t, hs, "c2r iv", th3, 24))
	a.Equal(decodeHex(t, c.R2CKey), specExpand(t, hs, "r2c key", th3, 32))
	a.Equal(decodeHex(t, c.R2CIV), specExpand(t, hs, "r2c iv", th3, 24))

	if psk == nil {
		a.True(isZero(ch[binderOffset:]))
	} else {
		a.Equal(binder, ch[binderOffset:])
	}
}

func specExpand(
	t *testing.T, secret []byte, label string, context []byte, n int,
) []byte {
	t.Helper()
	a := require.New(t)
	full := "kamune relayleg v2 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(full))}
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(sha512.New, secret, string(info), n)
	a.NoError(err)
	a.Len(out, n)
	return out
}

func specHMAC(key, msg []byte) []byte {
	m := hmac.New(sha512.New, key)
	_, _ = m.Write(msg)
	summed := m.Sum(nil)
	out := make([]byte, 32)
	copy(out, summed[:32])
	return out
}

func specHash(parts ...[]byte) []byte {
	summed := sha512.Sum512(bytes.Join(parts, nil))
	return append([]byte(nil), summed[:]...)
}
