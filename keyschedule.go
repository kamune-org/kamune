package kamune

import (
	"crypto/hkdf"
	"crypto/sha512"
	"fmt"
)

const hashLen = 64

// hsKeys holds the handshake traffic keys derived from the hybrid secret and
// the transcript hash after the ServerHello.
type hsKeys struct {
	hs   []byte
	rKey []byte
	iKey []byte
	rFin []byte
	iFin []byte
}

// appSecrets holds the application keys and the values derived after the final
// transcript hash.
type appSecrets struct {
	iApp     []byte
	rApp     []byte
	exporter []byte
	resNext  []byte
	sid      []byte
}

// labelInfo builds the HkdfLabel bytes for Expand-Label.
// full is "kamune2 " plus label, and both full and ctx are at most 255 bytes.
func labelInfo(label string, ctx []byte, n int) ([]byte, error) {
	full := "kamune2 " + label
	if len(full) > 255 || len(ctx) > 255 || n < 0 || n > 65535 {
		return nil, fmt.Errorf("expand-label: length out of range")
	}
	info := make([]byte, 0, 4+len(full)+len(ctx))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(ctx)))
	info = append(info, ctx...)
	return info, nil
}

func expandLabel(
	secret []byte, label string, ctx []byte, n int,
) ([]byte, error) {
	info, err := labelInfo(label, ctx, n)
	if err != nil {
		return nil, err
	}
	out, err := hkdf.Expand(sha512.New, secret, string(info), n)
	if err != nil {
		return nil, fmt.Errorf("expand-label: %w", err)
	}
	return out, nil
}

func deriveSecret(secret []byte, label string, th []byte) ([]byte, error) {
	return expandLabel(secret, label, th, hashLen)
}

func scheduleHS(ss, thSH []byte) (hsKeys, error) {
	var zero hsKeys
	zeros := make([]byte, hashLen)
	hs, err := hkdf.Extract(sha512.New, ss, zeros)
	if err != nil {
		return zero, fmt.Errorf("extract hs: %w", err)
	}
	rHS, err := deriveSecret(hs, "r hs traffic", thSH)
	if err != nil {
		return zero, err
	}
	iHS, err := deriveSecret(hs, "i hs traffic", thSH)
	if err != nil {
		return zero, err
	}
	rKey, err := expandLabel(rHS, "key", nil, 32)
	if err != nil {
		return zero, err
	}
	iKey, err := expandLabel(iHS, "key", nil, 32)
	if err != nil {
		return zero, err
	}
	rFin, err := expandLabel(rHS, "finished", nil, hashLen)
	if err != nil {
		return zero, err
	}
	iFin, err := expandLabel(iHS, "finished", nil, hashLen)
	if err != nil {
		return zero, err
	}
	return hsKeys{hs: hs, rKey: rKey, iKey: iKey, rFin: rFin, iFin: iFin}, nil
}

func masterSecret(hs, psk []byte) ([]byte, error) {
	salt, err := expandLabel(hs, "derived", nil, hashLen)
	if err != nil {
		return nil, err
	}
	out, err := hkdf.Extract(sha512.New, psk, salt)
	if err != nil {
		return nil, fmt.Errorf("extract master: %w", err)
	}
	return out, nil
}

func confirmKey(master []byte) ([]byte, error) {
	return expandLabel(master, "r confirm", nil, hashLen)
}

func sessionSecrets(master, thFinal []byte) (appSecrets, error) {
	var zero appSecrets
	iAP, err := deriveSecret(master, "i ap traffic", thFinal)
	if err != nil {
		return zero, err
	}
	rAP, err := deriveSecret(master, "r ap traffic", thFinal)
	if err != nil {
		return zero, err
	}
	iApp, err := expandLabel(iAP, "key", nil, 32)
	if err != nil {
		return zero, err
	}
	rApp, err := expandLabel(rAP, "key", nil, 32)
	if err != nil {
		return zero, err
	}
	exporter, err := deriveSecret(master, "exp master", thFinal)
	if err != nil {
		return zero, err
	}
	resNext, err := deriveSecret(master, "res master", thFinal)
	if err != nil {
		return zero, err
	}
	sidFull, err := deriveSecret(master, "session id", thFinal)
	if err != nil {
		return zero, err
	}
	return appSecrets{
		iApp: iApp, rApp: rApp, exporter: exporter,
		resNext: resNext, sid: sidFull[:15],
	}, nil
}

func exportKeyingMaterial(
	expMaster []byte, label string, context []byte, n int,
) ([]byte, error) {
	if len(label) < 1 || len(label) > 200 || n < 1 || n > 16320 {
		return nil, ErrInvalidExport
	}
	secret, err := expandLabel(expMaster, label, nil, hashLen)
	if err != nil {
		return nil, err
	}
	sum := sha512.Sum512(context)
	return expandLabel(secret, "exporter", sum[:], n)
}
