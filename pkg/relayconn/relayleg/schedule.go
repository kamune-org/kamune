package relayleg

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
)

// Label strings from RFC 009 section 8. The prefix includes the
// trailing space. FullLabel is the prefix plus the short label.
const (
	labelPrefix   = "kamune relayleg v2 "
	prologueLabel = labelPrefix + "prologue"
	infoStatic    = labelPrefix + "static"
	infoEphemeral = labelPrefix + "ephemeral"
	exportContext = labelPrefix + "ss"

	ssLen   = 32
	macLen  = 32
	hashLen = sha512.Size
)

// expandLabel is ExpandLabel from RFC 009 section 8.
// HkdfLabel is uint16(L) || uint8(len(FullLabel)) || FullLabel ||
// uint8(len(Context)) || Context, and FullLabel is
// "kamune relayleg v2 " plus label.
func expandLabel(
	secret []byte, label string, context []byte, n int,
) ([]byte, error) {
	full := labelPrefix + label
	if len(full) > 255 || len(context) > 255 || n < 0 || n > 65535 {
		return nil, errors.New("expand-label: length out of range")
	}
	info := make([]byte, 0, 3+len(full)+len(context))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(sha512.New, secret, string(info), n)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func pskIKM(psk *PSK) []byte {
	ikm := make([]byte, macLen)
	if psk != nil {
		copy(ikm, psk[:])
	}
	return ikm
}

func earlySecret(psk *PSK) ([]byte, error) {
	var salt [hashLen]byte
	// Extract's secret argument is the ikm. The spec writes
	// HKDF-Extract(salt, ikm) with a salt of 64 zero bytes.
	return hkdf.Extract(sha512.New, pskIKM(psk), salt[:])
}

func sum(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func hmac32(key, msg []byte) []byte {
	m := hmac.New(sha512.New, key)
	_, _ = m.Write(msg)
	summed := m.Sum(nil)
	out := make([]byte, macLen)
	copy(out, summed[:macLen])
	return out
}

// binderValue is the section 8 binder: HMAC-SHA512(binder_key, TH1)
// truncated to 32 bytes. chPrefix is ClientHello without the binder.
func binderValue(es, chPrefix []byte) ([]byte, error) {
	key, err := expandLabel(es, "binder", nil, hashLen)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return hmac32(key, sum(chPrefix)), nil
}

// computeBinder is the binder for a ClientHello that already holds
// every byte before the binder field. The PSK may be nil, which uses
// 32 zero bytes as the ikm. The caller puts the result on the wire
// only when a PSK is in use.
func computeBinder(psk *PSK, ch []byte) ([]byte, error) {
	if len(ch) < binderOffset {
		return nil, errors.New("binder: short client hello")
	}
	es, err := earlySecret(psk)
	if err != nil {
		return nil, err
	}
	defer clear(es)
	return binderValue(es, ch[:binderOffset])
}

func finishedValue(hs, th2 []byte) ([]byte, error) {
	key, err := expandLabel(hs, "relay finished", nil, hashLen)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return hmac32(key, th2), nil
}

// recordKeys holds the two directional record keys and IVs.
// Channel copies them into the AEADs and then wipes this value.
type recordKeys struct {
	c2rKey [ssLen]byte
	r2cKey [ssLen]byte
	c2rIV  [nonceLen]byte
	r2cIV  [nonceLen]byte
}

func (k *recordKeys) wipe() {
	clear(k.c2rKey[:])
	clear(k.r2cKey[:])
	clear(k.c2rIV[:])
	clear(k.r2cIV[:])
}

func fillLabel(
	dst []byte, secret []byte, label string, ctx []byte,
) error {
	out, err := expandLabel(secret, label, ctx, len(dst))
	if err != nil {
		return err
	}
	copy(dst, out)
	clear(out)
	return nil
}

func trafficKeys(hs, th3 []byte) (recordKeys, error) {
	var keys recordKeys
	err := fillLabel(keys.c2rKey[:], hs, "c2r key", th3)
	if err != nil {
		return keys, err
	}
	err = fillLabel(keys.c2rIV[:], hs, "c2r iv", th3)
	if err != nil {
		return keys, err
	}
	err = fillLabel(keys.r2cKey[:], hs, "r2c key", th3)
	if err != nil {
		return keys, err
	}
	err = fillLabel(keys.r2cIV[:], hs, "r2c iv", th3)
	if err != nil {
		return keys, err
	}
	return keys, nil
}

// schedule derives the binder, finished_r and the record keys.
// ch is the full ClientHello, including its binder field. sh
// contributes only its prefix of finishedOffset bytes; finished_r
// is recomputed and used for TH3, so a stale trailer is ignored.
// A nil PSK uses 32 zero bytes as the early-secret ikm. The returned
// binder is the HMAC even then. The wire binder is zeros when the
// client has no PSK.
func schedule(
	psk *PSK, relayPK PublicKey, ch, sh, ssS, ssE []byte,
) (binder, finished, th3 []byte, keys recordKeys, err error) {
	if len(ch) != sizeClientHello || len(sh) < finishedOffset ||
		len(ssS) != ssLen || len(ssE) != ssLen {
		err = errors.New("schedule: bad input length")
		return binder, finished, th3, keys, err
	}
	var es, ss, hs, salt []byte
	defer func() {
		clear(es)
		clear(ss)
		clear(hs)
		clear(salt)
	}()

	th0 := sum([]byte(prologueLabel), relayPK[:])
	es, err = earlySecret(psk)
	if err != nil {
		return binder, finished, th3, keys, err
	}
	binder, err = binderValue(es, ch[:binderOffset])
	if err != nil {
		return binder, finished, th3, keys, err
	}

	salt, err = expandLabel(es, "derived", nil, hashLen)
	if err != nil {
		return binder, finished, th3, keys, err
	}
	ss, err = hkdf.Extract(sha512.New, ssS, salt)
	clear(salt)
	salt = nil
	if err != nil {
		return binder, finished, th3, keys, err
	}
	salt, err = expandLabel(ss, "derived", nil, hashLen)
	if err != nil {
		return binder, finished, th3, keys, err
	}
	hs, err = hkdf.Extract(sha512.New, ssE, salt)
	clear(salt)
	salt = nil
	if err != nil {
		return binder, finished, th3, keys, err
	}

	th2 := sum(th0, ch, sh[:finishedOffset])
	finished, err = finishedValue(hs, th2)
	if err != nil {
		return binder, finished, th3, keys, err
	}
	shFull := make([]byte, finishedOffset+finishedLen)
	copy(shFull, sh[:finishedOffset])
	copy(shFull[finishedOffset:], finished)
	th3 = sum(th0, ch, shFull)
	keys, err = trafficKeys(hs, th3)
	return binder, finished, th3, keys, err
}
