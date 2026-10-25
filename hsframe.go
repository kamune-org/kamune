package kamune

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"fmt"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
)

const (
	protocolVersion = 0x02

	frameClientHello   = 0x01
	frameServerHello   = 0x02
	frameResponderAuth = 0x03
	frameInitiatorAuth = 0x04
	frameConfirm       = 0x05

	clientHelloSize   = 1282
	serverHelloSize   = 1154
	responderAuthSize = 214
	initiatorAuthSize = 426
	confirmFrameSize  = 234

	responderAuthPlain = 172
	initiatorAuthPlain = 384
	confirmPlain       = 192

	helloNonceLen   = 32
	hsNonceLen      = 24
	xwingPKLen      = 1216
	xwingEncLen     = 1120
	pkixLen         = 44
	finishedLen     = 64
	maxNameLen      = 64
	maxVersionLen   = 32
	resumeSIDLen    = 24
	confirmCold     = 1
	confirmResumed  = 2
	confirmRejected = 3
	reasonVerifier  = 1
	reasonVersion   = 2
)

var (
	pkixPrefix = []byte{
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
		0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
	}
	hsADPrefix = []byte("kamune/2 hs")
)

// initiatorBlock is the initiator identity the transcript hashes, with each
// field already separated from its length prefix.
type initiatorBlock struct {
	Key       []byte
	Name      []byte
	Version   []byte
	ResumeSID []byte
}

func writeClientHello(dst, nonce, tag, pk []byte) ([]byte, error) {
	if len(nonce) != helloNonceLen || len(tag) != helloNonceLen ||
		len(pk) != xwingPKLen {
		return nil, fmt.Errorf("%w: client hello", ErrInvalidHandshake)
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(pk); err != nil {
		return nil, fmt.Errorf(
			"%w: ephemeral key: %w", ErrInvalidHandshake, err,
		)
	}
	out := append(dst, protocolVersion, frameClientHello)
	out = append(out, nonce...)
	out = append(out, tag...)
	out = append(out, pk...)
	return out, nil
}

func parseClientHello(f []byte) (nonce, tag, pk []byte, err error) {
	if len(f) != clientHelloSize {
		return nil, nil, nil, fmt.Errorf(
			"%w: client hello length %d", ErrInvalidHandshake, len(f),
		)
	}
	if err = checkVer(f[0]); err != nil {
		return nil, nil, nil, err
	}
	if f[1] != frameClientHello {
		return nil, nil, nil, fmt.Errorf(
			"%w: client hello type %d", ErrInvalidHandshake, f[1],
		)
	}
	if _, err = hpke.MLKEM768X25519().NewPublicKey(f[66:]); err != nil {
		return nil, nil, nil, fmt.Errorf(
			"%w: ephemeral key: %w", ErrInvalidHandshake, err,
		)
	}
	return f[2:34], f[34:66], f[66:], nil
}

func writeServerHello(dst, nonce, enc []byte) ([]byte, error) {
	if len(nonce) != helloNonceLen || len(enc) != xwingEncLen {
		return nil, fmt.Errorf("%w: server hello", ErrInvalidHandshake)
	}
	out := append(dst, protocolVersion, frameServerHello)
	out = append(out, nonce...)
	out = append(out, enc...)
	return out, nil
}

func parseServerHello(f []byte) (nonce, enc []byte, err error) {
	if len(f) != serverHelloSize {
		return nil, nil, fmt.Errorf(
			"%w: server hello length %d", ErrInvalidHandshake, len(f),
		)
	}
	if err = checkVer(f[0]); err != nil {
		return nil, nil, err
	}
	if f[1] != frameServerHello {
		return nil, nil, fmt.Errorf(
			"%w: server hello type %d", ErrInvalidHandshake, f[1],
		)
	}
	return f[2:34], f[34:], nil
}

func sealHS(key, plaintext []byte, ver, typ byte) ([]byte, error) {
	e, err := enigma.NewFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHandshake, err)
	}
	nonce := make([]byte, hsNonceLen)
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("handshake nonce: %w", err)
	}
	ct, err := e.Seal(nonce, plaintext, hsAD(ver, typ))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHandshake, err)
	}
	out := make([]byte, 0, 2+hsNonceLen+len(ct))
	out = append(out, ver, typ)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func openHS(key, frame []byte, typ byte) ([]byte, error) {
	plain, err := hsPlainSize(typ)
	if err != nil {
		return nil, err
	}
	if len(frame) != 2+hsNonceLen+plain+16 {
		return nil, fmt.Errorf(
			"%w: handshake length %d", ErrInvalidHandshake, len(frame),
		)
	}
	if err = checkVer(frame[0]); err != nil {
		return nil, err
	}
	if frame[1] != typ {
		return nil, fmt.Errorf(
			"%w: handshake type %d", ErrInvalidHandshake, frame[1],
		)
	}
	e, err := enigma.NewFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHandshake, err)
	}
	pt, err := e.Open(frame[2:2+hsNonceLen], frame[2+hsNonceLen:], hsAD(
		frame[0], frame[1],
	))
	if err != nil {
		return nil, ErrVerificationFailed
	}
	return pt, nil
}

func encodeResponderAuth(keyR, sigR, finR []byte) ([]byte, error) {
	if err := checkIdentityKey(keyR); err != nil {
		return nil, err
	}
	if len(sigR) != finishedLen || len(finR) != finishedLen {
		return nil, fmt.Errorf("%w: responder auth", ErrInvalidHandshake)
	}
	out := make([]byte, 0, responderAuthPlain)
	out = append(out, keyR...)
	out = append(out, sigR...)
	out = append(out, finR...)
	return out, nil
}

func parseResponderAuth(p []byte) (keyR, sigR, finR []byte, err error) {
	if len(p) != responderAuthPlain {
		return nil, nil, nil, fmt.Errorf(
			"%w: responder auth length %d", ErrInvalidHandshake, len(p),
		)
	}
	if err = checkIdentityKey(p[:pkixLen]); err != nil {
		return nil, nil, nil, err
	}
	sigR = p[pkixLen : pkixLen+finishedLen]
	finR = p[pkixLen+finishedLen:]
	return p[:pkixLen], sigR, finR, nil
}

func encodeInitiatorAuth(
	id initiatorBlock, binder, sigI, finI []byte,
) ([]byte, error) {
	block, err := encodeIdentity(id)
	if err != nil {
		return nil, err
	}
	if len(sigI) != finishedLen || len(finI) != finishedLen {
		return nil, fmt.Errorf("%w: initiator auth", ErrInvalidHandshake)
	}
	if len(id.ResumeSID) == resumeSIDLen {
		if len(binder) != finishedLen {
			return nil, fmt.Errorf("%w: binder", ErrInvalidHandshake)
		}
	} else if len(binder) != 0 {
		return nil, fmt.Errorf("%w: binder", ErrInvalidHandshake)
	}
	out := make([]byte, initiatorAuthPlain)
	n := copy(out, block)
	if len(binder) != 0 {
		n += copy(out[n:], binder)
	}
	n += copy(out[n:], sigI)
	copy(out[n:], finI)
	return out, nil
}

func parseInitiatorAuth(
	p []byte,
) (id initiatorBlock, binder, sigI, finI []byte, err error) {
	if len(p) != initiatorAuthPlain {
		return id, nil, nil, nil, fmt.Errorf(
			"%w: initiator auth length %d", ErrInvalidHandshake, len(p),
		)
	}
	rest := p
	if len(rest) < pkixLen {
		return id, nil, nil, nil, fmt.Errorf(
			"%w: initiator auth", ErrInvalidHandshake,
		)
	}
	key := rest[:pkixLen]
	rest = rest[pkixLen:]
	if err = checkIdentityKey(key); err != nil {
		return id, nil, nil, nil, err
	}
	name, n, err := readStr8(rest, maxNameLen)
	if err != nil {
		return id, nil, nil, nil, err
	}
	rest = rest[n:]
	version, n, err := readStr8(rest, maxVersionLen)
	if err != nil {
		return id, nil, nil, nil, err
	}
	rest = rest[n:]
	sid, n, err := readStr8(rest, resumeSIDLen)
	if err != nil {
		return id, nil, nil, nil, err
	}
	rest = rest[n:]
	if err = checkIdentityFields(name, version, sid); err != nil {
		return id, nil, nil, nil, err
	}
	if len(sid) == resumeSIDLen {
		if len(rest) < finishedLen {
			return id, nil, nil, nil, fmt.Errorf(
				"%w: binder", ErrInvalidHandshake,
			)
		}
		binder = rest[:finishedLen]
		rest = rest[finishedLen:]
	}
	if len(rest) < 2*finishedLen {
		return id, nil, nil, nil, fmt.Errorf(
			"%w: initiator auth", ErrInvalidHandshake,
		)
	}
	sigI = rest[:finishedLen]
	finI = rest[finishedLen : 2*finishedLen]
	if err = checkZero(rest[2*finishedLen:]); err != nil {
		return id, nil, nil, nil, err
	}
	id = initiatorBlock{
		Key: key, Name: name, Version: version, ResumeSID: sid,
	}
	return id, binder, sigI, finI, nil
}

func encodeConfirm(
	status, reason byte, name, version string, finC []byte,
) ([]byte, error) {
	if err := checkConfirm(status, reason, name, version); err != nil {
		return nil, err
	}
	if len(finC) != finishedLen {
		return nil, fmt.Errorf("%w: confirm", ErrInvalidHandshake)
	}
	body, err := encodeConfirmBody(status, reason, name, version)
	if err != nil {
		return nil, err
	}
	out := make([]byte, confirmPlain)
	n := copy(out, body)
	copy(out[n:], finC)
	return out, nil
}

func parseConfirm(
	p []byte,
) (status, reason byte, name, version string, finC []byte, err error) {
	if len(p) != confirmPlain {
		return 0, 0, "", "", nil, fmt.Errorf(
			"%w: confirm length %d", ErrInvalidHandshake, len(p),
		)
	}
	status, reason = p[0], p[1]
	rest := p[2:]
	nb, n, err := readStr8(rest, maxNameLen)
	if err != nil {
		return 0, 0, "", "", nil, err
	}
	rest = rest[n:]
	vb, n, err := readStr8(rest, maxVersionLen)
	if err != nil {
		return 0, 0, "", "", nil, err
	}
	rest = rest[n:]
	if len(rest) < finishedLen {
		return 0, 0, "", "", nil, fmt.Errorf("%w: confirm", ErrInvalidHandshake)
	}
	finC = rest[:finishedLen]
	if err = checkZero(rest[finishedLen:]); err != nil {
		return 0, 0, "", "", nil, err
	}
	name, version = string(nb), string(vb)
	return status, reason, name, version, finC, nil
}

func encodeIdentity(id initiatorBlock) ([]byte, error) {
	if err := checkIdentityKey(id.Key); err != nil {
		return nil, err
	}
	if err := checkIdentityFields(
		id.Name, id.Version, id.ResumeSID,
	); err != nil {
		return nil, err
	}
	out := make([]byte, 0, pkixLen+maxNameLen+maxVersionLen+resumeSIDLen+3)
	out = append(out, id.Key...)
	var err error
	out, err = appendStr8(out, id.Name, maxNameLen)
	if err != nil {
		return nil, err
	}
	out, err = appendStr8(out, id.Version, maxVersionLen)
	if err != nil {
		return nil, err
	}
	return appendStr8(out, id.ResumeSID, resumeSIDLen)
}

func encodeConfirmBody(
	status, reason byte, name, version string,
) ([]byte, error) {
	out := make([]byte, 0, 2+maxNameLen+maxVersionLen+2)
	out = append(out, status, reason)
	var err error
	out, err = appendStr8(out, []byte(name), maxNameLen)
	if err != nil {
		return nil, err
	}
	return appendStr8(out, []byte(version), maxVersionLen)
}

func checkIdentityFields(name, version, sid []byte) error {
	if err := ValidatePeerName(string(name)); err != nil {
		return err
	}
	if _, err := parseSemver(string(version)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHandshake, err)
	}
	return checkResumeSID(sid)
}

func checkResumeSID(sid []byte) error {
	if len(sid) == 0 {
		return nil
	}
	if len(sid) != resumeSIDLen {
		return fmt.Errorf("%w: resume sid", ErrInvalidHandshake)
	}
	for _, c := range sid {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return fmt.Errorf("%w: resume sid", ErrInvalidHandshake)
		}
	}
	return nil
}

func checkConfirm(status, reason byte, name, version string) error {
	if err := checkConfirmStatus(status, reason, name, version); err != nil {
		return err
	}
	if status == confirmRejected {
		return nil
	}
	if err := ValidatePeerName(name); err != nil {
		return err
	}
	if _, err := parseSemver(version); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHandshake, err)
	}
	return nil
}

// checkConfirmStatus checks the status and reason. Name and version are checked
// after finished_C, by the caller, so a bad MAC is not hidden.
func checkConfirmStatus(status, reason byte, name, version string) error {
	switch status {
	case confirmCold, confirmResumed:
		if reason != 0 {
			return fmt.Errorf("%w: confirm reason", ErrInvalidHandshake)
		}
	case confirmRejected:
		if reason != reasonVerifier && reason != reasonVersion {
			return fmt.Errorf("%w: confirm reason", ErrInvalidHandshake)
		}
		if name != "" || version != "" {
			return fmt.Errorf("%w: rejected confirm", ErrInvalidHandshake)
		}
	default:
		return fmt.Errorf("%w: confirm status", ErrInvalidHandshake)
	}
	return nil
}

func checkIdentityKey(k []byte) error {
	if len(k) != pkixLen || !bytes.HasPrefix(k, pkixPrefix) ||
		!attest.IsValidPublicKey(k) {
		return fmt.Errorf("%w: identity key", ErrInvalidHandshake)
	}
	return nil
}

func checkVer(v byte) error {
	if v != protocolVersion {
		return fmt.Errorf("%w: version %d", ErrUnsupportedProtocol, v)
	}
	return nil
}

func hsPlainSize(typ byte) (int, error) {
	switch typ {
	case frameResponderAuth:
		return responderAuthPlain, nil
	case frameInitiatorAuth:
		return initiatorAuthPlain, nil
	case frameConfirm:
		return confirmPlain, nil
	default:
		return 0, fmt.Errorf("%w: type %d", ErrInvalidHandshake, typ)
	}
}

func hsAD(ver, typ byte) []byte {
	ad := make([]byte, 0, len(hsADPrefix)+2)
	ad = append(ad, hsADPrefix...)
	return append(ad, ver, typ)
}

func appendStr8(dst, s []byte, max int) ([]byte, error) {
	if len(s) > max {
		return nil, fmt.Errorf(
			"%w: string length %d", ErrInvalidHandshake, len(s),
		)
	}
	dst = append(dst, byte(len(s)))
	return append(dst, s...), nil
}

func readStr8(p []byte, max int) (s []byte, n int, err error) {
	if len(p) < 1 {
		return nil, 0, fmt.Errorf("%w: short string", ErrInvalidHandshake)
	}
	n = int(p[0])
	if n > max || len(p) < 1+n {
		return nil, 0, fmt.Errorf(
			"%w: string length %d", ErrInvalidHandshake, n,
		)
	}
	return p[1 : 1+n], 1 + n, nil
}

func checkZero(p []byte) error {
	for _, b := range p {
		if b != 0 {
			return fmt.Errorf("%w: padding", ErrInvalidHandshake)
		}
	}
	return nil
}
