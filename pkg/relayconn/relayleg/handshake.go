package relayleg

import (
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

// ClientConfig is the client's handshake input.
// RelayKey is the static key the client encapsulates to.
// PSK is the access key, or nil when the client has none.
type ClientConfig struct {
	PSK      *PSK
	RelayKey PublicKey
}

// ServerConfig is the relay's handshake input.
// Key is the relay static key and must be non-nil.
// PSK is the access key, or nil when the relay is public.
type ServerConfig struct {
	Key *PrivateKey
	PSK *PSK
}

// clientKeyHint is the hint written into ClientHello.
// Tests replace it so two different keys can share a hint.
// Tests that replace it must not call t.Parallel.
var clientKeyHint = KeyHint

// clientState is the client after ClientHello is built and before
// ServerHello is accepted. finish is the C2 step. The ephemeral
// key and ss_s stay here only until the channel exists. Channel
// does not keep them.
type clientState struct {
	eph hpke.PrivateKey
	ch  []byte
	ssS []byte
	cfg ClientConfig
}

// FetchKey runs C0. It sends KeyRequest and reads one frame.
// A KeyResponse returns the relay key. An all-zero key is
// ErrInvalidRelayKey. An alert returns its typed error. EOF or
// a close is ErrHandshakeRejected. Any other frame is
// ErrBadMessage.
func FetchKey(rw ReadWriter) (PublicKey, error) {
	var zero PublicKey
	err := rw.WriteBytes(keyRequestFrame())
	if err != nil {
		return zero, fmt.Errorf("write key request: %w", err)
	}
	frame, err := readRelay(rw)
	if err != nil {
		return zero, err
	}
	return takeKeyResponse(frame)
}

func takeKeyResponse(frame []byte) (PublicKey, error) {
	var zero PublicKey
	typ, err := classify(frame)
	if err != nil {
		return zero, err
	}
	switch typ {
	case typeKeyResponse:
		if len(frame) != sizeKeyResponse {
			return zero, ErrBadMessage
		}
		var pk PublicKey
		copy(pk[:], frame[headerLen:])
		if pk == zero {
			return zero, ErrInvalidRelayKey
		}
		return pk, nil
	case typeAlert:
		return zero, alertError(frame)
	default:
		return zero, ErrBadMessage
	}
}

// Initiate runs C1 through C3.
// Encapsulation failure, including a low-order relay key, returns
// ErrInvalidRelayKey and writes nothing. A ServerHello whose
// finished_r does not match returns ErrRelayAuthFailed.
func Initiate(rw ReadWriter, cfg ClientConfig) (*Channel, error) {
	st, err := prepareClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := rw.WriteBytes(st.ch); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	frame, err := readRelay(rw)
	if err != nil {
		return nil, err
	}
	return st.finish(rw, frame)
}

func prepareClient(cfg ClientConfig) (*clientState, error) {
	eph, ephPK, err := newEphemeral()
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	enc, ss, err := sealStatic(cfg.RelayKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRelayKey, err)
	}
	ch, err := buildClientHello(cfg, enc, ephPK)
	if err != nil {
		clear(ss)
		return nil, err
	}
	st := &clientState{cfg: cfg, ch: ch, ssS: ss, eph: eph}
	return st, nil
}

func buildClientHello(
	cfg ClientConfig, enc, ephPK []byte,
) ([]byte, error) {
	if len(enc) != encSLen || len(ephPK) != ephPKLen {
		return nil, fmt.Errorf(
			"handshake: enc %d bytes, eph %d bytes",
			len(enc), len(ephPK),
		)
	}
	ch := make([]byte, sizeClientHello)
	putHeader(ch, typeClientHello)
	if cfg.PSK != nil {
		ch[flagOffset] = pskFlag
	}
	hint := clientKeyHint(cfg.RelayKey)
	copy(ch[hintOffset:], hint[:])
	copy(ch[encSOffset:], enc)
	copy(ch[ephOffset:], ephPK)
	if cfg.PSK == nil {
		return ch, nil
	}
	b, err := computeBinder(cfg.PSK, ch)
	if err != nil {
		return nil, fmt.Errorf("binder: %w", err)
	}
	copy(ch[binderOffset:], b)
	clear(b)
	return ch, nil
}

// finish is the client's C2 step for a frame already read.
// Tests reuse one clientState across ServerHello bit flips.
func (st *clientState) finish(
	rw ReadWriter, frame []byte,
) (*Channel, error) {
	typ, err := classify(frame)
	if err != nil {
		return nil, err
	}
	switch typ {
	case typeServerHello:
		if len(frame) != sizeServerHello {
			return nil, ErrBadMessage
		}
		return st.openHello(rw, frame)
	case typeAlert:
		return nil, alertError(frame)
	default:
		return nil, ErrBadMessage
	}
}

func (st *clientState) openHello(
	rw ReadWriter, sh []byte,
) (*Channel, error) {
	encE := sh[encEOffset : encEOffset+encELen]
	ssE, err := openEphemeral(st.eph, encE)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadMessage, err)
	}
	defer clear(ssE)
	_, fin, _, keys, err := schedule(
		st.cfg.PSK, st.cfg.RelayKey, st.ch, sh, st.ssS, ssE,
	)
	if err != nil {
		keys.wipe()
		return nil, err
	}
	match := subtle.ConstantTimeCompare(fin, sh[finishedOffset:])
	clear(fin)
	if match != 1 {
		keys.wipe()
		return nil, ErrRelayAuthFailed
	}
	return newChannel(rw, &keys, true)
}

// Accept runs S0 through S2.
// A relay with a PSK writes nothing and returns ErrSilentReject
// unless the first frame is a ClientHello with the PSK flag, zero
// reserved bits and a valid binder. The binder is one HMAC and is
// checked before any KEM operation. A read error is returned as
// itself and nothing is written.
//
// A relay without a PSK answers KeyRequest with KeyResponse, then
// reads a ClientHello. Any other frame in S0 or S1 sends alert 1.
// In S2, reserved flag bits and a non-zero binder with the flag
// clear send alert 1, the PSK flag sends alert 2, and a key hint
// that is not KeyHint of the relay key sends alert 3. A failed
// decapsulation or encapsulation sends alert 1.
// After an alert, Accept returns the error the alert maps to.
func Accept(rw ReadWriter, cfg ServerConfig) (*Channel, error) {
	if cfg.Key == nil {
		return nil, fmt.Errorf("%w: nil", ErrInvalidRelayKey)
	}
	frame, err := rw.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	if cfg.PSK != nil {
		if !pskFrameOK(cfg.PSK, frame) {
			return nil, ErrSilentReject
		}
		return acceptHello(rw, cfg, frame)
	}
	if exact(frame, typeKeyRequest, sizeKeyRequest) {
		err := writeKeyResponse(rw, cfg.Key.PublicKey())
		if err != nil {
			return nil, err
		}
		next, err := rw.ReadBytes()
		if err != nil {
			return nil, fmt.Errorf("read handshake: %w", err)
		}
		if !exact(next, typeClientHello, sizeClientHello) {
			return nil, sendAlert(rw, alertBadMessage)
		}
		return acceptHello(rw, cfg, next)
	}
	if exact(frame, typeClientHello, sizeClientHello) {
		return acceptHello(rw, cfg, frame)
	}
	return nil, sendAlert(rw, alertBadMessage)
}

// pskFrameOK is the S0 gate for a relay that holds a PSK.
// It is one HMAC over the ClientHello prefix and does no KEM work.
func pskFrameOK(psk *PSK, frame []byte) bool {
	if psk == nil || !exact(frame, typeClientHello, sizeClientHello) {
		return false
	}
	if frame[flagOffset] != pskFlag {
		return false
	}
	return binderMatches(psk, frame)
}

// binderMatches reports whether ch's binder field is the HMAC
// from section 8 for psk. ch must be a full ClientHello.
func binderMatches(psk *PSK, ch []byte) bool {
	if psk == nil || len(ch) != sizeClientHello {
		return false
	}
	got, err := computeBinder(psk, ch)
	if err != nil {
		return false
	}
	same := subtle.ConstantTimeCompare(got, ch[binderOffset:])
	clear(got)
	return same == 1
}

func acceptHello(
	rw ReadWriter, cfg ServerConfig, ch []byte,
) (*Channel, error) {
	if cfg.PSK == nil {
		flags := ch[flagOffset]
		if flags&^byte(pskFlag) != 0 {
			return nil, sendAlert(rw, alertBadMessage)
		}
		if flags&pskFlag != 0 {
			return nil, sendAlert(rw, alertPSKUnexpected)
		}
		if !isZero(ch[binderOffset:]) {
			return nil, sendAlert(rw, alertBadMessage)
		}
	}
	pk := cfg.Key.PublicKey()
	want := KeyHint(pk)
	gotHint := ch[hintOffset : hintOffset+hintLen]
	if subtle.ConstantTimeCompare(gotHint, want[:]) != 1 {
		return nil, sendAlert(rw, alertUnknownKey)
	}
	encS := ch[encSOffset : encSOffset+encSLen]
	ssS, err := openStatic(cfg.Key, encS)
	if err != nil {
		return nil, sendAlert(rw, alertBadMessage)
	}
	defer clear(ssS)
	ephPK := ch[ephOffset:binderOffset]
	encE, ssE, err := sealEphemeral(ephPK)
	if err != nil {
		return nil, sendAlert(rw, alertBadMessage)
	}
	defer clear(ssE)
	if len(encE) != encELen {
		return nil, sendAlert(rw, alertBadMessage)
	}
	sh := make([]byte, sizeServerHello)
	putHeader(sh, typeServerHello)
	copy(sh[encEOffset:], encE)
	_, fin, _, keys, err := schedule(cfg.PSK, pk, ch, sh, ssS, ssE)
	if err != nil {
		keys.wipe()
		return nil, err
	}
	copy(sh[finishedOffset:], fin)
	clear(fin)
	out, err := newChannel(rw, &keys, false)
	if err != nil {
		return nil, err
	}
	if err := rw.WriteBytes(sh); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}
	return out, nil
}

func writeKeyResponse(rw ReadWriter, pk PublicKey) error {
	frame := make([]byte, sizeKeyResponse)
	putHeader(frame, typeKeyResponse)
	copy(frame[headerLen:], pk[:])
	if err := rw.WriteBytes(frame); err != nil {
		return fmt.Errorf("write key response: %w", err)
	}
	return nil
}

func sendAlert(rw ReadWriter, code byte) error {
	if err := rw.WriteBytes(alertFrame(code)); err != nil {
		return fmt.Errorf("write alert: %w", err)
	}
	return alertCodeError(code)
}

// readRelay reads one handshake frame.
// EOF, unexpected EOF, a closed pipe and net.ErrClosed become
// ErrHandshakeRejected, with the cause wrapped. A deadline or any
// other timeout is wrapped and is not ErrHandshakeRejected.
func readRelay(rw ReadWriter) ([]byte, error) {
	frame, err := rw.ReadBytes()
	if err == nil {
		return frame, nil
	}
	if isHandshakeClose(err) {
		return nil, fmt.Errorf("%w: %w", ErrHandshakeRejected, err)
	}
	return nil, fmt.Errorf("read handshake: %w", err)
}

// isHandshakeClose reports whether err is the peer going away.
// A deadline or a timeout is not a close.
//
// A close is io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe (what
// net.Pipe and io.Pipe return), or net.ErrClosed. A connection
// reset and every other read error are left unchanged.
func isHandshakeClose(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}

// SilentDelay returns a uniform random duration from 2s through
// 8s, both ends included. The caller waits, then closes. The
// duration comes from crypto/rand. A crypto/rand failure returns
// the minimum, 2s.
func SilentDelay() time.Duration {
	const (
		silentMin = 2 * time.Second
		silentMax = 8 * time.Second
	)
	span := int64(silentMax - silentMin)
	n, err := rand.Int(rand.Reader, big.NewInt(span+1))
	if err != nil {
		return silentMin
	}
	return silentMin + time.Duration(n.Int64())
}
