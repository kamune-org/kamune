package kamune

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/ratchet"
)

type handshakeOpts struct {
	remoteVerifier   RemoteVerifier
	ratchetThreshold uint64
}

func requestHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM keys: %w", err)
	}

	salt := randomBytes(saltSize)
	sessionKeyPrefix := enigma.Text(sessionIDLength / 2)
	req := &pb.Handshake{
		Key:        ml.PublicKey.Bytes(),
		Salt:       salt,
		SessionKey: sessionKeyPrefix,
	}
	reqBytes, _, err := pt.serialize(req)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake request: %w", err)
	}
	if err = pt.conn.WriteBytes(reqBytes); err != nil {
		return nil, fmt.Errorf("writing handshake request: %w", err)
	}

	respBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}
	var resp pb.Handshake
	if _, err = pt.deserialize(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("deserializing handshake response: %w", err)
	}
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulating secret: %w", err)
	}

	sessionID := sessionKeyPrefix + resp.GetSessionKey()
	encoder, err := enigma.NewEnigma(secret, salt, []byte(sessionID+c2s))
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, resp.GetSalt(), []byte(sessionID+s2c),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder, opts.ratchetThreshold)
	if err := sendChallenge(t, secret, []byte(sessionID+c2s)); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	if err := acceptChallenge(t); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	r, err := bootstrapDoubleRatchet(t, secret, t.sessionID, true)
	if err != nil {
		return nil, fmt.Errorf("bootstrap double ratchet: %w", err)
	}
	t.ratchet = r

	return t, nil
}

func acceptHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	reqBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake request: %w", err)
	}
	var req pb.Handshake
	if _, err = pt.deserialize(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("deserializing handshake request: %w", err)
	}
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulating key: %w", err)
	}

	sessionKeySuffix := enigma.Text(sessionIDLength / 2)
	sessionID := req.GetSessionKey() + sessionKeySuffix
	salt := randomBytes(saltSize)
	resp := &pb.Handshake{
		Key:        ct,
		Salt:       salt,
		SessionKey: sessionKeySuffix,
	}
	respBytes, _, err := pt.serialize(resp)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake response: %w", err)
	}
	if err = pt.conn.WriteBytes(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake response: %w", err)
	}

	encoder, err := enigma.NewEnigma(secret, salt, []byte(sessionID+s2c))
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, req.GetSalt(), []byte(sessionID+c2s),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder, opts.ratchetThreshold)
	if err := acceptChallenge(t); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	if err := sendChallenge(t, secret, []byte(sessionID+s2c)); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	r, err := bootstrapDoubleRatchet(t, secret, t.sessionID, false)
	if err != nil {
		return nil, fmt.Errorf("bootstrap double ratchet: %w", err)
	}
	t.ratchet = r

	return t, nil
}

func sendChallenge(t *Transport, secret, info []byte) error {
	challenge, err := enigma.Derive(secret, nil, info, challengeSize)
	if err != nil {
		return fmt.Errorf("deriving a challenge: %w", err)
	}
	if _, err := t.Send(Bytes(challenge)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}

	if subtle.ConstantTimeCompare(r.Value, challenge) != 1 {
		return ErrVerificationFailed
	}

	return nil
}

func acceptChallenge(t *Transport) error {
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if _, err := t.Send(Bytes(r.Value)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}

	return nil
}

// bootstrapDoubleRatchet exchanges X25519 public keys over the current
// enigma-authenticated channel and returns an initialized ratchet.
func bootstrapDoubleRatchet(
	t *Transport, secret []byte, sessionID string, initiator bool,
) (*ratchet.Ratchet, error) {
	r, err := ratchet.NewFromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("creating new ratchet: %w", err)
	}

	theirBlob := Bytes(nil)
	if initiator {
		if _, err := t.Send(Bytes(r.OurPublic())); err != nil {
			return nil, fmt.Errorf("sending our public key: %w", err)
		}
		if _, err := t.Receive(theirBlob); err != nil {
			return nil, fmt.Errorf("receiving their public key: %w", err)
		}
	} else {
		if _, err := t.Receive(theirBlob); err != nil {
			return nil, fmt.Errorf("receiving their public key: %w", err)
		}
		if _, err := t.Send(Bytes(r.OurPublic())); err != nil {
			return nil, fmt.Errorf("sending our public key: %w", err)
		}
	}

	if err := r.SetTheirPublic(theirBlob.GetValue(), sessionID); err != nil {
		return nil, fmt.Errorf("setting their public key: %w", err)
	}
	return r, nil
}

func randomBytes(l int) []byte {
	buf := make([]byte, l)
	_, _ = rand.Read(buf)
	return buf
}

func padding(maxSize int) []byte {
	return randomBytes(mathrand.IntN(maxSize))
}
