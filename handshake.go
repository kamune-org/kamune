package kamune

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/internal/enigma"
	"github.com/hossein1376/kamune/internal/exchange"
)

func requestHandshake(pt *plainTransport) (*Transport, error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM keys: %w", err)
	}
	nonce := randomBytes(enigma.BaseNonceSize)
	req := &pb.Handshake{
		Key:     ml.PublicKey.Bytes(),
		Nonce:   nonce,
		Padding: padding(handshakePadding),
	}
	reqBytes, _, err := pt.serialize(req, pt.sent.Load())
	if err != nil {
		return nil, fmt.Errorf("serializing handshake request: %w", err)
	}
	if _, err = pt.conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("writing handshake request: %w", err)
	}
	pt.sent.Add(1)

	respBytes, err := read(pt.conn)
	if err != nil {
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}
	var resp pb.Handshake
	if _, err = pt.deserialize(respBytes, &resp, pt.received.Load()); err != nil {
		return nil, fmt.Errorf("deserializing handshake response: %w", err)
	}
	pt.received.Add(1)
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulating secret: %w", err)
	}

	encoder, err := enigma.NewEnigma(secret, nonce, enigma.C2S)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(secret, resp.GetNonce(), enigma.S2C)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, resp.GetSessionID(), encoder, decoder)
	if err := sendVerification(t); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}
	if err := receiveVerification(t); err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}

	return t, nil
}

func acceptHandshake(pt *plainTransport) (*Transport, error) {
	reqBytes, err := read(pt.conn)
	if err != nil {
		return nil, fmt.Errorf("reading handshake request: %w", err)

	}
	var req pb.Handshake
	if _, err = pt.deserialize(reqBytes, &req, pt.received.Load()); err != nil {
		return nil, fmt.Errorf("deserializing handshake request: %w", err)
	}
	pt.received.Add(1)
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulating key: %w", err)
	}

	sessionID := rand.Text()
	nonce := randomBytes(enigma.BaseNonceSize)
	resp := &pb.Handshake{
		Key:       ct,
		Nonce:     nonce,
		SessionID: &sessionID,
		Padding:   padding(handshakePadding),
	}
	respBytes, _, err := pt.serialize(resp, pt.sent.Load())
	if err != nil {
		return nil, fmt.Errorf("serializing handshake response: %w", err)
	}
	if _, err = pt.conn.Write(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake response: %w", err)
	}
	pt.sent.Add(1)

	encoder, err := enigma.NewEnigma(secret, nonce, enigma.S2C)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(secret, req.GetNonce(), enigma.C2S)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder)
	if err := receiveVerification(t); err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}
	if err := sendVerification(t); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}

	return t, nil
}

func sendVerification(t *Transport) error {
	m := []byte(rand.Text())
	if _, err := t.Send(Bytes(m)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if !bytes.Equal(r.Value, m) {
		return ErrVerificationFailed
	}

	return nil
}

func receiveVerification(t *Transport) error {
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if _, err := t.Send(Bytes(r.Value)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}

	return nil
}

func randomBytes(l int) []byte {
	rnd := make([]byte, l)
	if _, err := rand.Read(rnd); err != nil {
		panic(fmt.Errorf("generating random bytes: %w", err))
	}
	return rnd
}

func padding(maxSize int) []byte {
	return randomBytes(mathrand.IntN(maxSize))
}
