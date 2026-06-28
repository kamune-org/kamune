// Package broker implements the kamune relay broker: a single UDP listener that
// combines STUN-like IP echo and signal introduction for P2P hole-punching.
// Pure functions only; no I/O.
package broker

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// magic is the fixed 4-byte protocol identifier: "KBRK".
	magic = "KBRK"
	// ver is the protocol version. v1 is the only version.
	ver = 0x01

	// opcodeEcho is a STUN-like request; the server responds with the source's
	// perceived IP:port.
	opcodeEcho = 0x01
	// opcodeRegister is a signal-introduction request: the peer supplies (or
	// omits) a token and waits for a NOTIFY.
	opcodeRegister = 0x02
	// opcodeNotify is sent by the server only; peers should not send it. The
	// server ignores incoming NOTIFYs.
	opcodeNotify = 0x03

	tokenSize     = 16
	x25519KeySize = 32
	ipv4Size      = 4
	portSize      = 2
	nonceSize     = chacha20poly1305.NonceSizeX // XChaCha20-Poly1305: 24 bytes

	// headerSize is magic(4) + ver(1) + opcode(1).
	headerSize = 6
	// notifyHeaderSize is header(6) + brokerEphPub(32).
	notifyHeaderSize = 38
	// aadSize is magic(4) + ver(1) + opcode(1) + brokerEphPub(32).
	aadSize = 38

	// Register size = header + token(16) + peerEphPub(32) + ip(4) + port(2).
	registerSize = 60

	// Notify payload sizes.
	peerMatchedPayloadSize   = 1 + tokenSize + x25519KeySize + ipv4Size + portSize // 55
	tokenAssignedPayloadSize = 1 + tokenSize + 4                                   // 21
)

// Opcode enumerates the protocol opcodes.
type Opcode byte

const (
	OpcodeEcho     Opcode = opcodeEcho
	OpcodeRegister Opcode = opcodeRegister
	OpcodeNotify   Opcode = opcodeNotify
)

// NotifyType is the type byte inside a NOTIFY plaintext payload.
type NotifyType byte

const (
	// NotifyPeerMatched (0x01): the peer's counterpart has been matched;
	// payload carries the counterpart's IP:port + eph pub.
	NotifyPeerMatched NotifyType = 0x01
	// NotifyTokenAssigned (0x02): the broker has assigned a random token;
	// payload carries the token and TTL.
	NotifyTokenAssigned NotifyType = 0x02
)

// ErrShortPacket is returned when a packet is too short for its kind.
var ErrShortPacket = errors.New("packet too short")

// ErrBadMagic is returned when a packet does not start with the broker magic.
var ErrBadMagic = errors.New("bad magic")

// ErrBadVersion is returned when a packet has an unsupported version.
var ErrBadVersion = errors.New("bad version")

// ErrBadOpcode is returned when a packet has an unknown opcode.
var ErrBadOpcode = errors.New("bad opcode")

// NotifyPayload is the decoded plaintext of a NOTIFY packet. The field set
// depends on Type: TOKEN_ASSIGNED fills Token and TTLSeconds; PEER_MATCHED
// fills Token, OtherPeerEphPub, IP, and Port.
type NotifyPayload struct {
	Type            NotifyType
	Token           []byte
	OtherPeerEphPub []byte
	IP              net.IP
	Port            uint16
	TTLSeconds      uint32
}

// ParseEchoRequest validates a STUN_ECHO request. Trailing bytes are ignored
// per the wire format (the response is based on the source address, not packet
// content).
func ParseEchoRequest(pkt []byte) error {
	if len(pkt) < headerSize {
		return ErrShortPacket
	}
	if !bytesHasPrefix(pkt, magic) {
		return ErrBadMagic
	}
	if pkt[4] != ver {
		return ErrBadVersion
	}
	if pkt[5] != opcodeEcho {
		return ErrBadOpcode
	}
	return nil
}

// BuildEchoResponse formats the source address as "ip:port\0".
func BuildEchoResponse(addr *net.UDPAddr) []byte {
	ip4 := addr.IP.To4()
	if ip4 == nil {
		// Fall back to the raw IP string for non-IPv4 sources. v1 rejects
		// non-IPv4 entirely (see ParseRegister); the only way to get here is if
		// the server is misconfigured.
		ip4 = addr.IP
	}
	return append([]byte(
		net.JoinHostPort(ip4.String(), fmt.Sprintf("%d", addr.Port))), 0,
	)
}

// ParseRegister unpacks a 60-byte REGISTER. The returned slices alias
// the input; callers that need to retain the values past the next
// packet must copy.
func ParseRegister(pkt []byte) (
	token, peerEphPub []byte, ip net.IP, port uint16, err error,
) {
	if len(pkt) < registerSize {
		return nil, nil, nil, 0, ErrShortPacket
	}
	if !bytesHasPrefix(pkt, magic) {
		return nil, nil, nil, 0, ErrBadMagic
	}
	if pkt[4] != ver {
		return nil, nil, nil, 0, ErrBadVersion
	}
	if pkt[5] != opcodeRegister {
		return nil, nil, nil, 0, ErrBadOpcode
	}
	token = pkt[headerSize : headerSize+tokenSize]
	peerEphPub = pkt[headerSize+tokenSize : headerSize+tokenSize+x25519KeySize]
	ip = net.IP(pkt[headerSize+tokenSize+x25519KeySize : headerSize+tokenSize+x25519KeySize+ipv4Size])
	port = binary.BigEndian.Uint16(
		pkt[headerSize+tokenSize+x25519KeySize+ipv4Size : registerSize],
	)
	return token, peerEphPub, ip, port, nil
}

// BuildRegister builds a 60-byte REGISTER packet. The token may be nil/empty
// (random mode) or a 16-byte precomputed token (static mode). The peerEphPub
// must be 32 bytes.
func BuildRegister(token, peerEphPub []byte, ip net.IP, port uint16) []byte {
	tk := padOrTruncate(token, tokenSize)
	pk := padOrTruncate(peerEphPub, x25519KeySize)
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = make(net.IP, ipv4Size) // zero IP for IPv6 (rejected by server)
	}
	ipSlice := padOrTruncate(ip4, ipv4Size)

	pkt := make([]byte, 0, registerSize)
	pkt = append(pkt, magic...)
	pkt = append(pkt, ver, opcodeRegister)
	pkt = append(pkt, tk...)
	pkt = append(pkt, pk...)
	pkt = append(pkt, ipSlice...)
	portBytes := make([]byte, portSize)
	binary.BigEndian.PutUint16(portBytes, port)
	pkt = append(pkt, portBytes...)
	return pkt
}

// BuildNotifyPeerMatched builds a NOTIFY(PEER_MATCHED) packet from the given
// header fields and AEAD output. The caller is responsible for computing the
// sealed bytes (PeerMatchedPlaintext + AEAD).
func BuildNotifyPeerMatched(brokerEphPub, nonce, sealed []byte) []byte {
	return buildNotify(brokerEphPub, nonce, sealed, peerMatchedPayloadSize)
}

// BuildNotifyTokenAssigned builds a NOTIFY(TOKEN_ASSIGNED) packet.
func BuildNotifyTokenAssigned(brokerEphPub, nonce, sealed []byte) []byte {
	return buildNotify(brokerEphPub, nonce, sealed, tokenAssignedPayloadSize)
}

// ParseNotify unpacks a NOTIFY packet. The returned slices alias the input.
func ParseNotify(pkt []byte) (brokerEphPub, nonce, sealed []byte, err error) {
	if len(pkt) < notifyHeaderSize+nonceSize {
		return nil, nil, nil, ErrShortPacket
	}
	if !bytesHasPrefix(pkt, magic) {
		return nil, nil, nil, ErrBadMagic
	}
	if pkt[4] != ver {
		return nil, nil, nil, ErrBadVersion
	}
	if pkt[5] != opcodeNotify {
		return nil, nil, nil, ErrBadOpcode
	}
	brokerEphPub = pkt[headerSize:notifyHeaderSize]
	nonce = pkt[notifyHeaderSize : notifyHeaderSize+nonceSize]
	sealed = pkt[notifyHeaderSize+nonceSize:]
	return brokerEphPub, nonce, sealed, nil
}

// PeerMatchedPlaintext builds the plaintext for a PEER_MATCHED NOTIFY.
func PeerMatchedPlaintext(
	token, otherPeerEphPub []byte, ip net.IP, port uint16,
) []byte {
	tk := padOrTruncate(token, tokenSize)
	pk := padOrTruncate(otherPeerEphPub, x25519KeySize)
	ip4 := padOrTruncate(ip.To4(), ipv4Size)
	if len(ip4) == 0 {
		ip4 = make(net.IP, ipv4Size)
	}

	p := make([]byte, 0, peerMatchedPayloadSize)
	p = append(p, byte(NotifyPeerMatched))
	p = append(p, tk...)
	p = append(p, pk...)
	p = append(p, ip4...)
	portBytes := make([]byte, portSize)
	binary.BigEndian.PutUint16(portBytes, port)
	p = append(p, portBytes...)
	return p
}

// TokenAssignedPlaintext builds the plaintext for a TOKEN_ASSIGNED NOTIFY.
func TokenAssignedPlaintext(token []byte, ttlSeconds uint32) []byte {
	tk := padOrTruncate(token, tokenSize)
	p := make([]byte, 0, tokenAssignedPayloadSize)
	p = append(p, byte(NotifyTokenAssigned))
	p = append(p, tk...)
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, ttlSeconds)
	p = append(p, ttlBytes...)
	return p
}

// ParseNotifyPayload decodes a NOTIFY plaintext.
func ParseNotifyPayload(plaintext []byte) (NotifyPayload, error) {
	if len(plaintext) < 1 {
		return NotifyPayload{}, ErrShortPacket
	}
	var out NotifyPayload
	out.Type = NotifyType(plaintext[0])
	switch out.Type {
	case NotifyPeerMatched:
		if len(plaintext) < peerMatchedPayloadSize {
			return NotifyPayload{}, ErrShortPacket
		}
		out.Token = plaintext[1 : 1+tokenSize]
		out.OtherPeerEphPub = plaintext[1+tokenSize : 1+tokenSize+x25519KeySize]
		out.IP = net.IP(plaintext[1+tokenSize+x25519KeySize : 1+tokenSize+x25519KeySize+ipv4Size])
		out.Port = binary.BigEndian.Uint16(
			plaintext[1+tokenSize+x25519KeySize+ipv4Size : peerMatchedPayloadSize],
		)
	case NotifyTokenAssigned:
		if len(plaintext) < tokenAssignedPayloadSize {
			return NotifyPayload{}, ErrShortPacket
		}
		out.Token = plaintext[1 : 1+tokenSize]
		out.TTLSeconds = binary.BigEndian.Uint32(
			plaintext[1+tokenSize : tokenAssignedPayloadSize],
		)
	default:
		return NotifyPayload{}, ErrBadOpcode
	}
	return out, nil
}

// SealNotify encrypts plaintext with the per-REGISTER AEAD key and AAD. The
// AEAD key is SHA-256(shared_secret)[:32]; the AAD binds the ciphertext to the
// broker's ephemeral public key so a captured NOTIFY cannot be re-targeted.
// Returns a random 12-byte nonce and the sealed bytes (ciphertext || tag).
func SealNotify(aeadKey, brokerEphPub, plaintext []byte) (nonce, sealed []byte) {
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		panic(fmt.Errorf("chacha20poly1305.NewX: %w", err))
	}
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Errorf("rand.Read: %w", err))
	}
	sealed = aead.Seal(nil, nonce, plaintext, buildAAD(brokerEphPub))
	return nonce, sealed
}

// OpenNotify is the peer-side counterpart of SealNotify.
func OpenNotify(aeadKey, brokerEphPub, nonce, sealed []byte) ([]byte, error) {
	if len(aeadKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead key must be %d bytes", chacha20poly1305.KeySize)
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes", nonceSize)
	}
	aead, err := chacha20poly1305.NewX(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.NewX: %w", err)
	}
	return aead.Open(nil, nonce, sealed, buildAAD(brokerEphPub))
}

func buildNotify(brokerEphPub, nonce, sealed []byte, _ int) []byte {
	out := make([]byte, 0, notifyHeaderSize+len(nonce)+len(sealed))
	out = append(out, magic...)
	out = append(out, ver, opcodeNotify)
	out = append(out, brokerEphPub...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out
}

func buildAAD(brokerEphPub []byte) []byte {
	aad := make([]byte, 0, aadSize)
	aad = append(aad, magic...)
	aad = append(aad, ver, opcodeNotify)
	aad = append(aad, brokerEphPub...)
	return aad
}

func bytesHasPrefix(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// padOrTruncate returns a slice of length n. If the input is shorter, the
// remainder is zero-filled; if longer, the input is truncated.
func padOrTruncate(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
