package relayleg

// Version is the relay-leg version byte.
const Version = 2

const (
	magic0 = 'K'
	magic1 = 'R'

	headerLen   = 4
	flagLen     = 1
	hintLen     = 4
	encSLen     = 32
	ephPKLen    = 1216
	binderLen   = 32
	encELen     = 1120
	finishedLen = 32

	flagOffset   = headerLen
	hintOffset   = flagOffset + flagLen
	encSOffset   = hintOffset + hintLen
	ephOffset    = encSOffset + encSLen
	binderOffset = ephOffset + ephPKLen

	encEOffset     = headerLen
	finishedOffset = encEOffset + encELen

	sizeKeyRequest  = headerLen
	sizeKeyResponse = headerLen + encSLen
	sizeAlert       = headerLen + 1

	// pskFlag is ClientHello flags bit 0. Bits 1-7 must be zero,
	// so a PSK hello has flags equal to this byte.
	pskFlag = 0x01

	typeKeyRequest  byte = 0x01
	typeKeyResponse byte = 0x02
	typeClientHello byte = 0x03
	typeServerHello byte = 0x04
	typeAlert       byte = 0x05

	alertBadMessage    byte = 1
	alertPSKUnexpected byte = 2
	alertUnknownKey    byte = 3
)

// MaxHandshakeFrame is the largest handshake frame either side
// accepts before ServerHello. It is the ClientHello size.
const MaxHandshakeFrame = headerLen + flagLen + hintLen +
	encSLen + ephPKLen + binderLen

const (
	sizeClientHello = MaxHandshakeFrame
	sizeServerHello = finishedOffset + finishedLen
)

// The arithmetic above is the layout in RFC 009 section 7.1.
var (
	_ [0]struct{} = [MaxHandshakeFrame - 1289]struct{}{}
	_ [0]struct{} = [sizeServerHello - 1156]struct{}{}
	_ [0]struct{} = [sizeKeyResponse - 36]struct{}{}
	_ [0]struct{} = [sizeKeyRequest - 4]struct{}{}
	_ [0]struct{} = [sizeAlert - 5]struct{}{}
	_ [0]struct{} = [binderOffset - 1257]struct{}{}
	_ [0]struct{} = [finishedOffset - 1124]struct{}{}
)

func putHeader(dst []byte, typ byte) {
	dst[0] = magic0
	dst[1] = magic1
	dst[2] = Version
	dst[3] = typ
}

func keyRequestFrame() []byte {
	frame := make([]byte, sizeKeyRequest)
	putHeader(frame, typeKeyRequest)
	return frame
}

// exact reports whether frame is one handshake message: KR, version
// 2, the given type, and that total size.
func exact(frame []byte, typ byte, n int) bool {
	return len(frame) == n &&
		n >= headerLen &&
		frame[0] == magic0 &&
		frame[1] == magic1 &&
		frame[2] == Version &&
		frame[3] == typ
}

// classify checks the header of a frame the client read.
// A KR frame whose version is not 2 is ErrUnsupportedVersion,
// including alerts. Any other bad header is ErrBadMessage.
func classify(frame []byte) (byte, error) {
	if len(frame) < headerLen ||
		frame[0] != magic0 || frame[1] != magic1 {
		return 0, ErrBadMessage
	}
	if frame[2] != Version {
		return 0, ErrUnsupportedVersion
	}
	return frame[3], nil
}

func alertFrame(code byte) []byte {
	frame := make([]byte, sizeAlert)
	putHeader(frame, typeAlert)
	frame[headerLen] = code
	return frame
}

func alertCodeError(code byte) error {
	switch code {
	case alertBadMessage:
		return ErrBadMessage
	case alertPSKUnexpected:
		return ErrPSKUnexpected
	case alertUnknownKey:
		return ErrRelayKeyNotHeld
	default:
		return ErrBadMessage
	}
}

func alertError(frame []byte) error {
	if len(frame) != sizeAlert {
		return ErrBadMessage
	}
	return alertCodeError(frame[headerLen])
}

func isZero(b []byte) bool {
	var x byte
	for _, c := range b {
		x |= c
	}
	return x == 0
}
