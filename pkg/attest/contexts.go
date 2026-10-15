package attest

// Signature contexts are prefix-free, so a signature made for one purpose
// cannot be presented as a signature for another.
const (
	ContextResponderHandshake = "kamune/2 responder signature\x00"
	ContextInitiatorHandshake = "kamune/2 initiator signature\x00"
	ContextTransportFrame     = "kamune/transport-sign/v1"
)

// Contexts returns the signature contexts this package defines.
func Contexts() []string {
	return []string{
		ContextResponderHandshake,
		ContextInitiatorHandshake,
		ContextTransportFrame,
	}
}
