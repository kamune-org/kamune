package engine

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/kamune-org/kamune/internal/enigma"
)

// kdfAlgorithm identifies the function that stretches the passphrase into
// the key that wraps the data encryption secret.
type kdfAlgorithm uint8

const (
	// kdfLegacyHKDF is a single HKDF-SHA512 call with no work factor. It is
	// only read, from stores written before kdf-params existed. Opening such
	// a store re-wraps its secret under [defaultKDF].
	kdfLegacyHKDF kdfAlgorithm = 0
	// kdfArgon2id is Argon2id (RFC 9106) with the stored parameters.
	kdfArgon2id kdfAlgorithm = 1
)

const (
	kdfParamsSize  = 10
	derivedKeySize = 32

	// Bounds on stored Argon2id parameters. They keep a corrupt or tampered
	// store from making an open allocate more memory than a client can be
	// expected to have, which gets the process killed instead of returning
	// an error, or run for more than a few seconds. maxKDFWork bounds time
	// times memory, the number of KiB blocks an open fills.
	maxKDFTime   = 64
	maxKDFMemory = 1 << 20 // KiB, 1 GiB
	maxKDFWork   = 4 << 20 // KiB passes, 4 GiB
)

// kdfParams selects the passphrase stretching function and its cost. They
// are stored under kdf-params next to the derive salt, so the cost can be
// raised later without a format change. The encoding is one algorithm byte,
// the Argon2id time and memory (KiB) as big-endian uint32 values, and one
// parallelism byte.
type kdfParams struct {
	time    uint32
	memory  uint32
	alg     kdfAlgorithm
	threads uint8
}

var (
	// legacyKDF describes stores that have no kdf-params entry.
	legacyKDF = kdfParams{alg: kdfLegacyHKDF}

	// defaultKDF is the minimum cost of a wrapping. New stores use it, and
	// a weaker stored wrapping is raised to it, see [kdfParams.atLeast], on
	// the next successful unlock. It is the second
	// recommended option of RFC 9106 (t=3, m=64 MiB, p=4), which takes about
	// a tenth of a second on a current laptop.
	defaultKDF = kdfParams{
		alg: kdfArgon2id, time: 3, memory: 64 * 1024, threads: 4,
	}
)

func (p kdfParams) marshal() []byte {
	b := make([]byte, kdfParamsSize)
	b[0] = byte(p.alg)
	binary.BigEndian.PutUint32(b[1:5], p.time)
	binary.BigEndian.PutUint32(b[5:9], p.memory)
	b[9] = p.threads
	return b
}

func parseKDFParams(b []byte) (kdfParams, error) {
	if len(b) != kdfParamsSize {
		return kdfParams{}, fmt.Errorf(
			"%w: kdf params are %d bytes", ErrCorruptMetadata, len(b),
		)
	}
	p := kdfParams{
		alg:     kdfAlgorithm(b[0]),
		time:    binary.BigEndian.Uint32(b[1:5]),
		memory:  binary.BigEndian.Uint32(b[5:9]),
		threads: b[9],
	}
	if p.alg != kdfArgon2id {
		return kdfParams{}, fmt.Errorf(
			"%w: unknown kdf algorithm %d", ErrCorruptMetadata, p.alg,
		)
	}
	if p.time < 1 || p.time > maxKDFTime ||
		p.threads < 1 ||
		p.memory < 8*uint32(p.threads) || p.memory > maxKDFMemory ||
		uint64(p.time)*uint64(p.memory) > maxKDFWork {
		return kdfParams{}, fmt.Errorf(
			"%w: argon2id parameters out of range (t=%d m=%d p=%d)",
			ErrCorruptMetadata, p.time, p.memory, p.threads,
		)
	}
	return p, nil
}

// derive stretches pass with salt into the input of the key-encryption
// cipher. That cipher applies HKDF with its own salt and label, which keeps
// the derived key separate from any other use.
func (p kdfParams) derive(pass, salt []byte) ([]byte, error) {
	switch p.alg {
	case kdfArgon2id:
		return argon2.IDKey(
			pass, salt, p.time, p.memory, p.threads, derivedKeySize,
		), nil
	case kdfLegacyHKDF:
		return enigma.Derive(pass, salt, []byte(dpk), derivedKeySize)
	default:
		return nil, fmt.Errorf(
			"%w: unknown kdf algorithm %d", ErrCorruptMetadata, p.alg,
		)
	}
}

// atLeast returns the parameters to wrap with when p is stored and q is the
// minimum: q when p is not Argon2id, otherwise the larger time, memory and
// parallelism of the two. A guess under the result costs at least as much
// as under either, so raising one parameter never lowers another that p
// already had. The result equals p when p needs no change. For q =
// [defaultKDF] and p within the parse bounds, the result is within them.
func (p kdfParams) atLeast(q kdfParams) kdfParams {
	if p.alg != kdfArgon2id || q.alg != kdfArgon2id {
		return q
	}
	return kdfParams{
		alg:     kdfArgon2id,
		time:    max(p.time, q.time),
		memory:  max(p.memory, q.memory),
		threads: max(p.threads, q.threads),
	}
}
