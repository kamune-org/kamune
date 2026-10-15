package kamune

import (
	"context"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
)

// Role is the side of the handshake the local endpoint plays.
type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// VerifyRequest describes an authenticated peer to a verifier.
type VerifyRequest struct {
	Peer           *storage.Peer
	LocalPublicKey []byte
	SessionID      string
	Role           Role
	Pinned         bool
	ResumeOffered  bool
	Resumed        bool
}

// verifyFunc is the handshake verifier. The exported RemoteVerifier stays as it
// is until the v2 switch.
type verifyFunc func(
	ctx context.Context, store *storage.Storage, req VerifyRequest,
) error

// runVerifier runs v with a timeout. A nil error after the timeout context is
// done is a rejection.
func runVerifier(
	ctx context.Context,
	timeout time.Duration,
	v verifyFunc,
	store *storage.Storage,
	req VerifyRequest,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout = verifyTimeoutOrDefault(timeout)
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		if v == nil {
			errc <- nil
			return
		}
		errc <- v(vctx, store, req)
	}()
	select {
	case <-vctx.Done():
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
			return fmt.Errorf(
				"%w: verifier finished after its deadline: %w",
				ErrVerificationFailed, vctx.Err(),
			)
		default:
			return fmt.Errorf(
				"%w: %w", ErrVerificationFailed, vctx.Err(),
			)
		}
	case err := <-errc:
		if err != nil {
			return err
		}
		if vctx.Err() != nil {
			return fmt.Errorf("%w: %w", ErrVerificationFailed, vctx.Err())
		}
		return nil
	}
}
