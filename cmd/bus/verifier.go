package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// ErrPeerKeyMismatch rejects a peer whose key is not the key of the peer
// the connection was opened for.
var ErrPeerKeyMismatch = errors.New(
	"peer key does not match the peer selected for this connection",
)

// ErrVerificationCancelled rejects a peer whose prompt was closed because
// the server or the dial it came through stopped before the user
// answered.
var ErrVerificationCancelled = errors.New(
	"the verification was cancelled before it was answered",
)

// ErrTooManyVerifications rejects a peer that connects to a server of the
// app and would need a prompt while maxPendingVerifications prompts for
// such peers are already open.
var ErrTooManyVerifications = errors.New(
	"too many verification requests are waiting for an answer",
)

// maxPendingVerifications caps the prompts for peers that connect to a
// server of the app that may wait for the user at once. Anyone who can
// reach a listener can start a handshake with a new key, and each prompt
// holds a server goroutine until the user answers or verificationTimeout
// passes. The prompts for peers the user dials neither count toward the
// cap nor are refused for it, so that peers which connect to the app
// cannot keep the user from reaching a peer.
const maxPendingVerifications = 3

// currentVerifMode returns the verification mode that new servers and
// dialers use.
func (a *App) currentVerifMode() VerificationMode {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.verifMode
}

// getVerifier returns the verifier for the current verification mode,
// for peers that the user dials.
func (a *App) getVerifier() kamune.RemoteVerifier {
	return a.verifierFor(a.currentVerifMode())
}

// verifierFor returns the verifier for mode, for peers that the user
// dials. A mode that is not defined gets the strict verifier, so a bad
// value never turns verification off.
func (a *App) verifierFor(mode VerificationMode) kamune.RemoteVerifier {
	return a.verifierWithin(a.lifeCtx(), mode, false)
}

// verifierWithin returns the verifier for mode whose prompts end, and
// reject their peer, once ctx ends: ctx is the lifetime of the server or
// the dial that the verifier is for. inbound is set for the verifier of
// a server, whose peers connect to the app, and clear for one whose
// peers the user dials, by ConnectToServer or a session's reconnect;
// see maxPendingVerifications.
func (a *App) verifierWithin(
	ctx context.Context, mode VerificationMode, inbound bool,
) kamune.RemoteVerifier {
	switch mode {
	case VerificationModeQuick:
		return a.createQuickVerifier(ctx, inbound)
	case VerificationModeAutoAccept:
		return a.createAutoAcceptVerifier()
	default:
		return a.createStrictVerifier(ctx, inbound)
	}
}

// pinPeer returns a verifier that rejects a peer whose key is not want
// before rv sees it, so a peer that answers a connection meant for
// another peer is neither prompted for nor admitted, whatever name it
// claims and whether or not its key is stored. A nil want returns rv.
func (a *App) pinPeer(
	want []byte, rv kamune.RemoteVerifier,
) kamune.RemoteVerifier {
	if want == nil {
		return rv
	}
	return func(store *storage.Storage, peer *storage.Peer) error {
		if !bytes.Equal(peer.PublicKey, want) {
			a.addLogEntry("WARN",
				"Rejected peer "+a.identifyPeer(store, peer).logName()+
					": its key is not the selected peer's key")
			return ErrPeerKeyMismatch
		}
		return rv(store, peer)
	}
}

// The verifiers below only decide whether to admit a peer. None of them
// saves the peer: rememberPeer does that once the session is established.

// createStrictVerifier asks the user about every peer, known or not.
func (a *App) createStrictVerifier(
	ctx context.Context, inbound bool,
) kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		id := a.identifyPeer(store, peer)
		return a.promptVerification(
			ctx, id, peer.PublicKey, "strict", inbound,
		)
	}
}

// createQuickVerifier admits a peer whose key is stored without asking
// and asks the user about any other peer. The name a peer claims plays
// no part: a stored peer is shown under its stored name whatever it
// claims, and an unknown peer is asked about whatever name it claims.
func (a *App) createQuickVerifier(
	ctx context.Context, inbound bool,
) kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		id := a.identifyPeer(store, peer)
		if id.Known {
			a.addLogEntry("INFO", "Auto-accepted known peer: "+id.logName())
			return nil
		}
		return a.promptVerification(
			ctx, id, peer.PublicKey, "quick", inbound,
		)
	}
}

// promptVerification asks the user whether to admit the peer id, whose
// key is key, and waits for the answer. Once ctx ends, the prompt closes
// and the peer is rejected with ErrVerificationCancelled.
//
// Each request gets its own ID, and the frontend queues requests and
// shows them one at a time, so a new request never replaces the one the
// user is looking at. At most maxPendingVerifications inbound requests,
// for peers that connected to a server of the app, wait at once; an
// inbound peer that would need another is rejected without a prompt. A
// request for a peer the user dials is never rejected for that cap.
// Every request ends with a verify-peer-closed event, whether it was
// answered or timed out, so the frontend can drop it from its queue.
func (a *App) promptVerification(
	ctx context.Context, id peerIdentity, key []byte, mode string,
	inbound bool,
) error {
	if ctx.Err() != nil {
		return ErrVerificationCancelled
	}
	emoji := strings.Join(fingerprint.Emoji(key), " • ")
	numeric := fingerprint.Numeric(key)
	hex := fingerprint.Hex(key)

	result := make(chan error, 1)

	a.verifMu.Lock()
	if inbound && a.inboundPromptsLocked() >= maxPendingVerifications {
		a.verifMu.Unlock()
		a.addLogEntry("WARN", fmt.Sprintf(
			"Rejected incoming peer %s: %d verification requests for "+
				"incoming connections are already waiting",
			id.logName(), maxPendingVerifications,
		))
		return ErrTooManyVerifications
	}
	if len(a.verifRequests) == 0 {
		// The first open prompt saves the status to restore once the
		// last one closes.
		a.verifPrevStatus = a.GetStatus()
	}
	reqID := a.verifIDCounter.Add(1)
	a.verifRequests[reqID] = &pendingVerification{
		result:  result,
		label:   id.Label,
		inbound: inbound,
	}
	a.verifMu.Unlock()
	defer a.endVerification(reqID)

	a.setStatus(StatusVerifying, verifyingStatus(id.Label))
	a.addLogEntry("INFO", "Verifying peer: "+id.logName())

	a.emitEvent("verify-peer", map[string]any{
		"requestID":    reqID,
		"peerID":       id.KeyB64,
		"peerName":     id.Label,
		"claimedName":  id.ClaimedName,
		"numeric":      numeric,
		"emoji":        emoji,
		"hex":          hex,
		"known":        id.Known,
		"nameMismatch": id.NameMismatch,
		"nameConflict": id.NameConflict,
		"mode":         mode,
	})

	return a.awaitVerification(ctx, reqID, result)
}

// inboundPromptsLocked counts the open prompts for peers that connected
// to a server of the app. The caller holds a.verifMu.
func (a *App) inboundPromptsLocked() int {
	n := 0
	for _, p := range a.verifRequests {
		if p.inbound {
			n++
		}
	}
	return n
}

func verifyingStatus(label string) string {
	return "Verifying fingerprint of " + label + "..."
}

// endVerification closes request reqID, on every way a prompt ends, and
// emits verify-peer-closed. While other prompts stay open the status
// names the oldest of them. When the last one closes, the status from
// before the first one opened comes back, unless something else, such as
// a failed dial, has changed the status in the meantime.
func (a *App) endVerification(reqID int64) {
	a.verifMu.Lock()
	delete(a.verifRequests, reqID)
	var next *pendingVerification
	var nextID int64
	for id, p := range a.verifRequests {
		if next == nil || id < nextID {
			next, nextID = p, id
		}
	}
	prev := a.verifPrevStatus
	a.verifMu.Unlock()

	a.emitEvent("verify-peer-closed", reqID)
	if next != nil {
		a.replaceStatus(StatusVerifying, StatusVerifying,
			verifyingStatus(next.label))
		return
	}
	a.replaceStatus(StatusVerifying, prev.Status, prev.Message)
}

// createAutoAcceptVerifier admits every peer without asking.
func (a *App) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		a.addLogEntry("INFO",
			"Auto-accepted peer: "+a.identifyPeer(store, peer).logName())
		return nil
	}
}

// verificationTimeout is how long a prompt waits for the user. It stays
// below the core's default verify limit of 150 s, past which the
// handshake counts an accept as a rejection.
const verificationTimeout = 2 * time.Minute

func (a *App) verificationTimeout() time.Duration {
	if a.verifTimeout > 0 {
		return a.verifTimeout
	}
	return verificationTimeout
}

func (a *App) awaitVerification(
	ctx context.Context, reqID int64, result chan error,
) error {
	timeout := a.verificationTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case verdict := <-result:
		return verdict
	case <-ctx.Done():
		a.addLogEntry("INFO", fmt.Sprintf(
			"Verification request %d closed: its server or dial stopped",
			reqID,
		))
		return ErrVerificationCancelled
	case <-timer.C:
		a.addLogEntry("WARN", fmt.Sprintf(
			"Verification request %d timed out after %v", reqID, timeout,
		))
		return fmt.Errorf("verification timed out after %v", timeout)
	}
}

func (a *App) VerifyResponse(requestID int64, accepted bool) {
	a.verifMu.Lock()
	pending, ok := a.verifRequests[requestID]
	a.verifMu.Unlock()

	if !ok {
		a.addLogEntry("WARN", "Verification request not found: "+fmt.Sprintf("%d", requestID))
		return
	}

	if accepted {
		select {
		case pending.result <- nil:
		default:
		}
		a.addLogEntry("INFO", "Accepted peer: "+pending.label)
	} else {
		select {
		case pending.result <- kamune.ErrVerificationFailed:
		default:
		}
		a.addLogEntry("INFO", "Rejected peer: "+pending.label)
	}
}
