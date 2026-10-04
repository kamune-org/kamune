package main

import (
	"bytes"
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

// currentVerifMode returns the verification mode that new servers and
// dialers use.
func (a *App) currentVerifMode() VerificationMode {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.verifMode
}

// getVerifier returns the verifier for the current verification mode.
func (a *App) getVerifier() kamune.RemoteVerifier {
	return a.verifierFor(a.currentVerifMode())
}

// verifierFor returns the verifier for mode.
func (a *App) verifierFor(mode VerificationMode) kamune.RemoteVerifier {
	switch mode {
	case VerificationModeStrict:
		return a.createStrictVerifier()
	case VerificationModeQuick:
		return a.createQuickVerifier()
	default:
		return a.createAutoAcceptVerifier()
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
func (a *App) createStrictVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		id := a.identifyPeer(store, peer)
		return a.promptVerification(id, peer.PublicKey, "strict")
	}
}

// createQuickVerifier admits a peer whose key is stored without asking
// and asks the user about any other peer. The name a peer claims plays
// no part: a stored peer is shown under its stored name whatever it
// claims, and an unknown peer is asked about whatever name it claims.
func (a *App) createQuickVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		id := a.identifyPeer(store, peer)
		if id.Known {
			a.addLogEntry("INFO", "Auto-accepted known peer: "+id.logName())
			return nil
		}
		return a.promptVerification(id, peer.PublicKey, "quick")
	}
}

// promptVerification asks the user whether to admit the peer id, whose
// key is key, and waits for the answer.
func (a *App) promptVerification(
	id peerIdentity, key []byte, mode string,
) error {
	emoji := strings.Join(fingerprint.Emoji(key), " • ")
	hex := fingerprint.Hex(key)

	a.mu.RLock()
	prevStatus := a.status
	prevMsg := a.statusMsg
	a.mu.RUnlock()

	reqID := a.verifIDCounter.Add(1)
	result := make(chan error, 1)

	a.verifMu.Lock()
	a.verifRequests[reqID] = &pendingVerification{
		result: result,
		peerID: id.Label,
		hex:    hex,
	}
	a.verifMu.Unlock()

	a.setStatus(StatusVerifying, "Verifying fingerprint of "+id.Label+"...")
	a.addLogEntry("INFO", "Verifying peer: "+id.logName())

	a.emitEvent("verify-peer", map[string]any{
		"requestID":    reqID,
		"peerID":       id.KeyB64,
		"peerName":     id.Label,
		"claimedName":  id.ClaimedName,
		"emoji":        emoji,
		"hex":          hex,
		"known":        id.Known,
		"nameMismatch": id.NameMismatch,
		"nameConflict": id.NameConflict,
		"mode":         mode,
	})

	verdict := a.awaitVerification(reqID, result)

	if verdict != nil {
		return verdict
	}

	a.setStatus(prevStatus, prevMsg)
	return nil
}

// createAutoAcceptVerifier admits every peer without asking.
func (a *App) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		a.addLogEntry("INFO",
			"Auto-accepted peer: "+a.identifyPeer(store, peer).logName())
		return nil
	}
}

const verificationTimeout = 2 * time.Minute

func (a *App) awaitVerification(reqID int64, result chan error) error {
	timer := time.NewTimer(verificationTimeout)
	defer timer.Stop()

	select {
	case verdict := <-result:
		a.verifMu.Lock()
		delete(a.verifRequests, reqID)
		a.verifMu.Unlock()
		return verdict
	case <-timer.C:
		a.verifMu.Lock()
		delete(a.verifRequests, reqID)
		a.verifMu.Unlock()
		a.setStatus(StatusError, "Verification timed out")
		a.addLogEntry("WARN", "Verification timed out for request: "+fmt.Sprintf("%d", reqID))
		return fmt.Errorf("verification timed out after %v", verificationTimeout)
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
		a.addLogEntry("INFO", "Accepted peer: "+truncateSessionID(pending.peerID))
	} else {
		select {
		case pending.result <- kamune.ErrVerificationFailed:
		default:
		}
		a.addLogEntry("INFO", "Rejected peer: "+truncateSessionID(pending.peerID))
	}
}
