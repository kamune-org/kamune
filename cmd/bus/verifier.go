package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) getVerifier() kamune.RemoteVerifier {
	a.mu.RLock()
	mode := a.verifMode
	a.mu.RUnlock()

	switch mode {
	case VerificationModeStrict:
		return a.createStrictVerifier()
	case VerificationModeQuick:
		return a.createQuickVerifier()
	default:
		return a.createAutoAcceptVerifier()
	}
}

func (a *App) createStrictVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey
		emoji := strings.Join(fingerprint.Emoji(key), " • ")
		hex := fingerprint.Hex(key)

		known := false
		_, err := store.FindPeer(key)
		if err == nil {
			known = true
		}

		reqID := a.verifIDCounter.Add(1)
		result := make(chan error, 1)

		a.verifMu.Lock()
		a.verifRequests[reqID] = &pendingVerification{
			result: result,
			peerID: peer.Name,
			hex:    hex,
		}
		a.verifMu.Unlock()

		runtime.EventsEmit(a.ctx, "verify-peer", map[string]any{
			"requestID": reqID,
			"peerID":    peer.Name,
			"peerName":  peer.Name,
			"emoji":     emoji,
			"hex":       hex,
			"known":     known,
			"mode":      "strict",
		})

		verdict := a.awaitVerification(reqID, result)

		if verdict != nil {
			return verdict
		}

		if !known {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				a.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		return nil
	}
}

func (a *App) createQuickVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey

		_, err := store.FindPeer(key)
		if err == nil {
			a.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name)
			return nil
		}

		emoji := strings.Join(fingerprint.Emoji(key), " • ")
		hex := fingerprint.Hex(key)

		reqID := a.verifIDCounter.Add(1)
		result := make(chan error, 1)

		a.verifMu.Lock()
		a.verifRequests[reqID] = &pendingVerification{
			result: result,
			peerID: peer.Name,
			hex:    hex,
		}
		a.verifMu.Unlock()

		runtime.EventsEmit(a.ctx, "verify-peer", map[string]any{
			"requestID": reqID,
			"peerID":    peer.Name,
			"peerName":  peer.Name,
			"emoji":     emoji,
			"hex":       hex,
			"known":     false,
			"mode":      "quick",
		})

		verdict := a.awaitVerification(reqID, result)

		if verdict != nil {
			return verdict
		}

		peer.FirstSeen = time.Now()
		if err := store.StorePeer(peer); err != nil {
			a.addLogEntry("WARN", "Failed to save peer: "+err.Error())
		}

		return nil
	}
}

func (a *App) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey

		_, err := store.FindPeer(key)
		if err != nil {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				a.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		a.addLogEntry("INFO", "Auto-accepted peer: "+peer.Name)
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
		pending.result <- nil
		a.addLogEntry("INFO", "Accepted peer: "+truncateSessionID(pending.peerID))
	} else {
		pending.result <- kamune.ErrVerificationFailed
		a.addLogEntry("INFO", "Rejected peer: "+truncateSessionID(pending.peerID))
	}
}
