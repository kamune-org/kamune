package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

const verifTimeout = 2 * time.Minute

type pendingVerification struct {
	result chan error
	peerID string
	hex    string
}

// getVerifier returns a kamune.RemoteVerifier based on the current mode.
func (d *Daemon) getVerifier() kamune.RemoteVerifier {
	d.mu.RLock()
	mode := d.verifMode
	d.mu.RUnlock()

	switch mode {
	case VerificationModeStrict:
		return d.createStrictVerifier()
	case VerificationModeQuick:
		return d.createQuickVerifier()
	default:
		return d.createAutoAcceptVerifier()
	}
}

func (d *Daemon) createStrictVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey
		hexFP := fingerprint.Hex(key)

		known := false
		if _, err := store.FindPeer(key); err == nil {
			known = true
		}

		d.mu.RLock()
		prevStatus := d.status
		prevMsg := d.statusMsg
		d.mu.RUnlock()

		reqID := d.verifIDCounter.Add(1)
		result := make(chan error, 1)

		d.verifMu.Lock()
		d.verifRequests[reqID] = &pendingVerification{
			result: result,
			peerID: peer.Name,
			hex:    hexFP,
		}
		d.verifMu.Unlock()

		d.setStatus(StatusVerifying, "Verifying fingerprint of "+peer.Name+"...")
		d.addLogEntry("INFO", "Verifying peer: "+peer.Name)

		d.emit(EvtVerifyPeer, "", MapA{
			"request_id": reqID,
			"peer_name":  peer.Name,
			"emoji":      fingerprint.Emoji(key),
			"hex":        hexFP,
			"known":      known,
			"mode":       "strict",
		})

		verdict := d.awaitVerification(reqID, result)
		if verdict != nil {
			return verdict
		}

		d.setStatus(prevStatus, prevMsg)

		if !known && !d.incognito {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		return nil
	}
}

func (d *Daemon) createQuickVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey

		if _, err := store.FindPeer(key); err == nil {
			d.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name)
			return nil
		}

		hexFP := fingerprint.Hex(key)

		d.mu.RLock()
		prevStatus := d.status
		prevMsg := d.statusMsg
		d.mu.RUnlock()

		reqID := d.verifIDCounter.Add(1)
		result := make(chan error, 1)

		d.verifMu.Lock()
		d.verifRequests[reqID] = &pendingVerification{
			result: result,
			peerID: peer.Name,
			hex:    hexFP,
		}
		d.verifMu.Unlock()

		d.setStatus(StatusVerifying, "Verifying fingerprint of "+peer.Name+"...")
		d.addLogEntry("INFO", "Verifying peer: "+peer.Name)

		d.emit(EvtVerifyPeer, "", MapA{
			"request_id": reqID,
			"peer_name":  peer.Name,
			"emoji":      fingerprint.Emoji(key),
			"hex":        hexFP,
			"known":      false,
			"mode":       "quick",
		})

		verdict := d.awaitVerification(reqID, result)
		if verdict != nil {
			return verdict
		}

		d.setStatus(prevStatus, prevMsg)

		if !d.incognito {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		return nil
	}
}

func (d *Daemon) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		key := peer.PublicKey

		if _, err := store.FindPeer(key); err != nil && !d.incognito {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		d.addLogEntry("INFO", "Auto-accepted peer: "+peer.Name)
		return nil
	}
}

func (d *Daemon) awaitVerification(reqID int64, result chan error) error {
	timer := time.NewTimer(verifTimeout)
	defer timer.Stop()

	select {
	case verdict := <-result:
		d.verifMu.Lock()
		delete(d.verifRequests, reqID)
		d.verifMu.Unlock()
		return verdict
	case <-timer.C:
		d.verifMu.Lock()
		delete(d.verifRequests, reqID)
		d.verifMu.Unlock()
		d.setStatus(StatusError, "Verification timed out")
		d.addLogEntry("WARN",
			fmt.Sprintf("Verification timed out for request: %d", reqID))
		return fmt.Errorf("verification timed out after %v", verifTimeout)
	}
}

// handleVerifyResponse handles a verify_response command.
func (d *Daemon) handleVerifyResponse(cmd Command) {
	var params VerifyResponseParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.verifMu.Lock()
	pending, ok := d.verifRequests[params.RequestID]
	d.verifMu.Unlock()

	if !ok {
		d.addLogEntry("WARN",
			fmt.Sprintf("Verification request not found: %d", params.RequestID))
		d.emitError(cmd.ID, "verification request not found")
		return
	}

	if params.Accepted {
		select {
		case pending.result <- nil:
		default:
		}
		d.addLogEntry("INFO", "Accepted peer: "+truncateSessionID(pending.peerID))
	} else {
		select {
		case pending.result <- kamune.ErrVerificationFailed:
		default:
		}
		d.addLogEntry("INFO", "Rejected peer: "+truncateSessionID(pending.peerID))
	}

	d.emit(EvtResponse, cmd.ID, MapS{"status": "ok"})
}

// handleSetVerificationMode sets the verification mode, persists it, and
// restarts the server if running (to apply the new mode to incoming
// connections).
func (d *Daemon) handleSetVerificationMode(cmd Command) {
	var params SetVerificationModeParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	mode := VerificationMode(params.Mode)
	if mode < VerificationModeStrict || mode > VerificationModeAutoAccept {
		d.emitError(cmd.ID, fmt.Sprintf("invalid mode: %d", params.Mode))
		return
	}

	d.mu.Lock()
	d.verifMode = mode
	serverRunning := d.server != nil
	d.mu.Unlock()

	if store := d.store(); store != nil {
		_ = store.SetSettings("daemon", "verification_mode",
			fmt.Sprintf("%d", params.Mode))
	}

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "ok", "mode": fmt.Sprintf("%d", params.Mode),
	})

	if serverRunning {
		d.handleRestartServer(Command{ID: ""})
	}
}

// handleGetVerificationMode returns the current verification mode.
func (d *Daemon) handleGetVerificationMode(cmd Command) {
	d.mu.RLock()
	mode := d.verifMode
	d.mu.RUnlock()
	d.emit(EvtResponse, cmd.ID, MapS{"mode": fmt.Sprintf("%d", mode)})
}

func truncateSessionID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:8] + "..." + id[len(id)-4:]
}
