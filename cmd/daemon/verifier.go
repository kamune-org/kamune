package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	verifTimeout = 2 * time.Minute
	// maxPendingVerifications caps the verify_peer prompts for unknown
	// peers that connect to the server and may be open at once.
	maxPendingVerifications = 8
)

var (
	// errVerificationPending rejects a peer that connects to the server,
	// without asking the user, while a verification of the same key from
	// another inbound connection is pending.
	errVerificationPending = fmt.Errorf(
		"%w: a verification of this peer is already pending",
		kamune.ErrVerificationFailed,
	)
	// errTooManyVerifications rejects an unknown peer that connects to
	// the server, without asking the user, while maxPendingVerifications
	// such peers are pending.
	errTooManyVerifications = fmt.Errorf(
		"%w: too many verifications are pending",
		kamune.ErrVerificationFailed,
	)
)

type pendingVerification struct {
	result chan error
	peerID string
	hex    string
	key    string
	// inbound is true for a peer that connected to the server, and false
	// for one the user dialed.
	inbound bool
	// known is true for a peer that is in storage.
	known bool
}

// inboundVerifier returns the verifier for peers that connect to the
// server. Anyone who can reach the server can open its prompts, so it
// limits them: see beginVerification.
func (d *Daemon) inboundVerifier() kamune.RemoteVerifier {
	return d.getVerifier(true)
}

// outboundVerifier returns the verifier for peers the user dials, by the
// dial command or a reconnect. These are never rejected for the prompts
// that inbound peers hold open, so a flood of inbound connections cannot
// stop the user from reaching a peer.
func (d *Daemon) outboundVerifier() kamune.RemoteVerifier {
	return d.getVerifier(false)
}

// getVerifier returns a kamune.RemoteVerifier based on the current mode. An
// unknown mode gets the Strict verifier. inbound tells whether it checks
// peers that connect to the server or peers the user dials.
func (d *Daemon) getVerifier(inbound bool) kamune.RemoteVerifier {
	d.mu.RLock()
	mode := d.verifMode
	d.mu.RUnlock()

	switch mode {
	case VerificationModeQuick:
		return d.createQuickVerifier(inbound)
	case VerificationModeAutoAccept:
		return d.createAutoAcceptVerifier()
	default:
		return d.createStrictVerifier(inbound)
	}
}

// parseVerificationMode returns the mode a stored setting names, and false
// when it names none.
func parseVerificationMode(s string) (VerificationMode, bool) {
	mode, err := strconv.Atoi(s)
	if err != nil || mode < int(VerificationModeStrict) ||
		mode > int(VerificationModeAutoAccept) {
		return 0, false
	}
	return VerificationMode(mode), true
}

func (d *Daemon) createStrictVerifier(inbound bool) kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		known := false
		if _, err := store.FindPeer(peer.PublicKey); err == nil {
			known = true
		}

		if err := d.askUser(peer, known, inbound, "strict"); err != nil {
			return err
		}

		if !known && !d.isIncognito() {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		return nil
	}
}

func (d *Daemon) createQuickVerifier(inbound bool) kamune.RemoteVerifier {
	return func(store *storage.Storage, peer *storage.Peer) error {
		if _, err := store.FindPeer(peer.PublicKey); err == nil {
			d.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name)
			return nil
		}

		if err := d.askUser(peer, false, inbound, "quick"); err != nil {
			return err
		}

		if !d.isIncognito() {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
			}
		}

		return nil
	}
}

// createAutoAcceptVerifier accepts every peer without asking. It does not
// store new peers: nobody verified them, and Quick mode accepts a stored
// peer without asking. A session with a peer that is not stored cannot be
// resumed.
func (d *Daemon) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(_ *storage.Storage, peer *storage.Peer) error {
		d.addLogEntry("INFO", "Auto-accepted peer: "+peer.Name)
		return nil
	}
}

// askUser emits verify_peer for peer and waits for the user's verdict, for
// at most verifTimeout. For a peer that connected to the server it fails
// closed when beginVerification says so: the peer is rejected at once
// without asking.
func (d *Daemon) askUser(
	peer *storage.Peer, known, inbound bool, mode string,
) error {
	key := peer.PublicKey
	hexFP := fingerprint.Hex(key)

	reqID, result, err := d.beginVerification(peer, hexFP, known, inbound)
	if err != nil {
		d.addLogEntry("WARN",
			"Rejected peer "+peer.Name+" without asking: "+err.Error())
		return err
	}
	defer d.endVerification(reqID)

	d.addLogEntry("INFO", "Verifying peer: "+peer.Name)
	d.emit(EvtVerifyPeer, "", MapA{
		"request_id": reqID,
		"peer_name":  peer.Name,
		"emoji":      fingerprint.Emoji(key),
		"hex":        hexFP,
		"known":      known,
		"mode":       mode,
	})

	return d.awaitVerification(reqID, result)
}

// beginVerification records a pending verification of peer and returns its
// request ID and the channel its verdict arrives on. While verifications
// are pending the status is verifying; endVerification puts back the last
// other status that was current when one of them began.
//
// Only a peer that connected to the server (inbound) can be rejected,
// because anyone who reaches the server can open these prompts: it gets
// errVerificationPending while another inbound connection with its key is
// pending, and, when it is unknown, errTooManyVerifications while
// maxPendingVerifications unknown inbound peers are pending. Nothing is
// recorded then. A known peer is not capped, so a flood of unknown keys
// cannot lock it out, and the per-key check allows each stored key one
// prompt. A peer the user dials is never rejected here.
func (d *Daemon) beginVerification(
	peer *storage.Peer, hexFP string, known, inbound bool,
) (int64, chan error, error) {
	key := string(peer.PublicKey)

	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	if inbound {
		unknown := 0
		for _, p := range d.verifRequests {
			if !p.inbound {
				continue
			}
			if p.key == key {
				return 0, nil, errVerificationPending
			}
			if !p.known {
				unknown++
			}
		}
		if !known && unknown >= maxPendingVerifications {
			return 0, nil, errTooManyVerifications
		}
	}
	d.mu.RLock()
	if d.status != StatusVerifying {
		d.verifPrevStatus = d.status
		d.verifPrevMsg = d.statusMsg
	}
	d.mu.RUnlock()

	reqID := d.verifIDCounter.Add(1)
	result := make(chan error, 1)
	d.verifRequests[reqID] = &pendingVerification{
		result:  result,
		peerID:  peer.Name,
		hex:     hexFP,
		key:     key,
		inbound: inbound,
		known:   known,
	}
	d.setStatus(StatusVerifying, "Verifying fingerprint of "+peer.Name+"...")
	return reqID, result, nil
}

// endVerification removes the pending verification reqID. When no other
// is pending, the status that beginVerification saved is put back, unless
// something else has changed the status since.
func (d *Daemon) endVerification(reqID int64) {
	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	if _, ok := d.verifRequests[reqID]; !ok {
		return
	}
	delete(d.verifRequests, reqID)
	if len(d.verifRequests) > 0 {
		return
	}

	d.mu.Lock()
	if d.status != StatusVerifying {
		d.mu.Unlock()
		return
	}
	d.status = d.verifPrevStatus
	d.statusMsg = d.verifPrevMsg
	d.mu.Unlock()
	d.emit(EvtStatusChanged, "", MapS{
		"status": string(d.verifPrevStatus), "message": d.verifPrevMsg,
	})
}

// awaitVerification waits for the verdict on reqID, for at most
// verifTimeout. A verification that times out leaves the status alone: one
// peer's prompt does not decide the daemon's status.
func (d *Daemon) awaitVerification(reqID int64, result chan error) error {
	timer := time.NewTimer(verifTimeout)
	defer timer.Stop()

	select {
	case verdict := <-result:
		return verdict
	case <-timer.C:
		d.addLogEntry("WARN",
			fmt.Sprintf("Verification timed out for request: %d", reqID))
		return fmt.Errorf("verification timed out after %v", verifTimeout)
	case <-d.ctx.Done():
		return d.ctx.Err()
	}
}

// handleVerifyResponse handles a verify_response command.
func (d *Daemon) handleVerifyResponse(cmd Command) {
	var params VerifyResponseParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.verifMu.Lock()
	pending, ok := d.verifRequests[params.RequestID]
	d.verifMu.Unlock()

	if !ok {
		d.addLogEntry("WARN",
			fmt.Sprintf("Verification request not found: %d", params.RequestID))
		d.emitError(cmd.ID, "verification_not_found", "verification request not found")
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
		d.emitError(cmd.ID, "invalid_params", fmt.Sprintf("invalid params: %v", err))
		return
	}

	mode := VerificationMode(params.Mode)
	if mode < VerificationModeStrict || mode > VerificationModeAutoAccept {
		d.emitError(cmd.ID, "invalid_verification_mode", fmt.Sprintf("invalid mode: %d", params.Mode))
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
