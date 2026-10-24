package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	// defaultVerifTimeout is how long a verify_peer prompt waits for
	// verify_response before the peer is rejected.
	defaultVerifTimeout = 2 * time.Minute
	// maxPromptsPerMinute caps how many verify_peer prompts may open in
	// any rolling minute. Further unknown keys are rejected with no
	// prompt (RFC007 §20.1).
	maxPromptsPerMinute = 6
)

var (
	// errVerifierBusy rejects a handshake that needs a prompt while
	// another prompt is already open. RFC007 §20.1: one open prompt,
	// including the user's own dials.
	errVerifierBusy = fmt.Errorf(
		"%w: a verification prompt is already open",
		kamune.ErrVerificationFailed,
	)
	// errPromptRateLimited rejects an unknown key that needs a prompt
	// after maxPromptsPerMinute prompts in the last minute.
	errPromptRateLimited = fmt.Errorf(
		"%w: too many verification prompts",
		kamune.ErrVerificationFailed,
	)
	// errServerStopped rejects a peer that connected to the server while
	// its verification was pending and the server stopped.
	errServerStopped = fmt.Errorf(
		"%w: the server stopped", kamune.ErrVerificationFailed,
	)
)

type pendingVerification struct {
	result   chan error
	peerID   string
	peerCode string
	key      string
	// inbound is true for a peer that connected to the server, and false
	// for one the user dialed.
	inbound bool
	// known is true for a peer that is in storage.
	known bool
}

// inboundVerifier returns the verifier for peers that connect to the
// server. It verifies each peer in the mode in effect then, so
// set_verification_mode applies to a running server without a restart.
func (d *Daemon) inboundVerifier() kamune.RemoteVerifier {
	return d.peerVerifier(true)
}

// outboundVerifier returns the verifier for peers the user dials, by the
// dial command or a reconnect. The one-open-prompt and per-minute caps
// apply here too (RFC007 §20.1).
func (d *Daemon) outboundVerifier() kamune.RemoteVerifier {
	return d.peerVerifier(false)
}

// peerVerifier returns a kamune.RemoteVerifier for the current mode.
// inbound tells whether the peer connected to the server.
func (d *Daemon) peerVerifier(inbound bool) kamune.RemoteVerifier {
	return func(
		ctx context.Context, store *storage.Storage, req kamune.VerifyRequest,
	) error {
		d.mu.RLock()
		mode := d.verifMode
		d.mu.RUnlock()
		if mode < VerificationModeStrict ||
			mode > VerificationModeAutoAccept {
			mode = VerificationModeStrict
		}
		return d.verifyPeer(ctx, store, req, mode, inbound)
	}
}

// verifierShouldPrompt reports whether mode and req require a user prompt
// (RFC007 §16.1). known is whether the authenticated key is a stored,
// unexpired peer.
func verifierShouldPrompt(
	mode VerificationMode, req kamune.VerifyRequest, known bool,
) bool {
	switch mode {
	case VerificationModeAutoAccept:
		return false
	case VerificationModeQuick:
		if req.Role == kamune.RoleInitiator {
			return !req.Pinned
		}
		return !req.Resumed && !req.Pinned && !known
	default:
		if req.Role == kamune.RoleInitiator &&
			req.Pinned && req.ResumeOffered {
			return false
		}
		return true
	}
}

func verificationModeName(mode VerificationMode) string {
	switch mode {
	case VerificationModeQuick:
		return "quick"
	case VerificationModeAutoAccept:
		return "auto"
	default:
		return "strict"
	}
}

func verifyRoleName(role kamune.Role) string {
	if role == kamune.RoleInitiator {
		return "initiator"
	}
	return "responder"
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

// The verifiers below only decide whether to admit a peer, while its
// handshake is still running. None of them stores the peer: a peer whose
// handshake fails after the user accepted it must not become a known
// peer, which Quick mode admits without asking. They note an unknown
// peer that the user accepted, and rememberPeer stores it once its
// session is established.

func (d *Daemon) verifyPeer(
	ctx context.Context,
	store *storage.Storage,
	req kamune.VerifyRequest,
	mode VerificationMode,
	inbound bool,
) error {
	peer := req.Peer
	d.forgetAdmitted(peer.PublicKey)
	id := identifyPeer(store, peer)
	if !verifierShouldPrompt(mode, req, id.Known) {
		d.addLogEntry("INFO", "Auto-accepted peer: "+id.logName())
		return nil
	}
	if err := d.askUser(ctx, req, id, inbound, mode); err != nil {
		return err
	}
	if !id.Known {
		d.noteAdmitted(peer.PublicKey)
	}
	return nil
}

// createAutoAcceptVerifier accepts every peer without asking. Its peers
// are not stored: nobody verified them, and Quick mode accepts a stored
// peer without asking. A session with a peer that is not stored cannot be
// resumed.
func (d *Daemon) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(
		_ context.Context, store *storage.Storage, req kamune.VerifyRequest,
	) error {
		peer := req.Peer
		d.forgetAdmitted(peer.PublicKey)
		d.addLogEntry("INFO",
			"Auto-accepted peer: "+identifyPeer(store, peer).logName())
		return nil
	}
}

// noteAdmitted records that the user accepted the unknown peer with key,
// so that rememberPeer stores it once its session is established.
func (d *Daemon) noteAdmitted(key []byte) {
	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	d.admitted[string(key)] = struct{}{}
}

// forgetAdmitted drops the note of noteAdmitted for key. Each verification
// of a key starts with it, so a note left by a handshake that failed does
// not outlive the next verdict on the key.
func (d *Daemon) forgetAdmitted(key []byte) {
	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	delete(d.admitted, string(key))
}

// rememberPeer stores peer, the remote peer of a session that has just
// been established, when the user accepted it as an unknown peer; see
// noteAdmitted. It stores nothing for a session that started in
// incognito mode (incognito), nor while incognito mode is on, nor a peer
// that is stored already.
//
// The stored name names the peer in every later session and prompt, so
// the name the peer claimed is stored only when no other stored peer has
// it (see sameName); a peer that claims another peer's name, or none, is
// stored under the pseudonym of its key.
func (d *Daemon) rememberPeer(
	store *storage.Storage, peer *storage.Peer, incognito bool,
) {
	if store == nil || peer == nil {
		return
	}
	key := string(peer.PublicKey)
	d.verifMu.Lock()
	_, ok := d.admitted[key]
	delete(d.admitted, key)
	d.verifMu.Unlock()
	if !ok || incognito || d.isIncognito() {
		return
	}
	if _, err := store.FindPeer(peer.PublicKey); err == nil {
		return
	}
	name := strings.TrimSpace(peer.Name)
	if nameKey(name) == "" ||
		hasName(otherPeersNames(store, peer.PublicKey), name) {
		name = fingerprint.Pseudonym(peer.PublicKey)
	}
	now := time.Now()
	if err := store.StorePeer(&storage.Peer{
		Name:       name,
		PublicKey:  peer.PublicKey,
		AppVersion: peer.AppVersion,
		FirstSeen:  now,
		LastSeen:   now,
	}); err != nil {
		d.addLogEntry("WARN", "Failed to save peer: "+err.Error())
	}
}

// collidingStoredName returns the stored peer whose name EqualFold-matches
// the unknown peer's claimed name, if any (RFC007 §20.1).
func collidingStoredName(
	store *storage.Storage, peer *storage.Peer, known bool,
) *storage.Peer {
	if known || store == nil || peer == nil {
		return nil
	}
	name := strings.TrimSpace(peer.Name)
	if name == "" {
		return nil
	}
	peers, err := store.ListPeers()
	if err != nil {
		return nil
	}
	for _, p := range peers {
		if strings.EqualFold(p.Name, name) {
			p.PublicKey = bytes.Clone(p.PublicKey)
			return p
		}
	}
	return nil
}

// askUser emits verify_peer for req, which id describes, and waits for
// the user's verdict, for at most d.verifTimeout. It fails closed when
// beginVerification says so: the peer is rejected at once without asking.
func (d *Daemon) askUser(
	ctx context.Context,
	req kamune.VerifyRequest,
	id peerIdentity,
	inbound bool,
	mode VerificationMode,
) error {
	peer := req.Peer
	peerCode := fingerprint.Numeric(peer.PublicKey)

	reqID, result, err := d.beginVerification(
		peer, id, peerCode, inbound,
	)
	if err != nil {
		return err
	}
	defer d.endVerification(reqID)

	peerName := ""
	if req.Role != kamune.RoleInitiator {
		peerName = peer.Name
	}
	storedName := ""
	if id.Known {
		storedName = id.Label
	}
	storedCode := ""
	hit := collidingStoredName(d.store(), peer, id.Known)
	if hit != nil {
		storedName = hit.Name
		storedCode = fingerprint.Numeric(hit.PublicKey)
		d.addLogEntry("INFO",
			"A NEW key is using the name of your contact "+hit.Name)
	}

	d.addLogEntry("INFO", "Verifying peer: "+id.logName())
	d.emit(EvtVerifyPeer, "", MapA{
		"request_id":     reqID,
		"role":           verifyRoleName(req.Role),
		"peer_name":      peerName,
		"stored_name":    storedName,
		"stored_code":    storedCode,
		"name_collision": hit != nil,
		"own_code":       fingerprint.Numeric(req.LocalPublicKey),
		"peer_code":      peerCode,
		"safety_number": fingerprint.SafetyNumber(
			req.LocalPublicKey, peer.PublicKey,
		),
		"known":          id.Known,
		"mode":           verificationModeName(mode),
		"pinned":         req.Pinned,
		"resume_offered": req.ResumeOffered,
		"resumed":        req.Resumed,
		"session_id":     req.SessionID,
	})

	return d.awaitVerification(ctx, reqID, result)
}

// beginVerification records a pending verification of peer and returns its
// request ID and the channel its verdict arrives on. While a verification
// is pending the status is verifying; endVerification puts back the last
// other status that was current when it began.
//
// At most one prompt may be open. A second handshake that needs a prompt
// gets errVerifierBusy. Unknown keys that need a prompt after
// maxPromptsPerMinute prompts in the last minute get errPromptRateLimited.
func (d *Daemon) beginVerification(
	peer *storage.Peer, id peerIdentity, peerCode string, inbound bool,
) (int64, chan error, error) {
	key := string(peer.PublicKey)

	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	if len(d.verifRequests) > 0 {
		d.addLogEntry("DEBUG",
			"Rejected peer "+id.logName()+" without asking: "+
				errVerifierBusy.Error())
		return 0, nil, errVerifierBusy
	}
	now := time.Now()
	d.prunePromptTimesLocked(now)
	if !id.Known && len(d.promptTimes) >= maxPromptsPerMinute {
		d.addLogEntry("WARN",
			"Rejected unknown peer "+id.logName()+
				" without asking: too many prompts this minute")
		return 0, nil, errPromptRateLimited
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
		result:   result,
		peerID:   id.Label,
		peerCode: peerCode,
		key:      key,
		inbound:  inbound,
		known:    id.Known,
	}
	d.promptTimes = append(d.promptTimes, now)
	d.setStatus(StatusVerifying, "Verifying fingerprint of "+id.Label+"...")
	return reqID, result, nil
}

func (d *Daemon) prunePromptTimesLocked(now time.Time) {
	cut := now.Add(-time.Minute)
	i := 0
	for i < len(d.promptTimes) && !d.promptTimes[i].After(cut) {
		i++
	}
	if i > 0 {
		d.promptTimes = d.promptTimes[i:]
	}
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

// rejectInboundVerifications rejects every pending verification of a peer
// that connected to the server, as the server stops. Its prompt ends, and
// so does its handshake, which the stopped server would drop anyway.
func (d *Daemon) rejectInboundVerifications() {
	d.verifMu.Lock()
	defer d.verifMu.Unlock()
	for _, p := range d.verifRequests {
		if !p.inbound {
			continue
		}
		select {
		case p.result <- errServerStopped:
		default:
		}
	}
}

// awaitVerification waits for the verdict on reqID, for at most
// d.verifTimeout. A verification that times out leaves the status alone:
// one peer's prompt does not decide the daemon's status.
func (d *Daemon) awaitVerification(
	ctx context.Context, reqID int64, result chan error,
) error {
	timer := time.NewTimer(d.verifTimeout)
	defer timer.Stop()

	select {
	case verdict := <-result:
		return verdict
	case <-timer.C:
		d.addLogEntry("WARN",
			fmt.Sprintf("Verification timed out for request: %d", reqID))
		return fmt.Errorf("verification timed out after %v", d.verifTimeout)
	case <-ctx.Done():
		return ctx.Err()
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

// handleSetVerificationMode sets the verification mode and persists it.
// The verifiers read the mode when they verify a peer, so the new mode
// applies to the next peer verified, by a running server too. The server
// is not restarted, and live sessions and relay tokens are kept.
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
	d.mu.Unlock()

	if store := d.store(); store != nil {
		_ = store.SetSettings("daemon", "verification_mode",
			fmt.Sprintf("%d", params.Mode))
	}

	d.emit(EvtResponse, cmd.ID, MapS{
		"status": "ok", "mode": fmt.Sprintf("%d", params.Mode),
	})
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

// handshakeErrorCode maps a handshake error to a daemon error code
// (RFC007 §6). Match sentinels by identity so kamune.ErrHandshakeRejected
// does not collide with a later relayleg.ErrHandshakeRejected.
func handshakeErrorCode(err error) string {
	switch {
	case errors.Is(err, kamune.ErrVersionMismatch):
		return "version_mismatch"
	case errors.Is(err, kamune.ErrSelfConnection):
		return "self_connection"
	case errors.Is(err, kamune.ErrPeerKeyMismatch),
		errors.Is(err, errPeerKeyMismatch):
		return "peer_key_mismatch"
	case errors.Is(err, kamune.ErrUnsupportedProtocol):
		return "unsupported_protocol"
	case errors.Is(err, kamune.ErrVerificationFailed):
		return "verification_failed"
	case errors.Is(err, kamune.ErrResumeRefused):
		return "resume_refused"
	case errors.Is(err, kamune.ErrHandshakeRejected):
		return "handshake_rejected"
	default:
		return ""
	}
}
