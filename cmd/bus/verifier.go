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

const (
	// maxPromptsPerMinute caps how many verify-peer prompts may open in
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
)

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
// peers the user dials.
func (a *App) verifierWithin(
	ctx context.Context, mode VerificationMode, inbound bool,
) kamune.RemoteVerifier {
	if mode < VerificationModeStrict || mode > VerificationModeAutoAccept {
		mode = VerificationModeStrict
	}
	return func(
		vctx context.Context, store *storage.Storage, req kamune.VerifyRequest,
	) error {
		return a.verifyPeer(ctx, store, req, mode, inbound)
	}
}

// pinPeer returns a verifier that rejects a peer whose key is not want
// before rv sees it. Listener gates still use this; dials pin with
// DialWithPeerKey instead (RFC007 §20.3).
func (a *App) pinPeer(
	want []byte, rv kamune.RemoteVerifier,
) kamune.RemoteVerifier {
	if want == nil {
		return rv
	}
	return func(
		ctx context.Context, store *storage.Storage, req kamune.VerifyRequest,
	) error {
		peer := req.Peer
		if !bytes.Equal(peer.PublicKey, want) {
			a.addLogEntry("WARN",
				"Rejected peer "+a.identifyPeer(store, peer).logName()+
					": its key is not the selected peer's key")
			return ErrPeerKeyMismatch
		}
		return rv(ctx, store, req)
	}
}

// The verifiers below only decide whether to admit a peer. None of them
// saves the peer: rememberPeer does that once the session is established.

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

func (a *App) verifyPeer(
	ctx context.Context,
	store *storage.Storage,
	req kamune.VerifyRequest,
	mode VerificationMode,
	inbound bool,
) error {
	peer := req.Peer
	id := a.identifyPeer(store, peer)
	if !verifierShouldPrompt(mode, req, id.Known) {
		a.addLogEntry("INFO", "Auto-accepted peer: "+id.logName())
		return nil
	}
	return a.askUser(ctx, req, id, inbound, mode)
}

// createAutoAcceptVerifier admits every peer without asking.
func (a *App) createAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(
		_ context.Context, store *storage.Storage, req kamune.VerifyRequest,
	) error {
		peer := req.Peer
		a.addLogEntry("INFO",
			"Auto-accepted peer: "+a.identifyPeer(store, peer).logName())
		return nil
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

// askUser emits verify-peer for req, which id describes, and waits for
// the user's verdict. It fails closed when beginVerification says so.
func (a *App) askUser(
	ctx context.Context,
	req kamune.VerifyRequest,
	id peerIdentity,
	inbound bool,
	mode VerificationMode,
) error {
	if ctx.Err() != nil {
		return ErrVerificationCancelled
	}
	peer := req.Peer
	reqID, result, err := a.beginVerification(id, inbound)
	if err != nil {
		return err
	}
	defer a.endVerification(reqID)

	peerName := ""
	if req.Role != kamune.RoleInitiator {
		peerName = peer.Name
	}
	storedName := ""
	if id.Known {
		storedName = id.Label
	}
	storedCode := ""
	hit := collidingStoredName(a.store(), peer, id.Known)
	if hit != nil {
		storedName = hit.Name
		storedCode = fingerprint.Numeric(hit.PublicKey)
		a.addLogEntry("INFO",
			"A NEW key is using the name of your contact "+hit.Name)
	}

	a.setStatus(StatusVerifying, verifyingStatus(id.Label))
	a.addLogEntry("INFO", "Verifying peer: "+id.logName())

	a.emitEvent("verify-peer", map[string]any{
		"requestID":     reqID,
		"role":          verifyRoleName(req.Role),
		"peerName":      peerName,
		"nickname":      fingerprint.Pseudonym(peer.PublicKey),
		"storedName":    storedName,
		"storedCode":    storedCode,
		"nameCollision": hit != nil,
		"ownCode":       fingerprint.Numeric(req.LocalPublicKey),
		"peerCode":      fingerprint.Numeric(peer.PublicKey),
		"safetyNumber": fingerprint.SafetyNumber(
			req.LocalPublicKey, peer.PublicKey,
		),
		"known":         id.Known,
		"mode":          verificationModeName(mode),
		"pinned":        req.Pinned,
		"resumeOffered": req.ResumeOffered,
		"resumed":       req.Resumed,
		"sessionID":     req.SessionID,
	})

	return a.awaitVerification(ctx, reqID, result)
}

func verifyingStatus(label string) string {
	return "Verifying fingerprint of " + label + "..."
}

// beginVerification records a pending verification and returns its
// request ID and the channel its verdict arrives on. At most one prompt
// may be open. Unknown keys that need a prompt after
// maxPromptsPerMinute prompts in the last minute get errPromptRateLimited.
func (a *App) beginVerification(
	id peerIdentity, inbound bool,
) (int64, chan error, error) {
	a.verifMu.Lock()
	defer a.verifMu.Unlock()
	if len(a.verifRequests) > 0 {
		a.addLogEntry("DEBUG",
			"Rejected peer "+id.logName()+" without asking: "+
				errVerifierBusy.Error())
		return 0, nil, errVerifierBusy
	}
	now := time.Now()
	a.prunePromptTimesLocked(now)
	if !id.Known && len(a.promptTimes) >= maxPromptsPerMinute {
		a.addLogEntry("WARN",
			"Rejected unknown peer "+id.logName()+
				" without asking: too many prompts this minute")
		return 0, nil, errPromptRateLimited
	}

	if len(a.verifRequests) == 0 {
		a.verifPrevStatus = a.GetStatus()
	}
	reqID := a.verifIDCounter.Add(1)
	result := make(chan error, 1)
	a.verifRequests[reqID] = &pendingVerification{
		result:  result,
		label:   id.Label,
		inbound: inbound,
	}
	a.promptTimes = append(a.promptTimes, now)
	return reqID, result, nil
}

func (a *App) prunePromptTimesLocked(now time.Time) {
	cut := now.Add(-time.Minute)
	i := 0
	for i < len(a.promptTimes) && !a.promptTimes[i].After(cut) {
		i++
	}
	if i > 0 {
		a.promptTimes = a.promptTimes[i:]
	}
}

// endVerification closes request reqID and emits verify-peer-closed.
// When the last prompt closes, the status from before it opened comes
// back, unless something else has changed the status in the meantime.
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
		return fmt.Errorf("%w: no answer within %v",
			kamune.ErrVerificationFailed, timeout)
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
