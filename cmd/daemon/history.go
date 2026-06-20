package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// loadIdentityAndHistory reads the identity, settings, and history sessions
// from the store. Called after open_storage and submit_passphrase.
func (d *Daemon) loadIdentityAndHistory() {
	store := d.store()
	if store == nil {
		return
	}

	if pubKey, err := store.PublicKey(); err == nil {
		emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
		b64 := fingerprint.Base64(pubKey)
		hexFP := fingerprint.Hex(pubKey)
		sum := fingerprint.Sum(pubKey)

		d.mu.Lock()
		d.pubKey = pubKey
		d.mu.Unlock()

		d.emit(EvtFingerprintChange, "", MapA{
			"emoji": emoji, "b64": b64, "hex": hexFP, "sum": sum,
		})

		name, nameErr := store.GetSettings("daemon", "local_name")
		if nameErr == nil && name == "" {
			name = fingerprint.Pseudonym(pubKey)
			_ = store.SetSettings("daemon", "local_name", name)
		}
		if nameErr == nil && name != "" {
			d.mu.Lock()
			d.myName = name
			d.mu.Unlock()
			d.emit(EvtLocalNameChanged, "", MapS{"name": name})
		}
		d.addLogEntry("INFO", "Loaded identity from existing storage")
	} else {
		d.addLogEntry("DEBUG", "No identity key found: "+err.Error())
	}

	if modeStr, err := store.GetSettings("daemon", "verification_mode"); err == nil && modeStr != "" {
		if mode, err := strconv.Atoi(modeStr); err == nil {
			d.mu.Lock()
			d.verifMode = VerificationMode(mode)
			d.mu.Unlock()
		}
	}

	d.loadHistorySessions()
}

// loadHistorySessions refreshes the history cache from the store.
func (d *Daemon) loadHistorySessions() {
	store := d.store()
	if store == nil {
		return
	}

	summaries, err := store.ListSessionsByRecent()
	if err != nil {
		d.addLogEntry("WARN", "Could not list history sessions: "+err.Error())
		return
	}

	d.mu.Lock()
	d.histSessions = make([]*historySession, 0, len(summaries))
	for _, s := range summaries {
		d.histSessions = append(d.histSessions, &historySession{
			ID:           s.ID,
			Name:         s.Name,
			MessageCount: s.MessageCount,
			FirstMessage: s.FirstMessage,
			LastMessage:  s.LastMessage,
		})
	}
	d.mu.Unlock()

	d.emit(EvtHistoryUpdated, "", MapS{})
}

// handleGetHistorySessions returns the cached history session list.
func (d *Daemon) handleGetHistorySessions(cmd Command) {
	d.mu.RLock()
	sessions := make([]HistorySessionInfo, 0, len(d.histSessions))
	for _, hs := range d.histSessions {
		sessions = append(sessions, HistorySessionInfo{
			ID:           hs.ID,
			Name:         hs.Name,
			MessageCount: hs.MessageCount,
			FirstMessage: hs.FirstMessage,
			LastMessage:  hs.LastMessage,
			Loaded:       hs.Loaded,
		})
	}
	d.mu.RUnlock()
	d.emit(EvtResponse, cmd.ID, MapA{"sessions": sessions})
}

// handleGetHistoryMessages returns messages for a history session. Requires
// the session to have been loaded via load_history first.
func (d *Daemon) handleGetHistoryMessages(cmd Command) {
	var params GetHistoryMessagesParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.RLock()
	var found bool
	for _, hs := range d.histSessions {
		if hs.ID == params.SessionID && hs.Loaded {
			found = true
			break
		}
	}
	d.mu.RUnlock()

	if !found {
		d.emitError(
			cmd.ID,
			"history session not loaded — call load_history first",
		)
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	entries, err := store.GetChatHistory(params.SessionID)
	if err != nil {
		d.addLogEntry("ERROR", "Failed to get chat history: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("failed to get chat history: %v", err))
		return
	}

	msgs := make([]MessageInfo, len(entries))
	for i, e := range entries {
		msgs[i] = MessageInfo{
			Text:      string(e.Data),
			Timestamp: e.Timestamp,
			IsLocal:   e.Sender == storage.SenderLocal,
		}
	}
	d.emit(EvtResponse, cmd.ID, MapA{"messages": msgs})
}

// handleLoadHistory marks a history session as loaded.
func (d *Daemon) handleLoadHistory(cmd Command) {
	var params LoadHistoryParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	d.mu.Lock()
	for _, hs := range d.histSessions {
		if hs.ID == params.SessionID {
			hs.Loaded = true
			break
		}
	}
	d.mu.Unlock()

	d.emit(EvtHistoryLoaded, "", MapS{"session_id": params.SessionID})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "loaded"})
}

// handleRenameHistorySession renames a history session.
func (d *Daemon) handleRenameHistorySession(cmd Command) {
	var params RenameHistorySessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	if err := store.SetSessionName(params.SessionID, params.Name); err != nil {
		d.addLogEntry("ERROR", "Failed to rename history session: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("failed to rename: %v", err))
		return
	}

	d.mu.Lock()
	for _, hs := range d.histSessions {
		if hs.ID == params.SessionID {
			hs.Name = params.Name
			break
		}
	}
	d.mu.Unlock()

	d.emit(EvtHistoryUpdated, "", MapS{})
	d.addLogEntry("INFO", "Renamed history session: "+params.SessionID)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "ok"})
}

// handleDeleteHistorySession deletes a history session.
func (d *Daemon) handleDeleteHistorySession(cmd Command) {
	var params DeleteHistorySessionParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	if err := store.DeleteSession(params.SessionID); err != nil {
		d.addLogEntry("ERROR", "Failed to delete history session: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("failed to delete: %v", err))
		return
	}

	d.mu.Lock()
	for i, hs := range d.histSessions {
		if hs.ID == params.SessionID {
			d.histSessions = append(d.histSessions[:i], d.histSessions[i+1:]...)
			break
		}
	}
	d.mu.Unlock()

	d.emit(EvtHistoryUpdated, "", MapS{})
	d.addLogEntry("INFO", "Deleted history session: "+params.SessionID)
	d.emit(EvtResponse, cmd.ID, MapS{"status": "deleted"})
}

// handleRefreshHistory re-runs loadHistorySessions.
func (d *Daemon) handleRefreshHistory(cmd Command) {
	d.loadHistorySessions()
	d.addLogEntry("INFO", "History refreshed")
	d.emit(EvtResponse, cmd.ID, MapS{"status": "refreshed"})
}

// handleListPeers returns all known peers.
func (d *Daemon) handleListPeers(cmd Command) {
	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	peers, err := store.ListPeers()
	if err != nil {
		d.addLogEntry("ERROR", "Failed to list peers: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("failed to list peers: %v", err))
		return
	}

	infos := make([]PeerInfo, len(peers))
	for i, p := range peers {
		infos[i] = PeerInfo{
			Name:       p.Name,
			AppVersion: p.AppVersion,
			FirstSeen:  p.FirstSeen,
			LastSeen:   p.LastSeen,
			PublicKey:  base64.StdEncoding.EncodeToString(p.PublicKey),
		}
	}
	d.emit(EvtResponse, cmd.ID, MapA{"peers": infos})
}

// handleDeletePeer removes a known peer.
func (d *Daemon) handleDeletePeer(cmd Command) {
	var params DeletePeerParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	store := d.store()
	if store == nil {
		d.emitError(cmd.ID, "storage is not available")
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(params.PublicKey)
	if err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid base64 public_key: %v", err))
		return
	}

	if err := store.DeletePeer(pubKey); err != nil {
		d.addLogEntry("ERROR", "Failed to delete peer: "+err.Error())
		d.emitError(cmd.ID, fmt.Sprintf("failed to delete peer: %v", err))
		return
	}

	d.addLogEntry("INFO", "Deleted peer")
	d.emit(EvtResponse, cmd.ID, MapS{"status": "deleted"})
}

// handleGetFingerprint returns the current fingerprint.
func (d *Daemon) handleGetFingerprint(cmd Command) {
	d.mu.RLock()
	pubKey := d.pubKey
	d.mu.RUnlock()

	if len(pubKey) == 0 {
		d.emit(EvtResponse, cmd.ID, MapA{
			"emoji": "", "b64": "", "hex": "", "sum": "",
		})
		return
	}

	emoji := strings.Join(fingerprint.Emoji(pubKey), " • ")
	d.emit(EvtResponse, cmd.ID, MapA{
		"emoji": emoji,
		"b64":   fingerprint.Base64(pubKey),
		"hex":   fingerprint.Hex(pubKey),
		"sum":   fingerprint.Sum(pubKey),
	})
}

// handleGetMyName returns the local display name.
func (d *Daemon) handleGetMyName(cmd Command) {
	d.mu.RLock()
	name := d.myName
	d.mu.RUnlock()
	d.emit(EvtResponse, cmd.ID, MapS{"name": name})
}

// handleSetMyName sets and persists the local display name.
func (d *Daemon) handleSetMyName(cmd Command) {
	var params SetMyNameParams
	if err := json.Unmarshal(cmd.Params, &params); err != nil {
		d.emitError(cmd.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	const maxNameLength = 32
	if len(params.Name) > maxNameLength {
		d.emitError(
			cmd.ID,
			fmt.Sprintf("name must be %d characters or fewer", maxNameLength),
		)
		return
	}

	store := d.store()
	if store != nil {
		if err := store.SetSettings("daemon", "local_name", params.Name); err != nil {
			d.emitError(cmd.ID, fmt.Sprintf("persist name: %v", err))
			return
		}
	}

	d.mu.Lock()
	d.myName = params.Name
	d.mu.Unlock()

	d.emit(EvtLocalNameChanged, "", MapS{"name": params.Name})
	d.emit(EvtResponse, cmd.ID, MapS{"status": "ok"})
}

// handleGetVersion returns the daemon version.
func (d *Daemon) handleGetVersion(cmd Command) {
	d.emit(EvtResponse, cmd.ID, MapS{"version": version})
}

// handleGetLibraryVersion returns the kamune library version.
func (d *Daemon) handleGetLibraryVersion(cmd Command) {
	d.emit(EvtResponse, cmd.ID, MapS{"version": kamune.AppVersion})
}
