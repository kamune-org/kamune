package main

import (
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/bus/logger"
)

// loadChatHistory loads persisted chat entries from the database into the
// session's in-memory Messages slice. It must be called before the session is
// added to c.sessions so no locking is required.
func (c *ChatApp) loadChatHistory(session *Session) {
	if session.Transport == nil {
		return
	}

	store := session.Transport.Store()
	if store == nil {
		return
	}

	entries, err := store.GetChatHistory(session.ID)
	if err != nil {
		logger.Errorf("failed to load chat history for session %s: %v", session.ID, err)
		return
	}

	if len(entries) == 0 {
		return
	}

	msgs := make([]ChatMessage, 0, len(entries))
	for _, entry := range entries {
		msgs = append(msgs, ChatMessage{
			Text:      string(entry.Data),
			Timestamp: entry.Timestamp,
			IsLocal:   entry.Sender == kamune.SenderLocal,
		})
	}

	session.Messages = msgs
	session.LastActivity = entries[len(entries)-1].Timestamp
	logger.Infof("Loaded %d chat history entries for session %s", len(msgs), session.ID)
}

// saveSessionState persists the current transport state so the session can be
// resumed later. It is safe to call with a nil transport (it becomes a no-op).
func (c *ChatApp) saveSessionState(session *Session) {
	if session == nil || session.Transport == nil {
		return
	}

	// The server exposes its SessionManager; for client connections
	// the library already saves the state inside Dial(), but we save
	// again here to capture up-to-date sequence numbers.
	sm := sessionManagerForTransport(session.Transport)
	if sm == nil {
		logger.Infof("no session manager available for session %s, skipping state save", session.ID)
		return
	}

	if err := kamune.SaveSessionForResumption(session.Transport, sm); err != nil {
		logger.Errorf("failed to save session state for %s: %v", session.ID, err)
	} else {
		logger.Infof("Saved session state for %s", session.ID)
	}
}

// sessionManagerForTransport returns a SessionManager that wraps the
// transport's existing storage. It does not open a new database connection.
func sessionManagerForTransport(t *kamune.Transport) *kamune.SessionManager {
	if t == nil || t.Store() == nil {
		return nil
	}
	sm := kamune.NewSessionManager(t.Store(), 24*time.Hour)
	if sm == nil {
		logger.Warn("failed to create session manager from transport store")
	}
	return sm
}
