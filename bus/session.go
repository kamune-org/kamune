package main

import (
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
