package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestDBPathDefault(t *testing.T) {
	a := require.New(t)
	app := &App{
		dbPath: func() string {
			home, _ := os.UserHomeDir()
			return home + "/.config/kamune/db"
		}(),
	}
	a.NotEmpty(app.GetDBPath())
}

func TestGetDBPath(t *testing.T) {
	a := require.New(t)
	app := &App{}
	original := app.GetDBPath()

	app.dbPath = "/tmp/test-kamune-db"
	a.Equal("/tmp/test-kamune-db", app.GetDBPath())

	app.dbPath = original
	a.Equal(original, app.GetDBPath())
}

func TestDBPathConcurrency(t *testing.T) {
	a := require.New(t)
	app := &App{dbPath: "/initial/path"}
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			app.mu.Lock()
			app.dbPath = "/path/" + string(rune('a'+id))
			app.mu.Unlock()
		}(i)
	}

	for range 10 {
		wg.Go(func() {
			p := app.GetDBPath()
			a.NotEmpty(p, "DBPath should never be empty during concurrent access")
		})
	}

	wg.Wait()
	a.NotEmpty(app.GetDBPath(), "final DBPath should not be empty")
}

func TestMessageInfoStruct(t *testing.T) {
	a := require.New(t)
	now := time.Now()
	msg := MessageInfo{
		Text:      "Test message",
		Timestamp: now,
		IsLocal:   true,
	}

	a.Equal("Test message", msg.Text)
	a.True(msg.Timestamp.Equal(now), "timestamp mismatch")
	a.True(msg.IsLocal, "expected IsLocal to be true")
}

func TestMessageAppend(t *testing.T) {
	a := require.New(t)
	msgs := make([]MessageInfo, 0)

	msg1 := MessageInfo{Text: "Hello", Timestamp: time.Now(), IsLocal: true}
	msg2 := MessageInfo{Text: "World", Timestamp: time.Now(), IsLocal: false}

	msgs = append(msgs, msg1)
	msgs = append(msgs, msg2)

	a.Len(msgs, 2)
	a.Equal("Hello", msgs[0].Text)
	a.True(msgs[0].IsLocal, "expected first message to be local")
	a.False(msgs[1].IsLocal, "expected second message to be from peer")
}

func TestTruncateSessionID(t *testing.T) {
	a := require.New(t)
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},
		{"12345678abcdefgh", "12345678abcdefgh"},
		{"12345678901234567", "12345678...4567"},
		{"thisisalongersessionid", "thisisal...onid"},
		{"", ""},
		{"abc", "abc"},
		{"abcdefghijklmnop", "abcdefghijklmnop"},
		{"abcdefghijklmnopq", "abcdefgh...nopq"},
	}

	for _, tc := range tests {
		result := truncateSessionID(tc.input)
		a.Equal(tc.expected, result, "truncateSessionID(%q)", tc.input)
	}
}

func TestConcurrentSliceAccess(t *testing.T) {
	a := require.New(t)
	var mu sync.RWMutex
	sessions := make([]*liveSession, 0)
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mu.Lock()
			sessions = append(sessions, &liveSession{
				ID:       "session-" + string(rune('0'+id)),
				Messages: make([]MessageInfo, 0),
			})
			mu.Unlock()
		}(i)
	}

	for range 10 {
		wg.Go(func() {
			mu.RLock()
			_ = len(sessions)
			mu.RUnlock()
		})
	}

	wg.Wait()
	a.Len(sessions, 10)
}

func TestSessionRemoval(t *testing.T) {
	a := require.New(t)
	sessions := make([]*liveSession, 3)
	for i := range 3 {
		sessions[i] = &liveSession{
			ID: "session-" + string(rune('A'+i)),
		}
	}

	targetID := "session-B"
	for i, s := range sessions {
		if s.ID == targetID {
			sessions = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}

	a.Len(sessions, 2)
	for _, s := range sessions {
		a.NotEqual(targetID, s.ID, "session %q should have been removed", targetID)
	}
}

func TestConnectionStatusValues(t *testing.T) {
	a := require.New(t)
	values := []ConnectionStatus{
		StatusDisconnected,
		StatusConnecting,
		StatusConnected,
		StatusError,
	}
	seen := make(map[ConnectionStatus]bool)
	for _, v := range values {
		a.False(seen[v], "duplicate ConnectionStatus value: %q", v)
		seen[v] = true
	}
	a.Len(seen, 4)
}

func TestVerificationModeValues(t *testing.T) {
	a := require.New(t)
	modes := []VerificationMode{
		VerificationModeStrict,
		VerificationModeQuick,
		VerificationModeAutoAccept,
	}
	seen := make(map[VerificationMode]bool)
	for _, m := range modes {
		a.False(seen[m], "duplicate VerificationMode value: %d", m)
		seen[m] = true
	}
	a.Len(seen, 3)
}

func TestMessageTimestampOrdering(t *testing.T) {
	a := require.New(t)
	now := time.Now()
	messages := []MessageInfo{
		{Text: "First", Timestamp: now.Add(-2 * time.Minute), IsLocal: true},
		{Text: "Second", Timestamp: now.Add(-1 * time.Minute), IsLocal: false},
		{Text: "Third", Timestamp: now, IsLocal: true},
	}

	for i := 0; i < len(messages)-1; i++ {
		a.True(
			messages[i+1].Timestamp.After(messages[i].Timestamp),
			"message %d should be after message %d",
			i+1, i,
		)
	}
}

func TestEmptySessionList(t *testing.T) {
	a := require.New(t)
	sessions := make([]*liveSession, 0)
	a.Empty(sessions)
	for _, s := range sessions {
		a.Fail("should not iterate, got session %s", s.ID)
	}
}

func TestSenderTypeConstants(t *testing.T) {
	a := require.New(t)
	local := storage.SenderLocal
	peer := storage.SenderPeer
	a.NotEqual(local, peer, "SenderLocal and SenderPeer should be different values")
}

func TestLastActivityUpdate(t *testing.T) {
	a := require.New(t)
	then := time.Now().Add(-1 * time.Hour)
	lastActivity := then

	time.Sleep(10 * time.Millisecond)
	lastActivity = time.Now()

	a.True(lastActivity.After(then), "LastActivity should be updated to a more recent time")
}

func TestLiveSessionLifecycle(t *testing.T) {
	a := require.New(t)
	s := &liveSession{
		ID:          "test-session-123",
		PeerName:    "TestPeer",
		Messages:    make([]MessageInfo, 0),
		ReceiveDone: make(chan struct{}),
	}

	a.Equal("test-session-123", s.ID)
	a.Equal("TestPeer", s.PeerName)
	a.Empty(s.Messages)
}

func TestHistorySessionInfo(t *testing.T) {
	a := require.New(t)
	now := time.Now()
	hs := HistorySessionInfo{
		ID:           "hist-session-abc",
		MessageCount: 42,
		FirstMessage: now.Add(-1 * time.Hour),
		LastMessage:  now,
		Loaded:       false,
	}

	a.Equal("hist-session-abc", hs.ID)
	a.Equal(42, hs.MessageCount)
	a.False(hs.Loaded, "history session should not be loaded initially")
}

func TestSessionInfo(t *testing.T) {
	a := require.New(t)
	now := time.Now()
	info := SessionInfo{
		ID:           "session-123",
		PeerName:     "peer-name",
		IsServer:     true,
		MsgCount:     5,
		LastActivity: now,
	}

	a.Equal("session-123", info.ID)
	a.True(info.IsServer, "expected IsServer to be true")
	a.Equal(5, info.MsgCount)
}

func TestLogEntryInfo(t *testing.T) {
	a := require.New(t)
	now := time.Now()
	entry := LogEntryInfo{
		Timestamp: now,
		Level:     "INFO",
		Message:   "test log",
	}

	a.Equal("INFO", entry.Level)
	a.Equal("test log", entry.Message)
}
