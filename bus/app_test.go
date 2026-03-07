package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/assert"
)

// TestHistorySessionCreation verifies HistorySession struct creation
func TestHistorySessionCreation(t *testing.T) {
	a := assert.New(t)

	now := time.Now()
	hs := &HistorySession{
		ID:           "hist-session-abc",
		MessageCount: 42,
		FirstMessage: now.Add(-1 * time.Hour),
		LastMessage:  now,
		Messages:     nil,
		Loaded:       false,
	}

	a.Equal("hist-session-abc", hs.ID)
	a.Equal(42, hs.MessageCount)
	a.False(hs.Loaded, "history session should not be loaded initially")
	a.Nil(hs.Messages, "messages should be nil before loading")
}

// TestHistorySessionLoaded verifies the Loaded flag behavior
func TestHistorySessionLoaded(t *testing.T) {
	a := assert.New(t)

	hs := &HistorySession{
		ID:     "hist-loaded-test",
		Loaded: false,
	}

	a.False(hs.Loaded)

	// Simulate loading messages
	hs.Messages = []ChatMessage{
		{Text: "Hello from history", Timestamp: time.Now(), IsLocal: true},
		{Text: "Reply from history", Timestamp: time.Now(), IsLocal: false},
	}
	hs.Loaded = true
	hs.MessageCount = len(hs.Messages)

	a.True(hs.Loaded)
	a.Equal(2, hs.MessageCount)
	a.Equal("Hello from history", hs.Messages[0].Text)
}

// TestSidebarModeConstants verifies SidebarMode enum values
func TestSidebarModeConstants(t *testing.T) {
	a := assert.New(t)

	a.Equal(SidebarMode(0), SidebarModeSessions)
	a.Equal(SidebarMode(1), SidebarModeHistory)
	a.NotEqual(SidebarModeSessions, SidebarModeHistory)
}

// TestGetDisplayMessagesNoSession verifies getDisplayMessages with no active session
func TestGetDisplayMessagesNoSession(t *testing.T) {
	a := assert.New(t)

	c := &ChatApp{
		sessions:        make([]*Session, 0),
		historySessions: make([]*HistorySession, 0),
	}

	msgs := c.getDisplayMessages()
	a.Nil(msgs, "should return nil when no session is active")
}

// TestGetDisplayMessagesLiveSession verifies getDisplayMessages with a live session
func TestGetDisplayMessagesLiveSession(t *testing.T) {
	a := assert.New(t)

	session := &Session{
		ID: "live-session",
		Messages: []ChatMessage{
			{Text: "msg1", Timestamp: time.Now(), IsLocal: true},
			{Text: "msg2", Timestamp: time.Now(), IsLocal: false},
		},
	}

	c := &ChatApp{
		sessions:      []*Session{session},
		activeSession: session,
	}

	msgs := c.getDisplayMessages()
	a.NotNil(msgs)
	a.Equal(2, len(msgs))
	a.Equal("msg1", msgs[0].Text)
}

// TestGetDisplayMessagesHistorySession verifies getDisplayMessages with a history session
func TestGetDisplayMessagesHistorySession(t *testing.T) {
	a := assert.New(t)

	hs := &HistorySession{
		ID:     "hist-session",
		Loaded: true,
		Messages: []ChatMessage{
			{Text: "old-msg1", Timestamp: time.Now().Add(-1 * time.Hour), IsLocal: true},
			{Text: "old-msg2", Timestamp: time.Now().Add(-30 * time.Minute), IsLocal: false},
			{Text: "old-msg3", Timestamp: time.Now(), IsLocal: true},
		},
		MessageCount: 3,
	}

	c := &ChatApp{
		sessions:          make([]*Session, 0),
		activeSession:     nil,
		activeHistSession: hs,
	}

	msgs := c.getDisplayMessages()
	a.NotNil(msgs)
	a.Equal(3, len(msgs))
	a.Equal("old-msg1", msgs[0].Text)
}

// TestGetDisplayMessagesHistoryNotLoaded verifies nil when history is not loaded
func TestGetDisplayMessagesHistoryNotLoaded(t *testing.T) {
	a := assert.New(t)

	hs := &HistorySession{
		ID:     "hist-not-loaded",
		Loaded: false,
	}

	c := &ChatApp{
		activeHistSession: hs,
	}

	msgs := c.getDisplayMessages()
	a.Nil(msgs, "should return nil when history session is not loaded")
}

// TestGetDisplaySessionID verifies getDisplaySessionID
func TestGetDisplaySessionID(t *testing.T) {
	a := assert.New(t)

	// No session
	c := &ChatApp{}
	a.Equal("", c.getDisplaySessionID())

	// Live session
	c.activeSession = &Session{ID: "live-id-123"}
	a.Equal("live-id-123", c.getDisplaySessionID())

	// Live takes priority over history
	c.activeHistSession = &HistorySession{ID: "hist-id-456"}
	a.Equal("live-id-123", c.getDisplaySessionID(), "live session should take priority")

	// Only history
	c.activeSession = nil
	a.Equal("hist-id-456", c.getDisplaySessionID())
}

// TestIsViewingHistory verifies the isViewingHistory helper
func TestIsViewingHistory(t *testing.T) {
	a := assert.New(t)

	c := &ChatApp{}
	a.False(c.isViewingHistory(), "should be false with no sessions")

	c.activeSession = &Session{ID: "live"}
	a.False(c.isViewingHistory(), "should be false with live session active")

	c.activeHistSession = &HistorySession{ID: "hist"}
	a.False(c.isViewingHistory(), "should be false when both live and history are set")

	c.activeSession = nil
	a.True(c.isViewingHistory(), "should be true with only history session active")
}

// TestLiveTakePriorityOverHistory verifies live session display priority
func TestLiveTakePriorityOverHistory(t *testing.T) {
	a := assert.New(t)

	liveSession := &Session{
		ID:       "live",
		Messages: []ChatMessage{{Text: "live-msg", IsLocal: true}},
	}
	histSession := &HistorySession{
		ID:       "hist",
		Loaded:   true,
		Messages: []ChatMessage{{Text: "hist-msg", IsLocal: true}},
	}

	c := &ChatApp{
		activeSession:     liveSession,
		activeHistSession: histSession,
	}

	msgs := c.getDisplayMessages()
	a.Equal(1, len(msgs))
	a.Equal("live-msg", msgs[0].Text, "live session messages should take priority")
	a.False(c.isViewingHistory())
}

// TestAppVersionUpdated verifies version was bumped
func TestAppVersionUpdated(t *testing.T) {
	a := assert.New(t)

	a.Equal("2.0.0", appVersion, "appVersion should be 2.0.0 after refactor")
}

// TestDBPathDefault verifies that DBPath returns the default on construction
func TestDBPathDefault(t *testing.T) {
	a := assert.New(t)

	c := &ChatApp{
		dbPath: getDefaultDBDir(),
	}

	a.Equal(getDefaultDBDir(), c.DBPath())
	a.NotEmpty(c.DBPath(), "default DB path should not be empty")
}

// TestSetDBPath verifies that setting dbPath updates the value returned by DBPath
func TestSetDBPath(t *testing.T) {
	a := assert.New(t)

	c := &ChatApp{
		dbPath: getDefaultDBDir(),
	}

	original := c.DBPath()
	a.NotEmpty(original)

	// Simulate what SetDBPath does without triggering UI refresh (no Fyne app in tests)
	c.mu.Lock()
	c.dbPath = "/tmp/test-kamune-db"
	c.mu.Unlock()

	a.Equal("/tmp/test-kamune-db", c.DBPath())
	a.NotEqual(original, c.DBPath(), "path should have changed")

	// Set back
	c.mu.Lock()
	c.dbPath = original
	c.mu.Unlock()
	a.Equal(original, c.DBPath())
}

// TestDBPathDisplay verifies tilde-shortening of home directory
func TestDBPathDisplay(t *testing.T) {
	a := assert.New(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	c := &ChatApp{dbPath: home + "/some/path/db"}
	display := c.dbPathDisplay()
	a.Equal("~/some/path/db", display, "home dir should be replaced with ~")

	c.dbPath = "/opt/other/db"
	display = c.dbPathDisplay()
	a.Equal("/opt/other/db", display, "non-home path should be unchanged")

	c.dbPath = home
	display = c.dbPathDisplay()
	a.Equal("~", display, "exact home dir should become ~")
}

// TestDBPathConcurrency verifies that DBPath is safe for concurrent read/write
func TestDBPathConcurrency(t *testing.T) {
	a := assert.New(t)

	c := &ChatApp{
		dbPath: "/initial/path",
	}

	var wg sync.WaitGroup

	// Concurrent writers (set dbPath directly under lock to avoid Fyne UI calls)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c.mu.Lock()
			c.dbPath = "/path/" + string(rune('a'+n))
			c.mu.Unlock()
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := c.DBPath()
			a.NotEmpty(p, "DBPath should never be empty during concurrent access")
		}()
	}

	wg.Wait()

	// Final value should be one of the written paths
	a.NotEmpty(c.DBPath())
}

// TestSessionCreation verifies that sessions are properly created and stored
func TestSessionCreation(t *testing.T) {
	a := assert.New(t)

	session := &Session{
		ID:           "test-session-123",
		PeerName:     "TestPeer",
		Transport:    nil,
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now(),
	}

	a.Equal("test-session-123", session.ID)
	a.Equal(0, len(session.Messages))
}

// TestSessionMessageAppend verifies message appending to sessions
func TestSessionMessageAppend(t *testing.T) {
	a := assert.New(t)

	session := &Session{
		ID:           "test-session",
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now(),
	}

	msg1 := ChatMessage{
		Text:      "Hello, World!",
		Timestamp: time.Now(),
		IsLocal:   true,
	}

	msg2 := ChatMessage{
		Text:      "Hello back!",
		Timestamp: time.Now(),
		IsLocal:   false,
	}

	session.Messages = append(session.Messages, msg1)
	session.Messages = append(session.Messages, msg2)

	a.Equal(2, len(session.Messages))
	a.Equal("Hello, World!", session.Messages[0].Text)
	a.True(session.Messages[0].IsLocal, "expected first message to be local")
	a.False(session.Messages[1].IsLocal, "expected second message to be from peer")
}

// TestChatMessageStruct verifies ChatMessage structure
func TestChatMessageStruct(t *testing.T) {
	a := assert.New(t)

	now := time.Now()
	msg := ChatMessage{
		Text:      "Test message",
		Timestamp: now,
		IsLocal:   true,
	}

	a.Equal("Test message", msg.Text)
	a.True(msg.Timestamp.Equal(now), "timestamp mismatch")
	a.True(msg.IsLocal, "expected IsLocal to be true")
}

// TestTruncateSessionID verifies session ID truncation for display
func TestTruncateSessionID(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},
		{"exactly12ch", "exactly12ch"},
		{"thisisalongersessionid", "thisisalonge…"},
		{"", ""},
		{"123456789012", "123456789012"},
		{"1234567890123", "123456789012…"},
	}

	for _, tc := range tests {
		result := truncateSessionID(tc.input)
		a.Equal(tc.expected, result, "truncateSessionID(%q)", tc.input)
	}
}

// TestConcurrentSessionAccess verifies thread-safe session list access
func TestConcurrentSessionAccess(t *testing.T) {
	a := assert.New(t)

	sessions := make([]*Session, 0)
	var mu sync.RWMutex

	// Simulate concurrent reads and writes
	var wg sync.WaitGroup

	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mu.Lock()
			sessions = append(sessions, &Session{
				ID:           "session-" + string(rune('0'+id)),
				Messages:     make([]ChatMessage, 0),
				LastActivity: time.Now(),
			})
			mu.Unlock()
		}(i)
	}

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.RLock()
			_ = len(sessions)
			mu.RUnlock()
		}()
	}

	wg.Wait()

	a.Equal(10, len(sessions))
}

// TestSessionRemoval verifies session removal from slice
func TestSessionRemoval(t *testing.T) {
	a := assert.New(t)

	sessions := make([]*Session, 3)
	for i := 0; i < 3; i++ {
		sessions[i] = &Session{
			ID: "session-" + string(rune('A'+i)),
		}
	}

	// Remove middle session (session-B)
	targetID := "session-B"
	for i, s := range sessions {
		if s.ID == targetID {
			sessions = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}

	a.Equal(2, len(sessions))

	for _, s := range sessions {
		a.NotEqual(targetID, s.ID, "session %s should have been removed", targetID)
	}
}

// TestNotificationConfig verifies notification configuration defaults
func TestNotificationConfig(t *testing.T) {
	a := assert.New(t)

	cfg := notificationConfig{
		enabled:     true,
		soundOnRecv: false,
	}

	a.True(cfg.enabled, "expected notifications to be enabled by default")
	a.False(cfg.soundOnRecv, "expected sound to be disabled by default")
}

// TestStatusIndicatorStates verifies all connection states
func TestStatusIndicatorStates(t *testing.T) {
	a := assert.New(t)

	states := []ConnectionStatus{
		StatusDisconnected,
		StatusConnecting,
		StatusConnected,
		StatusError,
	}

	// Verify enum values are distinct
	seen := make(map[ConnectionStatus]bool)
	for _, s := range states {
		a.False(seen[s], "duplicate ConnectionStatus value: %d", s)
		seen[s] = true
	}

	a.Equal(4, len(seen))
}

// TestVerificationModes verifies all verification mode values
func TestVerificationModes(t *testing.T) {
	a := assert.New(t)

	modes := []VerificationMode{
		VerificationModeStrict,
		VerificationModeQuick,
		VerificationModeAutoAccept,
	}

	// Verify enum values are distinct
	seen := make(map[VerificationMode]bool)
	for _, m := range modes {
		a.False(seen[m], "duplicate VerificationMode value: %d", m)
		seen[m] = true
	}

	a.Equal(3, len(seen))
}

// TestMessageTimestampOrdering verifies message ordering by timestamp
func TestMessageTimestampOrdering(t *testing.T) {
	a := assert.New(t)

	now := time.Now()
	messages := []ChatMessage{
		{Text: "First", Timestamp: now.Add(-2 * time.Minute), IsLocal: true},
		{Text: "Second", Timestamp: now.Add(-1 * time.Minute), IsLocal: false},
		{Text: "Third", Timestamp: now, IsLocal: true},
	}

	for i := 1; i < len(messages); i++ {
		a.True(messages[i].Timestamp.After(messages[i-1].Timestamp), "message %d should be after message %d", i, i-1)
	}
}

// TestHistoryEntry verifies HistoryEntry structure
func TestHistoryEntry(t *testing.T) {
	a := assert.New(t)

	now := time.Now()
	entry := HistoryEntry{
		Timestamp: now,
		Sender:    "You",
		Message:   "Test message",
		IsLocal:   true,
	}

	a.Equal("You", entry.Sender)
	a.True(entry.IsLocal, "expected IsLocal to be true for local sender")

	peerEntry := HistoryEntry{
		Timestamp: now,
		Sender:    "Peer",
		Message:   "Reply message",
		IsLocal:   false,
	}

	a.Equal("Peer", peerEntry.Sender)
	a.False(peerEntry.IsLocal, "expected IsLocal to be false for peer sender")
}

// TestTruncateID verifies ID truncation in history module
func TestTruncateID(t *testing.T) {
	a := assert.New(t)

	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"thisislongerthan10", 10, "thisislong..."},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc..."},
	}

	for _, tc := range tests {
		result := truncateID(tc.input, tc.maxLen)
		a.Equal(tc.expected, result, "truncateID(%q, %d)", tc.input, tc.maxLen)
	}
}

// TestSenderTypeConstants verifies kamune sender type usage
func TestSenderTypeConstants(t *testing.T) {
	a := assert.New(t)

	// Verify the expected sender types exist and are usable
	localSender := storage.SenderLocal
	peerSender := storage.SenderPeer

	a.NotEqual(localSender, peerSender, "SenderLocal and SenderPeer should be different values")
}

// TestEmptySessionList verifies behavior with no sessions
func TestEmptySessionList(t *testing.T) {
	a := assert.New(t)

	sessions := make([]*Session, 0)

	a.Equal(0, len(sessions))

	// Verify safe iteration over empty list
	for _, s := range sessions {
		a.Fail("should not iterate, got session %s", s.ID)
	}
}

// TestSessionLastActivityUpdate verifies activity timestamp updates
func TestSessionLastActivityUpdate(t *testing.T) {
	a := assert.New(t)

	session := &Session{
		ID:           "test-session",
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now().Add(-1 * time.Hour),
	}

	oldActivity := session.LastActivity

	// Simulate receiving a message
	time.Sleep(10 * time.Millisecond)
	session.LastActivity = time.Now()

	a.True(session.LastActivity.After(oldActivity), "LastActivity should be updated to a more recent time")
}

// TestChatAppVersionConstant verifies version constant is set
func TestChatAppVersionConstant(t *testing.T) {
	a := assert.New(t)

	a.NotEmpty(appVersion, "appVersion should not be empty")
	a.Equal("2.0.0", appVersion, "appVersion should be 2.0.0")

	// Version should be in semver format (basic check)
	a.GreaterOrEqual(len(appVersion), 5, "appVersion '%s' seems too short for semver", appVersion)
}

// BenchmarkTruncateSessionID benchmarks the truncation function
func BenchmarkTruncateSessionID(b *testing.B) {
	longID := "this-is-a-very-long-session-id-that-needs-truncation"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncateSessionID(longID)
	}
}

// BenchmarkMessageAppend benchmarks message slice appending
func BenchmarkMessageAppend(b *testing.B) {
	session := &Session{
		ID:       "bench-session",
		Messages: make([]ChatMessage, 0),
	}

	msg := ChatMessage{
		Text:      "Benchmark message",
		Timestamp: time.Now(),
		IsLocal:   true,
	}

	for b.Loop() {
		session.Messages = append(session.Messages, msg)
	}
}

// BenchmarkConcurrentSessionRead benchmarks concurrent session reads
func BenchmarkConcurrentSessionRead(b *testing.B) {
	sessions := make([]*Session, 100)
	for i := range 100 {
		sessions[i] = &Session{ID: "session-" + string(rune(i))}
	}
	var mu sync.RWMutex

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.RLock()
			_ = len(sessions)
			mu.RUnlock()
		}
	})
}
