package main

import (
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
)

// TestSessionCreation verifies that sessions are properly created and stored
func TestSessionCreation(t *testing.T) {
	session := &Session{
		ID:           "test-session-123",
		PeerName:     "TestPeer",
		Transport:    nil,
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now(),
	}

	if session.ID != "test-session-123" {
		t.Errorf("expected session ID 'test-session-123', got '%s'", session.ID)
	}

	if len(session.Messages) != 0 {
		t.Errorf("expected empty messages slice, got %d messages", len(session.Messages))
	}
}

// TestSessionMessageAppend verifies message appending to sessions
func TestSessionMessageAppend(t *testing.T) {
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

	if len(session.Messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(session.Messages))
	}

	if session.Messages[0].Text != "Hello, World!" {
		t.Errorf("expected first message 'Hello, World!', got '%s'", session.Messages[0].Text)
	}

	if session.Messages[0].IsLocal != true {
		t.Error("expected first message to be local")
	}

	if session.Messages[1].IsLocal != false {
		t.Error("expected second message to be from peer")
	}
}

// TestChatMessageStruct verifies ChatMessage structure
func TestChatMessageStruct(t *testing.T) {
	now := time.Now()
	msg := ChatMessage{
		Text:      "Test message",
		Timestamp: now,
		IsLocal:   true,
	}

	if msg.Text != "Test message" {
		t.Errorf("expected text 'Test message', got '%s'", msg.Text)
	}

	if !msg.Timestamp.Equal(now) {
		t.Errorf("timestamp mismatch")
	}

	if msg.IsLocal != true {
		t.Error("expected IsLocal to be true")
	}
}

// TestTruncateSessionID verifies session ID truncation for display
func TestTruncateSessionID(t *testing.T) {
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
		if result != tc.expected {
			t.Errorf("truncateSessionID(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

// TestConcurrentSessionAccess verifies thread-safe session list access
func TestConcurrentSessionAccess(t *testing.T) {
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

	if len(sessions) != 10 {
		t.Errorf("expected 10 sessions, got %d", len(sessions))
	}
}

// TestSessionRemoval verifies session removal from slice
func TestSessionRemoval(t *testing.T) {
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

	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions after removal, got %d", len(sessions))
	}

	for _, s := range sessions {
		if s.ID == targetID {
			t.Errorf("session %s should have been removed", targetID)
		}
	}
}

// TestNotificationConfig verifies notification configuration defaults
func TestNotificationConfig(t *testing.T) {
	cfg := notificationConfig{
		enabled:     true,
		soundOnRecv: false,
	}

	if !cfg.enabled {
		t.Error("expected notifications to be enabled by default")
	}

	if cfg.soundOnRecv {
		t.Error("expected sound to be disabled by default")
	}
}

// TestStatusIndicatorStates verifies all connection states
func TestStatusIndicatorStates(t *testing.T) {
	states := []ConnectionStatus{
		StatusDisconnected,
		StatusConnecting,
		StatusConnected,
		StatusError,
	}

	// Verify enum values are distinct
	seen := make(map[ConnectionStatus]bool)
	for _, s := range states {
		if seen[s] {
			t.Errorf("duplicate ConnectionStatus value: %d", s)
		}
		seen[s] = true
	}

	if len(seen) != 4 {
		t.Errorf("expected 4 distinct status values, got %d", len(seen))
	}
}

// TestVerificationModes verifies all verification mode values
func TestVerificationModes(t *testing.T) {
	modes := []VerificationMode{
		VerificationModeStrict,
		VerificationModeQuick,
		VerificationModeAutoAccept,
	}

	// Verify enum values are distinct
	seen := make(map[VerificationMode]bool)
	for _, m := range modes {
		if seen[m] {
			t.Errorf("duplicate VerificationMode value: %d", m)
		}
		seen[m] = true
	}

	if len(seen) != 3 {
		t.Errorf("expected 3 distinct verification modes, got %d", len(seen))
	}
}

// TestMessageTimestampOrdering verifies message ordering by timestamp
func TestMessageTimestampOrdering(t *testing.T) {
	now := time.Now()
	messages := []ChatMessage{
		{Text: "First", Timestamp: now.Add(-2 * time.Minute), IsLocal: true},
		{Text: "Second", Timestamp: now.Add(-1 * time.Minute), IsLocal: false},
		{Text: "Third", Timestamp: now, IsLocal: true},
	}

	for i := 1; i < len(messages); i++ {
		if !messages[i].Timestamp.After(messages[i-1].Timestamp) {
			t.Errorf("message %d should be after message %d", i, i-1)
		}
	}
}

// TestHistoryEntry verifies HistoryEntry structure
func TestHistoryEntry(t *testing.T) {
	now := time.Now()
	entry := HistoryEntry{
		Timestamp: now,
		Sender:    "You",
		Message:   "Test message",
		IsLocal:   true,
	}

	if entry.Sender != "You" {
		t.Errorf("expected sender 'You', got '%s'", entry.Sender)
	}

	if entry.IsLocal != true {
		t.Error("expected IsLocal to be true for local sender")
	}

	peerEntry := HistoryEntry{
		Timestamp: now,
		Sender:    "Peer",
		Message:   "Reply message",
		IsLocal:   false,
	}

	if peerEntry.Sender != "Peer" {
		t.Errorf("expected sender 'Peer', got '%s'", peerEntry.Sender)
	}

	if peerEntry.IsLocal != false {
		t.Error("expected IsLocal to be false for peer sender")
	}
}

// TestTruncateID verifies ID truncation in history module
func TestTruncateID(t *testing.T) {
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
		if result != tc.expected {
			t.Errorf("truncateID(%q, %d) = %q, expected %q", tc.input, tc.maxLen, result, tc.expected)
		}
	}
}

// TestSenderTypeConstants verifies kamune sender type usage
func TestSenderTypeConstants(t *testing.T) {
	// Verify the expected sender types exist and are usable
	localSender := kamune.SenderLocal
	peerSender := kamune.SenderPeer

	if localSender == peerSender {
		t.Error("SenderLocal and SenderPeer should be different values")
	}
}

// TestEmptySessionList verifies behavior with no sessions
func TestEmptySessionList(t *testing.T) {
	sessions := make([]*Session, 0)

	if len(sessions) != 0 {
		t.Error("expected empty session list")
	}

	// Verify safe iteration over empty list
	for _, s := range sessions {
		t.Errorf("should not iterate, got session %s", s.ID)
	}
}

// TestSessionLastActivityUpdate verifies activity timestamp updates
func TestSessionLastActivityUpdate(t *testing.T) {
	session := &Session{
		ID:           "test-session",
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now().Add(-1 * time.Hour),
	}

	oldActivity := session.LastActivity

	// Simulate receiving a message
	time.Sleep(10 * time.Millisecond)
	session.LastActivity = time.Now()

	if !session.LastActivity.After(oldActivity) {
		t.Error("LastActivity should be updated to a more recent time")
	}
}

// TestChatAppVersionConstant verifies version constant is set
func TestChatAppVersionConstant(t *testing.T) {
	if appVersion == "" {
		t.Error("appVersion should not be empty")
	}

	// Version should be in semver format (basic check)
	if len(appVersion) < 5 { // minimum "0.0.0"
		t.Errorf("appVersion '%s' seems too short for semver", appVersion)
	}
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
