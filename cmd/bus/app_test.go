package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
)

func TestAppVersionConstant(t *testing.T) {
	if appVersion != "2.0.0" {
		t.Errorf("appVersion = %q, want %q", appVersion, "2.0.0")
	}
	if appVersion == "" {
		t.Error("appVersion should not be empty")
	}
}

func TestDBPathDefault(t *testing.T) {
	a := &App{
		dbPath: func() string {
			home, _ := os.UserHomeDir()
			return home + "/.config/kamune/db"
		}(),
	}
	if a.GetDBPath() == "" {
		t.Error("default DB path should not be empty")
	}
}

func TestGetDBPath(t *testing.T) {
	a := &App{}
	original := a.GetDBPath()

	a.dbPath = "/tmp/test-kamune-db"
	if a.GetDBPath() != "/tmp/test-kamune-db" {
		t.Errorf("DBPath = %q, want %q", a.GetDBPath(), "/tmp/test-kamune-db")
	}

	a.dbPath = original
	if a.GetDBPath() != original {
		t.Errorf("DBPath = %q, want %q", a.GetDBPath(), original)
	}
}

func TestDBPathConcurrency(t *testing.T) {
	a := &App{dbPath: "/initial/path"}
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			a.mu.Lock()
			a.dbPath = "/path/" + string(rune('a'+id))
			a.mu.Unlock()
		}(i)
	}

	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := a.GetDBPath()
			if p == "" {
				t.Error("DBPath should never be empty during concurrent access")
			}
		}()
	}

	wg.Wait()
	if a.GetDBPath() == "" {
		t.Error("final DBPath should not be empty")
	}
}

func TestMessageInfoStruct(t *testing.T) {
	now := time.Now()
	msg := MessageInfo{
		Text:      "Test message",
		Timestamp: now,
		IsLocal:   true,
	}

	if msg.Text != "Test message" {
		t.Errorf("Text = %q, want %q", msg.Text, "Test message")
	}
	if !msg.Timestamp.Equal(now) {
		t.Error("timestamp mismatch")
	}
	if !msg.IsLocal {
		t.Error("expected IsLocal to be true")
	}
}

func TestMessageAppend(t *testing.T) {
	msgs := make([]MessageInfo, 0)

	msg1 := MessageInfo{Text: "Hello", Timestamp: time.Now(), IsLocal: true}
	msg2 := MessageInfo{Text: "World", Timestamp: time.Now(), IsLocal: false}

	msgs = append(msgs, msg1)
	msgs = append(msgs, msg2)

	if len(msgs) != 2 {
		t.Errorf("len = %d, want 2", len(msgs))
	}
	if msgs[0].Text != "Hello" {
		t.Errorf("msgs[0].Text = %q, want %q", msgs[0].Text, "Hello")
	}
	if !msgs[0].IsLocal {
		t.Error("expected first message to be local")
	}
	if msgs[1].IsLocal {
		t.Error("expected second message to be from peer")
	}
}

func TestTruncateSessionID(t *testing.T) {
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
		if result != tc.expected {
			t.Errorf("truncateSessionID(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestConcurrentSliceAccess(t *testing.T) {
	var mu sync.RWMutex
	sessions := make([]*liveSession, 0)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
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
		t.Errorf("len(sessions) = %d, want 10", len(sessions))
	}
}

func TestSessionRemoval(t *testing.T) {
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

	if len(sessions) != 2 {
		t.Errorf("len = %d, want 2", len(sessions))
	}
	for _, s := range sessions {
		if s.ID == targetID {
			t.Errorf("session %q should have been removed", targetID)
		}
	}
}

func TestConnectionStatusValues(t *testing.T) {
	values := []ConnectionStatus{
		StatusDisconnected,
		StatusConnecting,
		StatusConnected,
		StatusError,
	}
	seen := make(map[ConnectionStatus]bool)
	for _, v := range values {
		if seen[v] {
			t.Errorf("duplicate ConnectionStatus value: %q", v)
		}
		seen[v] = true
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 distinct ConnectionStatus values, got %d", len(seen))
	}
}

func TestVerificationModeValues(t *testing.T) {
	modes := []VerificationMode{
		VerificationModeStrict,
		VerificationModeQuick,
		VerificationModeAutoAccept,
	}
	seen := make(map[VerificationMode]bool)
	for _, m := range modes {
		if seen[m] {
			t.Errorf("duplicate VerificationMode value: %d", m)
		}
		seen[m] = true
	}
	if len(seen) != 3 {
		t.Errorf("expected 3 distinct VerificationMode values, got %d", len(seen))
	}
}

func TestMessageTimestampOrdering(t *testing.T) {
	now := time.Now()
	messages := []MessageInfo{
		{Text: "First", Timestamp: now.Add(-2 * time.Minute), IsLocal: true},
		{Text: "Second", Timestamp: now.Add(-1 * time.Minute), IsLocal: false},
		{Text: "Third", Timestamp: now, IsLocal: true},
	}

	for i := 0; i < len(messages)-1; i++ {
		if !messages[i+1].Timestamp.After(messages[i].Timestamp) {
			t.Errorf("message %d should be after message %d", i+1, i)
		}
	}
}

func TestEmptySessionList(t *testing.T) {
	sessions := make([]*liveSession, 0)
	if len(sessions) != 0 {
		t.Errorf("expected empty list, got len %d", len(sessions))
	}
	for _, s := range sessions {
		t.Errorf("should not iterate, got session %s", s.ID)
	}
}

func TestSenderTypeConstants(t *testing.T) {
	local := storage.SenderLocal
	peer := storage.SenderPeer
	if local == peer {
		t.Error("SenderLocal and SenderPeer should be different values")
	}
}

func TestLastActivityUpdate(t *testing.T) {
	then := time.Now().Add(-1 * time.Hour)
	lastActivity := then

	time.Sleep(10 * time.Millisecond)
	lastActivity = time.Now()

	if !lastActivity.After(then) {
		t.Error("LastActivity should be updated to a more recent time")
	}
}

func TestLiveSessionLifecycle(t *testing.T) {
	s := &liveSession{
		ID:          "test-session-123",
		PeerName:    "TestPeer",
		Messages:    make([]MessageInfo, 0),
		ReceiveDone: make(chan struct{}),
	}

	if s.ID != "test-session-123" {
		t.Errorf("ID = %q, want %q", s.ID, "test-session-123")
	}
	if s.PeerName != "TestPeer" {
		t.Errorf("PeerName = %q, want %q", s.PeerName, "TestPeer")
	}
	if len(s.Messages) != 0 {
		t.Errorf("expected empty messages, got %d", len(s.Messages))
	}
}

func TestHistorySessionInfo(t *testing.T) {
	now := time.Now()
	hs := HistorySessionInfo{
		ID:           "hist-session-abc",
		MessageCount: 42,
		FirstMessage: now.Add(-1 * time.Hour),
		LastMessage:  now,
		Loaded:       false,
	}

	if hs.ID != "hist-session-abc" {
		t.Errorf("ID = %q, want %q", hs.ID, "hist-session-abc")
	}
	if hs.MessageCount != 42 {
		t.Errorf("MessageCount = %d, want 42", hs.MessageCount)
	}
	if hs.Loaded {
		t.Error("history session should not be loaded initially")
	}
}

func TestSessionInfo(t *testing.T) {
	now := time.Now()
	info := SessionInfo{
		ID:           "session-123",
		PeerName:     "peer-name",
		IsServer:     true,
		MsgCount:     5,
		LastActivity: now,
	}

	if info.ID != "session-123" {
		t.Errorf("ID = %q", info.ID)
	}
	if !info.IsServer {
		t.Error("expected IsServer to be true")
	}
	if info.MsgCount != 5 {
		t.Errorf("MsgCount = %d, want 5", info.MsgCount)
	}
}

func TestLogEntryInfo(t *testing.T) {
	now := time.Now()
	entry := LogEntryInfo{
		Timestamp: now,
		Level:     "INFO",
		Message:   "test log",
	}

	if entry.Level != "INFO" {
		t.Errorf("Level = %q", entry.Level)
	}
	if entry.Message != "test log" {
		t.Errorf("Message = %q", entry.Message)
	}
}
