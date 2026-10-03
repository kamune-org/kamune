package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStampRelaySession_TwoConsumedTokens(t *testing.T) {
	a := require.New(t)
	first := &tokenTracker{}
	second := &tokenTracker{}
	tokens := []relayToken{
		{Consumed: true, listener: first},
		{Consumed: true, listener: second},
	}
	stampRelaySession(tokens, second, "session-b")
	a.Empty(first.sessionID)
	a.Equal("session-b", second.sessionID)
	a.Empty(tokens[0].sessionID)
	a.Equal("session-b", tokens[1].sessionID)
}

func TestStampRelaySession_AfterSliceRemoval(t *testing.T) {
	a := require.New(t)
	tt := &tokenTracker{}
	stampRelaySession(nil, tt, "session-a")
	a.Equal("session-a", tt.sessionID)
}

func TestRelayReconnectLoop_EmptySessionDoesNotQueryRoot(t *testing.T) {
	a := require.New(t)
	id := relaySessionID(&tokenTracker{}, nil)
	a.Empty(id)
	_, ok := loadRelayPool(nil, id)
	a.False(ok)
}
