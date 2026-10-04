package main

import (
	"runtime"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

// heapInUse returns the bytes of live heap objects after a collection.
func heapInUse() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

func TestLiveSessionKeepsNoMessagesInMemory(t *testing.T) {
	a := require.New(t)
	d, _ := newTestDaemon(t, VerificationModeQuick, false)
	const (
		sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
		entries   = 96
		size      = 60 << 10
	)
	store := d.store()
	payload := make([]byte, size)
	for i := range entries {
		payload[0] = byte(i)
		a.NoError(store.AddChatEntry(
			sessionID, payload, time.Now(), storage.SenderPeer,
		))
	}

	// Leftover goroutines from other tests can change the heap while a
	// round runs, but not by the same amount in every round, whereas a
	// session that keeps its history grows it by the same amount each
	// time. The smallest growth of three rounds is compared.
	var grown int64
	for round := range 3 {
		session := &liveSession{ID: sessionID, LastActivity: time.Now()}
		before := heapInUse()
		d.loadChatHistory(session)
		for range entries {
			session.countMessage()
		}
		if g := heapInUse() - before; round == 0 || g < grown {
			grown = g
		}
		a.Equal(2*entries, d.sessionInfo(session).MsgCount)
		runtime.KeepAlive(session)
	}

	// The history is 5.6 MiB; a copy of it in memory would show here.
	a.Less(grown, int64(4<<20), "session keeps its history in memory")
}
