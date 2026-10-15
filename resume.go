package kamune

import (
	"crypto/hmac"
	"crypto/sha512"
	"sync"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	defaultResumeIdle   = 24 * time.Hour
	defaultResumeMaxAge = 7 * 24 * time.Hour
)

type resumeLockKey struct {
	store *storage.Storage
	sid   string
}

// resumeHold is one session's resume mutex. refs counts goroutines that
// have observed the entry and not yet finished TryLock or Unlock, so the
// entry is not deleted in that window.
type resumeHold struct {
	mu   sync.Mutex
	refs int
}

var (
	resumeMu    sync.Mutex
	resumeHolds = map[resumeLockKey]*resumeHold{}
)

// tryResumeLock locks one in-process resume of sid. The returned function
// releases the lock and drops the map entry once nobody holds it.
func tryResumeLock(store *storage.Storage, sid string) (func(), bool) {
	key := resumeLockKey{store: store, sid: sid}
	resumeMu.Lock()
	h := resumeHolds[key]
	if h == nil {
		h = &resumeHold{}
		resumeHolds[key] = h
	}
	h.refs++
	resumeMu.Unlock()

	if !h.mu.TryLock() {
		releaseResume(key, h)
		return nil, false
	}
	return func() {
		h.mu.Unlock()
		releaseResume(key, h)
	}, true
}

func releaseResume(key resumeLockKey, h *resumeHold) {
	resumeMu.Lock()
	h.refs--
	if h.refs == 0 {
		cur := resumeHolds[key]
		if cur == h {
			delete(resumeHolds, key)
		}
	}
	resumeMu.Unlock()
}

func binderKey(res []byte) ([]byte, error) {
	return expandLabel(res, "res binder", nil, hashLen)
}

func resPSK(res []byte) ([]byte, error) {
	return expandLabel(res, "res psk", nil, hashLen)
}

func macSHA512(key, msg []byte) []byte {
	m := hmac.New(sha512.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}
