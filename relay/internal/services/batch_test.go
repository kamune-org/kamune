package services

import (
	"crypto/rand"
	"testing"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	store, err := storage.Open(config.Storage{
		InMemory: true,
		LogLevel: 8, // suppress logs
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Config{
		Server: config.Server{
			Identity: attest.Ed25519Algorithm,
		},
		Storage: config.Storage{
			RegisterTTL:    30 * 60 * 1e9, // 30m as time.Duration
			MaxMessageSize: 10240,
			MaxQueueSize:   10000,
		},
	}
	svc, err := New(store, cfg)
	require.NoError(t, err)
	return svc
}

func newTestKeys(t *testing.T) (attest.PublicKey, attest.PublicKey) {
	t.Helper()
	s, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)
	r, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)
	return s.PublicKey(), r.PublicKey()
}

// ---------------------------------------------------------------------------
// BatchPopQueue tests
// ---------------------------------------------------------------------------

func TestBatchPopQueue_Empty(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 10)
	a.NoError(err)
	a.NotNil(msgs)
	a.Empty(msgs)
}

func TestBatchPopQueue_LessThanLimit(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	// Push 3 messages.
	for i := range 3 {
		err := svc.PushQueue(sender, receiver, sessionID, []byte{byte(i)})
		a.NoError(err)
	}

	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 10)
	a.NoError(err)
	a.Len(msgs, 3)
	for i, msg := range msgs {
		a.Equal([]byte{byte(i)}, msg)
	}

	// Queue should now be empty.
	msgs, err = svc.BatchPopQueue(sender, receiver, sessionID, 10)
	a.NoError(err)
	a.Empty(msgs)
}

func TestBatchPopQueue_ExactlyLimit(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	for i := range 5 {
		err := svc.PushQueue(sender, receiver, sessionID, []byte{byte(i)})
		a.NoError(err)
	}

	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 5)
	a.NoError(err)
	a.Len(msgs, 5)
}

func TestBatchPopQueue_MoreThanLimit(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	for i := range 8 {
		err := svc.PushQueue(sender, receiver, sessionID, []byte{byte(i)})
		a.NoError(err)
	}

	// Only pop 3.
	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 3)
	a.NoError(err)
	a.Len(msgs, 3)
	a.Equal([]byte{0}, msgs[0])
	a.Equal([]byte{1}, msgs[1])
	a.Equal([]byte{2}, msgs[2])

	// Remaining 5 should still be there.
	remaining, err := svc.QueueLen(sender, receiver, sessionID)
	a.NoError(err)
	a.Equal(uint64(5), remaining)
}

func TestBatchPopQueue_DefaultLimit(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	for i := range 15 {
		err := svc.PushQueue(sender, receiver, sessionID, []byte{byte(i)})
		a.NoError(err)
	}

	// Pass 0 => should use DefaultBatchSize (10).
	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 0)
	a.NoError(err)
	a.Len(msgs, DefaultBatchSize)
}

func TestBatchPopQueue_ClampedToMax(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	// Push MaxBatchSize + 10 messages.
	for i := range MaxBatchSize + 10 {
		err := svc.PushQueue(sender, receiver, sessionID, []byte{byte(i % 256)})
		a.NoError(err)
	}

	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 999)
	a.NoError(err)
	a.Len(msgs, MaxBatchSize)
}

func TestBatchPopQueue_FIFOOrder(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	data := []string{"alpha", "beta", "gamma", "delta"}
	for _, d := range data {
		err := svc.PushQueue(sender, receiver, sessionID, []byte(d))
		a.NoError(err)
	}

	msgs, err := svc.BatchPopQueue(sender, receiver, sessionID, 10)
	a.NoError(err)
	a.Len(msgs, 4)
	for i, expected := range data {
		a.Equal(expected, string(msgs[i]))
	}
}

// ---------------------------------------------------------------------------
// RefreshPeer tests
// ---------------------------------------------------------------------------

func TestRefreshPeer_NotFound(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	_, err = svc.RefreshPeer(pubKey, nil)
	a.Error(err)
}

func TestRefreshPeer_PreservesAddresses(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	originalAddr := []string{"1.2.3.4:8080", "5.6.7.8:9090"}
	_, err = svc.RegisterPeer(pubKey, attest.Ed25519Algorithm, originalAddr)
	a.NoError(err)

	// Refresh without providing new addresses.
	refreshed, err := svc.RefreshPeer(pubKey, nil)
	a.NoError(err)
	a.NotNil(refreshed)
	a.Equal(originalAddr, refreshed.Address)
}

func TestRefreshPeer_UpdatesAddresses(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	_, err = svc.RegisterPeer(pubKey, attest.Ed25519Algorithm, []string{"old:1234"})
	a.NoError(err)

	newAddr := []string{"new:5678", "new:9012"}
	refreshed, err := svc.RefreshPeer(pubKey, newAddr)
	a.NoError(err)
	a.NotNil(refreshed)
	a.Equal(newAddr, refreshed.Address)

	// Verify the update persisted by inquiring.
	peer, err := svc.InquiryPeer(pubKey)
	a.NoError(err)
	a.Equal(newAddr, peer.Address)
}

func TestRefreshPeer_UpdatesRegisteredAt(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	original, err := svc.RegisterPeer(pubKey, attest.Ed25519Algorithm, []string{"1.2.3.4:80"})
	a.NoError(err)

	refreshed, err := svc.RefreshPeer(pubKey, nil)
	a.NoError(err)
	// RegisteredAt should be updated (at least not before the original).
	a.False(refreshed.RegisteredAt.Before(original.RegisteredAt))
}

// ---------------------------------------------------------------------------
// WebhookRegistry tests
// ---------------------------------------------------------------------------

func TestWebhookRegistry_RegisterAndLookup(t *testing.T) {
	a := assert.New(t)
	wr := NewWebhookRegistry()

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pk := at.PublicKey()

	a.Equal("", wr.Lookup(pk))

	wr.Register(pk, "https://example.com/hook")
	a.Equal("https://example.com/hook", wr.Lookup(pk))
}

func TestWebhookRegistry_ReplaceRegistration(t *testing.T) {
	a := assert.New(t)
	wr := NewWebhookRegistry()

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pk := at.PublicKey()

	wr.Register(pk, "https://example.com/old")
	wr.Register(pk, "https://example.com/new")
	a.Equal("https://example.com/new", wr.Lookup(pk))
}

func TestWebhookRegistry_Unregister(t *testing.T) {
	a := assert.New(t)
	wr := NewWebhookRegistry()

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pk := at.PublicKey()

	// Unregistering a non-existent key should return false.
	a.False(wr.Unregister(pk))

	wr.Register(pk, "https://example.com/hook")
	a.True(wr.Unregister(pk))
	a.Equal("", wr.Lookup(pk))

	// Unregistering again should return false.
	a.False(wr.Unregister(pk))
}

func TestWebhookRegistry_IndependentPeers(t *testing.T) {
	a := assert.New(t)
	wr := NewWebhookRegistry()

	a1, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	a2, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	wr.Register(a1.PublicKey(), "https://peer1.example.com")
	wr.Register(a2.PublicKey(), "https://peer2.example.com")

	a.Equal("https://peer1.example.com", wr.Lookup(a1.PublicKey()))
	a.Equal("https://peer2.example.com", wr.Lookup(a2.PublicKey()))

	wr.Unregister(a1.PublicKey())
	a.Equal("", wr.Lookup(a1.PublicKey()))
	a.Equal("https://peer2.example.com", wr.Lookup(a2.PublicKey()))
}

func TestServiceRegisterWebhook(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	err = svc.RegisterWebhook(pubKey, "https://example.com/hook")
	a.NoError(err)

	url := svc.Webhooks().Lookup(at.PublicKey())
	a.Equal("https://example.com/hook", url)
}

func TestServiceUnregisterWebhook(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	pubKey := at.PublicKey().Marshal()

	err = svc.RegisterWebhook(pubKey, "https://example.com/hook")
	a.NoError(err)

	removed, err := svc.UnregisterWebhook(pubKey)
	a.NoError(err)
	a.True(removed)

	removed, err = svc.UnregisterWebhook(pubKey)
	a.NoError(err)
	a.False(removed)
}

// ---------------------------------------------------------------------------
// Metrics tests
// ---------------------------------------------------------------------------

func TestMetrics_Counters(t *testing.T) {
	a := assert.New(t)
	m := NewMetrics()

	m.IncMessagesRelayed()
	m.IncMessagesRelayed()
	m.IncMessagesQueued()
	m.IncMessagesPopped()
	m.IncPeersRegistered()
	m.IncPeersRefreshed()
	m.IncRateLimitHits()
	m.IncWebhooksFired()
	m.IncWebhooksFailed()
	m.IncWSMessagesIn()
	m.IncWSMessagesOut()
	m.IncBatchDrains()
	m.AddBatchDrainItems(5)

	m.mu.RLock()
	defer m.mu.RUnlock()

	a.Equal(int64(2), m.messagesRelayed)
	a.Equal(int64(1), m.messagesQueued)
	a.Equal(int64(1), m.messagesPopped)
	a.Equal(int64(1), m.peersRegistered)
	a.Equal(int64(1), m.peersRefreshed)
	a.Equal(int64(1), m.rateLimitHits)
	a.Equal(int64(1), m.webhooksFired)
	a.Equal(int64(1), m.webhooksFailed)
	a.Equal(int64(1), m.wsMessagesIn)
	a.Equal(int64(1), m.wsMessagesOut)
	a.Equal(int64(1), m.batchDrains)
	a.Equal(int64(5), m.batchDrainItems)
}

func TestMetrics_WSConnectionGauge(t *testing.T) {
	a := assert.New(t)
	m := NewMetrics()

	m.IncWSConnections()
	m.IncWSConnections()
	m.IncWSConnections()
	m.DecWSConnections()

	m.mu.RLock()
	defer m.mu.RUnlock()
	a.Equal(int64(2), m.wsConnections)
}

func TestMetrics_RecordConveyResult(t *testing.T) {
	a := assert.New(t)
	m := NewMetrics()

	m.RecordConveyResult(true)
	m.RecordConveyResult(true)
	m.RecordConveyResult(false)

	m.mu.RLock()
	defer m.mu.RUnlock()
	a.Equal(int64(2), m.messagesRelayed)
	a.Equal(int64(1), m.messagesQueued)
}

func TestMetrics_IncRequest(t *testing.T) {
	a := assert.New(t)
	m := NewMetrics()

	m.IncRequest("GET", "/health", 200, 1e6)
	m.IncRequest("GET", "/health", 200, 2e6)
	m.IncRequest("POST", "/convey", 500, 5e6)

	m.mu.RLock()
	defer m.mu.RUnlock()

	a.Equal(int64(2), m.requestsTotal["GET /health"])
	a.Equal(int64(1), m.requestsTotal["POST /convey"])
	a.Equal(int64(0), m.requestErrors["GET /health"])
	a.Equal(int64(1), m.requestErrors["POST /convey"])
	a.Equal(int64(2), m.requestCount["GET /health"])
}

func TestServiceMetrics_NotNil(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	a.NotNil(svc.Metrics())
}

// ---------------------------------------------------------------------------
// Hub tests
// ---------------------------------------------------------------------------

func TestHub_ConnectedCount(t *testing.T) {
	a := assert.New(t)
	hub := NewHub()
	a.Equal(0, hub.ConnectedCount())
}

func TestHub_IsConnected_WhenEmpty(t *testing.T) {
	a := assert.New(t)
	hub := NewHub()

	at, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	a.False(hub.IsConnected(at.PublicKey()))
}

func TestHub_DeliverToDisconnected(t *testing.T) {
	a := assert.New(t)
	hub := NewHub()

	sender, receiver := newTestKeys(t)
	ok := hub.Deliver(t.Context(), sender, receiver, "session1", []byte("hello"))
	a.False(ok)
}

// ---------------------------------------------------------------------------
// ConveyWithWS tests (hub available but peer not connected - should fall back)
// ---------------------------------------------------------------------------

func TestConveyWithWS_FallsBackToQueue(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)
	sender, receiver := newTestKeys(t)
	sessionID := rand.Text()

	// No WS connection for receiver, so it should fall back to queue.
	delivered, err := svc.ConveyWithWS(sender, receiver, sessionID, []byte("test-msg"))
	a.NoError(err)
	a.False(delivered)

	// Verify the message was queued.
	data, err := svc.PopQueue(sender, receiver, sessionID)
	a.NoError(err)
	a.Equal([]byte("test-msg"), data)
}
