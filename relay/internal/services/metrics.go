package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Metrics collects application-level counters and gauges for observability.
// It is intentionally dependency-free (no OTel SDK or Prometheus client
// required at compile time) so that the relay binary stays lightweight.
// The counters are exposed via a simple text endpoint that is compatible with
// the Prometheus exposition format.
type Metrics struct {
	mu sync.RWMutex

	// HTTP request counters & latencies, keyed by "METHOD /path".
	requestsTotal   map[string]int64
	requestErrors   map[string]int64
	requestDuration map[string]time.Duration
	requestCount    map[string]int64 // for average calculation

	// Application-level counters.
	messagesRelayed int64
	messagesQueued  int64
	messagesPopped  int64
	webhooksFired   int64
	webhooksFailed  int64
	wsConnections   int64 // current gauge (inc/dec)
	wsMessagesIn    int64
	wsMessagesOut   int64
	peersRegistered int64
	peersRefreshed  int64
	rateLimitHits   int64
	batchDrains     int64
	batchDrainItems int64

	startedAt time.Time
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		requestsTotal:   make(map[string]int64),
		requestErrors:   make(map[string]int64),
		requestDuration: make(map[string]time.Duration),
		requestCount:    make(map[string]int64),
		startedAt:       time.Now(),
	}
}

// ---- increment helpers (all goroutine-safe) --------------------------------

func (m *Metrics) IncRequest(method, path string, status int, dur time.Duration) {
	key := method + " " + path
	m.mu.Lock()
	m.requestsTotal[key]++
	m.requestDuration[key] += dur
	m.requestCount[key]++
	if status >= 400 {
		m.requestErrors[key]++
	}
	m.mu.Unlock()
}

func (m *Metrics) IncMessagesRelayed() { m.mu.Lock(); m.messagesRelayed++; m.mu.Unlock() }
func (m *Metrics) IncMessagesQueued()  { m.mu.Lock(); m.messagesQueued++; m.mu.Unlock() }
func (m *Metrics) IncMessagesPopped()  { m.mu.Lock(); m.messagesPopped++; m.mu.Unlock() }
func (m *Metrics) IncWebhooksFired()   { m.mu.Lock(); m.webhooksFired++; m.mu.Unlock() }
func (m *Metrics) IncWebhooksFailed()  { m.mu.Lock(); m.webhooksFailed++; m.mu.Unlock() }
func (m *Metrics) IncWSMessagesIn()    { m.mu.Lock(); m.wsMessagesIn++; m.mu.Unlock() }
func (m *Metrics) IncWSMessagesOut()   { m.mu.Lock(); m.wsMessagesOut++; m.mu.Unlock() }
func (m *Metrics) IncPeersRegistered() { m.mu.Lock(); m.peersRegistered++; m.mu.Unlock() }
func (m *Metrics) IncPeersRefreshed()  { m.mu.Lock(); m.peersRefreshed++; m.mu.Unlock() }
func (m *Metrics) IncRateLimitHits()   { m.mu.Lock(); m.rateLimitHits++; m.mu.Unlock() }
func (m *Metrics) IncBatchDrains()     { m.mu.Lock(); m.batchDrains++; m.mu.Unlock() }
func (m *Metrics) AddBatchDrainItems(n int64) {
	m.mu.Lock()
	m.batchDrainItems += n
	m.mu.Unlock()
}

func (m *Metrics) IncWSConnections() { m.mu.Lock(); m.wsConnections++; m.mu.Unlock() }
func (m *Metrics) DecWSConnections() { m.mu.Lock(); m.wsConnections--; m.mu.Unlock() }

// ---- Prometheus exposition format ------------------------------------------

// ServeHTTP writes all metrics in the Prometheus text exposition format.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Uptime.
	fmt.Fprintf(w, "# HELP relay_uptime_seconds Time since the relay server started.\n")
	fmt.Fprintf(w, "# TYPE relay_uptime_seconds gauge\n")
	fmt.Fprintf(w, "relay_uptime_seconds %f\n\n", time.Since(m.startedAt).Seconds())

	// Per-route HTTP metrics.
	fmt.Fprintf(w, "# HELP relay_http_requests_total Total number of HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE relay_http_requests_total counter\n")
	for key, count := range m.requestsTotal {
		fmt.Fprintf(w, "relay_http_requests_total{route=%q} %d\n", key, count)
	}

	fmt.Fprintf(w, "\n# HELP relay_http_request_errors_total Total number of HTTP requests that returned 4xx/5xx.\n")
	fmt.Fprintf(w, "# TYPE relay_http_request_errors_total counter\n")
	for key, count := range m.requestErrors {
		fmt.Fprintf(w, "relay_http_request_errors_total{route=%q} %d\n", key, count)
	}

	fmt.Fprintf(w, "\n# HELP relay_http_request_duration_seconds_total Cumulative HTTP request duration.\n")
	fmt.Fprintf(w, "# TYPE relay_http_request_duration_seconds_total counter\n")
	for key, dur := range m.requestDuration {
		fmt.Fprintf(w, "relay_http_request_duration_seconds_total{route=%q} %f\n", key, dur.Seconds())
	}

	fmt.Fprintf(w, "\n# HELP relay_http_request_duration_seconds_avg Average HTTP request duration.\n")
	fmt.Fprintf(w, "# TYPE relay_http_request_duration_seconds_avg gauge\n")
	for key, dur := range m.requestDuration {
		cnt := m.requestCount[key]
		if cnt == 0 {
			continue
		}
		fmt.Fprintf(w, "relay_http_request_duration_seconds_avg{route=%q} %f\n", key, dur.Seconds()/float64(cnt))
	}

	// Application-level counters.
	writeCounter(w, "relay_messages_relayed_total", "Total messages delivered directly to peers.", m.messagesRelayed)
	writeCounter(w, "relay_messages_queued_total", "Total messages pushed to queues.", m.messagesQueued)
	writeCounter(w, "relay_messages_popped_total", "Total messages popped from queues.", m.messagesPopped)
	writeCounter(w, "relay_peers_registered_total", "Total peer registrations.", m.peersRegistered)
	writeCounter(w, "relay_peers_refreshed_total", "Total peer TTL refreshes.", m.peersRefreshed)
	writeCounter(w, "relay_rate_limit_hits_total", "Total rate-limit rejections.", m.rateLimitHits)
	writeCounter(w, "relay_webhooks_fired_total", "Total webhook notifications fired.", m.webhooksFired)
	writeCounter(w, "relay_webhooks_failed_total", "Total webhook delivery failures.", m.webhooksFailed)
	writeCounter(w, "relay_batch_drains_total", "Total batch drain requests.", m.batchDrains)
	writeCounter(w, "relay_batch_drain_items_total", "Total individual messages drained via batch.", m.batchDrainItems)

	// WebSocket gauges.
	writeGauge(w, "relay_ws_connections_active", "Number of active WebSocket connections.", m.wsConnections)
	writeCounter(w, "relay_ws_messages_in_total", "Total WebSocket messages received from clients.", m.wsMessagesIn)
	writeCounter(w, "relay_ws_messages_out_total", "Total WebSocket messages sent to clients.", m.wsMessagesOut)
}

func writeCounter(w http.ResponseWriter, name, help string, val int64) {
	fmt.Fprintf(w, "\n# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, val)
}

func writeGauge(w http.ResponseWriter, name, help string, val int64) {
	fmt.Fprintf(w, "\n# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %d\n", name, val)
}

// ---- Metrics accessor on Service -------------------------------------------

// Metrics returns the service's metrics collector.
func (s *Service) Metrics() *Metrics {
	return s.metrics
}

// ---- HTTP middleware -------------------------------------------------------

// MetricsMiddleware returns an http.Handler middleware that records request
// count, error rate, and latency for every HTTP request.
func MetricsMiddleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(sw, r)
			m.IncRequest(r.Method, r.URL.Path, sw.code, time.Since(start))
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture the response status code.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

// Unwrap supports the http.ResponseController unwrapping convention so that
// middleware like flush/hijack still work through the wrapper.
func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}

// MetricsHandler returns an http.HandlerFunc that serves the Prometheus-
// compatible metrics endpoint.
func MetricsHandler(m *Metrics) http.HandlerFunc {
	return m.ServeHTTP
}

// RecordConveyResult is a helper that updates the appropriate metric counter
// after a Convey or ConveyWithWS call.
func (m *Metrics) RecordConveyResult(delivered bool) {
	if delivered {
		m.IncMessagesRelayed()
	} else {
		m.IncMessagesQueued()
	}
}

// contextKey is unexported to prevent collisions with other packages.
type contextKey string

const metricsKey contextKey = "relay.metrics"

// WithMetrics stores a Metrics reference in the context.
func WithMetrics(ctx context.Context, m *Metrics) context.Context {
	return context.WithValue(ctx, metricsKey, m)
}

// MetricsFrom retrieves the Metrics reference from the context, or nil.
func MetricsFrom(ctx context.Context) *Metrics {
	m, _ := ctx.Value(metricsKey).(*Metrics)
	return m
}

// LogMetricsSummary writes a one-line summary of key metrics to the default
// slog logger at Info level. Useful for periodic status logging.
func (m *Metrics) LogMetricsSummary() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slog.Info("metrics summary",
		slog.Int64("relayed", m.messagesRelayed),
		slog.Int64("queued", m.messagesQueued),
		slog.Int64("popped", m.messagesPopped),
		slog.Int64("ws_active", m.wsConnections),
		slog.Int64("peers_registered", m.peersRegistered),
		slog.Int64("rate_limited", m.rateLimitHits),
		slog.Int64("webhooks_fired", m.webhooksFired),
		slog.Duration("uptime", time.Since(m.startedAt)),
	)
}
