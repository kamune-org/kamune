package services

import (
	"fmt"
	"time"

	"github.com/kamune-org/kamune/relay/internal/model"
)

// HealthStatus contains the health check result for the relay server.
type HealthStatus struct {
	Status    string `json:"status"`
	Storage   string `json:"storage"`
	Latency   string `json:"latency"`
	Identity  string `json:"identity"`
	Uptime    string `json:"uptime"`
	StartedAt string `json:"started_at"`
}

// formatDuration returns a human-readable duration string.
// For sub-second durations it uses the default String() which gives
// values like "1.234ms" or "456.789µs". For longer durations it
// builds a compact "Xh Ym Zs" representation.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}

	totalSeconds := int(d.Seconds())
	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	case hours > 0:
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

// Health pings the underlying storage and returns the server's health status.
// If the storage is unreachable, the returned status will reflect the degraded
// state and the error will describe the failure.
func (s *Service) Health() (*HealthStatus, error) {
	start := time.Now()
	storageStatus := "ok"

	// Probe storage with a lightweight read-only transaction.
	err := s.store.Query(func(q model.Query) error {
		_, _ = q.Exists(identityNS, attestationKey)
		return nil
	})
	latency := time.Since(start)

	if err != nil {
		storageStatus = "degraded"
		return &HealthStatus{
			Status:    "degraded",
			Storage:   storageStatus,
			Latency:   formatDuration(latency),
			Identity:  fmt.Sprintf("%v", s.cfg.Server.Identity),
			Uptime:    formatDuration(time.Since(s.startedAt)),
			StartedAt: s.startedAt.Format("2006-01-02 15:04:05 MST"),
		}, fmt.Errorf("storage health check failed: %w", err)
	}

	return &HealthStatus{
		Status:    "ok",
		Storage:   storageStatus,
		Latency:   formatDuration(latency),
		Identity:  fmt.Sprintf("%v", s.cfg.Server.Identity),
		Uptime:    formatDuration(time.Since(s.startedAt)),
		StartedAt: s.startedAt.Format("2006-01-02 15:04:05 MST"),
	}, nil
}
