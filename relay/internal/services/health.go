package services

import (
	"fmt"
	"time"

	"github.com/kamune-org/kamune/relay/internal/model"
)

// HealthStatus contains the health check result for the relay server.
type HealthStatus struct {
	Status    string        `json:"status"`
	Storage   string        `json:"storage"`
	Latency   time.Duration `json:"latency"`
	Identity  string        `json:"identity"`
	Uptime    time.Duration `json:"uptime"`
	StartedAt time.Time     `json:"started_at"`
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
			Latency:   latency,
			Identity:  fmt.Sprintf("%v", s.cfg.Server.Identity),
			Uptime:    time.Since(s.startedAt),
			StartedAt: s.startedAt,
		}, fmt.Errorf("storage health check failed: %w", err)
	}

	return &HealthStatus{
		Status:    "ok",
		Storage:   storageStatus,
		Latency:   latency,
		Identity:  fmt.Sprintf("%v", s.cfg.Server.Identity),
		Uptime:    time.Since(s.startedAt),
		StartedAt: s.startedAt,
	}, nil
}
