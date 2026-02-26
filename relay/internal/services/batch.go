package services

import (
	"errors"
	"fmt"

	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
)

const (
	// DefaultBatchSize is used when the caller does not specify a limit.
	DefaultBatchSize = 10
	// MaxBatchSize is the upper bound on how many messages can be drained
	// in a single request, regardless of what the caller asks for.
	MaxBatchSize = 100
)

// BatchPopQueue pops up to `limit` messages from the queue identified by
// the sender/receiver/session tuple. Messages are returned in FIFO order.
//
// If limit <= 0 the DefaultBatchSize is used. If limit exceeds MaxBatchSize
// it is clamped to MaxBatchSize.
//
// The returned slice may contain fewer than `limit` items if the queue has
// fewer messages available. An empty (but non-nil) slice is returned when
// the queue is empty.
func (s *Service) BatchPopQueue(
	sender, receiver attest.PublicKey, sessionID string, limit int,
) ([][]byte, error) {
	if limit <= 0 {
		limit = DefaultBatchSize
	}
	if limit > MaxBatchSize {
		limit = MaxBatchSize
	}

	key, err := queueKey(sender, receiver, sessionID)
	if err != nil {
		return nil, fmt.Errorf("derive queue key: %w", err)
	}

	messages := make([][]byte, 0, limit)
	err = s.store.Command(func(c model.Command) error {
		for range limit {
			data, err := c.QPop(key)
			if err != nil {
				if errors.Is(err, storage.ErrMissing) {
					return errs.NotFound()
				}
				return fmt.Errorf("pop from queue: %w", err)
			}
			// QPop returns (nil, nil) when the queue is empty.
			if data == nil {
				break
			}
			messages = append(messages, data)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return messages, nil
}
