package services

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"github.com/hossein1376/grape/errs"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
	"golang.org/x/crypto/hkdf"
)

var (
	queueKeySize = 16

	// Sentinel errors returned by PushQueue to allow callers and handlers
	// to identify specific queue-related error conditions.
	// - ErrMessageTooLarge: payload exceeds configured MaxMessageSize
	// - ErrQueueFull: queue has reached MaxQueueSize
	ErrMessageTooLarge = errors.New("message too large")
	ErrQueueFull       = errors.New("queue full")
)

func (s *Service) PushQueue(
	sender, receiver attest.PublicKey, sessionID string, data []byte,
) error {
	// Enforce per-message size limit if configured (0 means unlimited)
	if s.cfg.Storage.MaxMessageSize > 0 && len(data) > s.cfg.Storage.MaxMessageSize {
		return fmt.Errorf("%w: size %d exceeds max %d", ErrMessageTooLarge, len(data), s.cfg.Storage.MaxMessageSize)
	}

	key, err := queueKey(sender, receiver, sessionID)
	if err != nil {
		return fmt.Errorf("derive queue key: %w", err)
	}

	err = s.store.Command(func(c model.Command) error {
		// Enforce max queue length if configured (0 means unlimited)
		if s.cfg.Storage.MaxQueueSize > 0 {
			qlen, err := c.QLen(key)
			if err != nil {
				return fmt.Errorf("get queue length: %w", err)
			}
			if qlen >= s.cfg.Storage.MaxQueueSize {
				return fmt.Errorf("%w: length %d >= max %d", ErrQueueFull, qlen, s.cfg.Storage.MaxQueueSize)
			}
		}

		return c.QPush(key, data)
	})
	if err != nil {
		return fmt.Errorf("push to queue: %w", err)
	}

	return nil
}

func (s *Service) PopQueue(
	sender, receiver attest.PublicKey, sessionID string,
) ([]byte, error) {
	key, err := queueKey(sender, receiver, sessionID)
	if err != nil {
		return nil, fmt.Errorf("derive queue key: %w", err)
	}

	var data []byte
	err = s.store.Command(func(c model.Command) error {
		var err error
		data, err = c.QPop(key)
		return err
	})
	if err != nil {
		if errors.Is(err, storage.ErrMissing) {
			return nil, errs.NotFound()
		}
		return nil, fmt.Errorf("pop from queue: %w", err)
	}

	return data, nil
}

func queueKey(sender, receiver attest.PublicKey, sessionID string) ([]byte, error) {
	sb := sender.Marshal()
	rb := receiver.Marshal()
	data := make([]byte, 0, len(sb)+len(rb)+len(sessionID))
	data = append(data, sb...)
	data = append(data, rb...)
	data = append(data, []byte(sessionID)...)

	r := hkdf.New(sha512.New, data, nil, nil)
	key := make([]byte, queueKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
