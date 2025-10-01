package services

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
)

const (
	rateLimit = "rt_limit"
)

var (
	rateLimitNS = model.NewNameSpace(rateLimit)
)

func (s *Service) RateLimit(remoteIP string) (bool, error) {
	ip := []byte(remoteIP)
	var ok bool
	err := s.store.Command(func(c model.Command) error {
		var (
			found    bool
			attempts uint64
		)
		ttl := s.cfg.RateLimit.TimeWindow

		attemptsBytes, err := c.Get(rateLimitNS, ip)
		switch {
		case err == nil:
			found = true
		case errors.Is(err, storage.ErrMissing):
			// continue
		default:
			return fmt.Errorf("get attempts: %w", err)
		}

		if found {
			attempts = binary.BigEndian.Uint64(attemptsBytes)
			if attempts >= s.cfg.RateLimit.Quota {
				return nil
			}
			ttl, err = c.TTL(rateLimitNS, ip)
			if err != nil {
				return fmt.Errorf("get ttl: %w", err)
			}
		}

		ok = true
		attemptsBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(attemptsBytes, attempts+1)
		if err = c.SetTTL(rateLimitNS, ip, attemptsBytes, ttl); err != nil {
			return fmt.Errorf("set to storage: %w", err)
		}

		return nil
	})
	return ok, err
}
