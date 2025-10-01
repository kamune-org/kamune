package services

import (
	"encoding/base64"
)

func (s *Service) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(s.attester.PublicKey().Marshal())
}
