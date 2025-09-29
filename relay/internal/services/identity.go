package services

func (s *Service) PublicKey() []byte {
	return s.attester.PublicKey().Marshal()
}
