package span

import (
	"time"
)

type Duration struct {
	d time.Duration
}

func New(d time.Duration) Duration {
	return Duration{d: d}
}
func (d Duration) Duration() time.Duration {
	return d.d
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.d.String()), nil
}
