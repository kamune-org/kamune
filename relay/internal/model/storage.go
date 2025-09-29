package model

import (
	"time"
)

type Store interface {
	Close() error
	Query(func(Query) error) error
	Command(func(Command) error) error
}

type Query interface {
	Get(key []byte) ([]byte, error)
	Exists(key []byte) (bool, error)
	TTL(key []byte) (time.Duration, error)
}

type Command interface {
	Query
	Delete(key []byte) error
	Set(key, value []byte) error
	SetTTL(key, value []byte, ttl time.Duration) error
}
