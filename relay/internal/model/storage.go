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
	Get(ns Namespace, name []byte) ([]byte, error)
	Exists(ns Namespace, name []byte) (bool, error)
	TTL(ns Namespace, name []byte) (time.Duration, error)
}

type Command interface {
	Query
	Delete(ns Namespace, name []byte) error
	Set(ns Namespace, name, value []byte) error
	SetTTL(ns Namespace, name, value []byte, ttl time.Duration) error
	QPush(name, value []byte) error
	QPop(name []byte) ([]byte, error)
}
