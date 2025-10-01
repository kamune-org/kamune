package model

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

const nameSpaceLength = 8

type Namespace uint64

func NewNameSpace(name string) Namespace {
	if l := len(name); l > nameSpaceLength {
		panic(fmt.Errorf("name space key is too long: %d", l))
	}
	b := make([]byte, nameSpaceLength)
	copy(b, name)
	return Namespace(binary.BigEndian.Uint64(b))
}

func (ns Namespace) String() string {
	return strconv.FormatUint(uint64(ns), 10)
}

func (ns Namespace) Key(suffix []byte) []byte {
	key := make([]byte, nameSpaceLength, nameSpaceLength+len(suffix))
	binary.BigEndian.PutUint64(key[:nameSpaceLength], uint64(ns))
	return append(key, suffix...)
}
