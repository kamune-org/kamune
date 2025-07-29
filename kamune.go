// Package kamune provides secure communication over untrusted networks.
package kamune

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hossein1376/kamune/internal/box/pb"
)

type Transferable interface {
	proto.Message
}

func Bytes(b []byte) *wrapperspb.BytesValue {
	return &wrapperspb.BytesValue{Value: b}
}

type Metadata struct {
	pb *pb.Metadata
}

func (m Metadata) Timestamp() time.Time {
	return m.pb.Timestamp.AsTime()
}

func (m Metadata) SequenceNum() uint64 {
	// TODO(h.yazdani): reintroduce message sequencing in a more elegant approach
	return 0
}
