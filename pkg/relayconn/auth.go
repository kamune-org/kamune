package relayconn

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

func sendAuth(ch *exchange.Channel, password string) error {
	auth := &pb.Frame{
		Kind: &pb.Frame_Auth{
			Auth: &pb.Auth{Psk: []byte(password)},
		},
	}
	b, err := proto.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshal auth: %w", err)
	}
	if err := ch.WriteBytes(b); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	resp, err := ch.ReadBytes()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	var frame pb.Frame
	if err := proto.Unmarshal(resp, &frame); err != nil {
		return fmt.Errorf("unmarshal auth response: %w", err)
	}
	if frame.GetAuth() == nil {
		return fmt.Errorf("unexpected auth response: %T", frame.Kind)
	}
	return nil
}
