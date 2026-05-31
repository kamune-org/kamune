package relayconn

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

func DialRelay(ctx context.Context, relayAddr string, selfKey, peerKey []byte) (*RelayConn, error) {
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}

	adapter := &wsAdapter{conn: ws, ctx: ctx}
	ch, err := exchange.Initiate(adapter)
	if err != nil {
		ws.Close(websocket.StatusNormalClosure, "exchange failed")
		return nil, fmt.Errorf("hpke initiate: %w", err)
	}

	identityFrame := &pb.Frame{
		Kind: &pb.Frame_Identity{
			Identity: &pb.Identity{Key: selfKey},
		},
	}
	identityBytes, err := proto.Marshal(identityFrame)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("marshal identity: %w", err)
	}
	if err := ch.WriteBytes(identityBytes); err != nil {
		ch.Close()
		return nil, fmt.Errorf("send identity: %w", err)
	}

	relayBytes, err := ch.ReadBytes()
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("read relay identity: %w", err)
	}
	var relayFrame pb.Frame
	if err := proto.Unmarshal(relayBytes, &relayFrame); err != nil {
		ch.Close()
		return nil, fmt.Errorf("unmarshal relay identity: %w", err)
	}
	_ = relayFrame.GetIdentity().GetKey()

	sid := syntheticSessionID(selfKey, peerKey)
	var mu sync.Mutex
	rc := newRelayConn(ctx, ch, peerKey, sid, &mu)
	rc.closeFn = func() { ch.Close() }

	go rc.readPump()
	return rc, nil
}

func syntheticSessionID(selfKey, peerKey []byte) string {
	h := sha256.Sum256(append(selfKey, peerKey...))
	return fmt.Sprintf("relay-hs:%x", h[:8])
}
