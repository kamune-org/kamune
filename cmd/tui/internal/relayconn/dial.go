package relayconn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// DialRelay connects to the relay and returns a [RelayConn] that communicates
// with the peer identified by peerKey through the relay address. The session
// ID is derived from both peers' keys and stays constant for the session.
func DialRelay(ctx context.Context, relayAddr string, selfKey, peerKey []byte) (*RelayConn, error) {
	keyB64 := base64.RawURLEncoding.EncodeToString(selfKey)
	u := fmt.Sprintf("ws://%s/ws?key=%s", relayAddr, keyB64)

	ws, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}

	// Read the welcome "connected" message.
	var welcome relayMessage
	if err := wsjson.Read(ctx, ws, &welcome); err != nil {
		ws.Close(websocket.StatusNormalClosure, "welcome read failed")
		return nil, fmt.Errorf("read welcome: %w", err)
	}

	// Synthetic session ID for the handshake phase.
	sid := syntheticSessionID(selfKey, peerKey)

	rc := newRelayConn(ctx, ws, peerKey, sid)

	go rc.readPump()

	return rc, nil
}

func (rc *RelayConn) readPump() {
	defer rc.cancel()

	for {
		var msg relayMessage
		if err := wsjson.Read(rc.ctx, rc.ws, &msg); err != nil {
			return
		}

		switch msg.Type {
		case "message":
			data, err := base64.RawURLEncoding.DecodeString(msg.Data)
			if err != nil {
				continue
			}
			rc.pushData(data)
		case "pong", "message_ack", "message_queued":
			continue
		case "error":
			continue
		default:
			continue
		}
	}
}

// syntheticSessionID returns a deterministic session ID derived from both
// public keys, usable before the Kamune handshake generates the real one.
func syntheticSessionID(selfKey, peerKey []byte) string {
	h := sha256.Sum256(append(selfKey, peerKey...))
	return fmt.Sprintf("relay-hs:%x", h[:8])
}
