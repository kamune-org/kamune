package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func listenRelay(store *storage.Storage, relayAddr string) (kamune.Listener, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, errors.New("relay server address is required")
	}

	at, err := store.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	selfKey := at.MarshalPublicKey()
	return relayconn.ListenRelay(context.Background(), relayAddr, selfKey)
}

func dialRelayFunc(store *storage.Storage, relayAddr string, peerKeyB64 string) (func(string) (kamune.Conn, error), error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, errors.New("relay server address is required")
	}
	if strings.TrimSpace(peerKeyB64) == "" {
		return nil, errors.New("peer public key is required")
	}

	at, err := store.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	selfKey := at.MarshalPublicKey()
	peerKey, err := base64.RawURLEncoding.DecodeString(peerKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode peer key: %w", err)
	}
	ctx := context.Background()
	return func(addr string) (kamune.Conn, error) {
		return relayconn.DialRelay(ctx, addr, selfKey, peerKey)
	}, nil
}
