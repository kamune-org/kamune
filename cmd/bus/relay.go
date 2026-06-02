package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
)

func listenRelay(relayAddr, password string) (kamune.Listener, string, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, "", errors.New("relay server address is required")
	}

	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	listener, token, err := relayconn.ListenRelay(context.Background(), relayAddr, opts...)
	if err != nil {
		return nil, "", err
	}
	return listener, hex.EncodeToString(token), nil
}

func dialRelayFunc(relayAddr, tokenHex, password string) (func(string) (kamune.Conn, error), error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, errors.New("relay server address is required")
	}
	if strings.TrimSpace(tokenHex) == "" {
		return nil, errors.New("relay token is required")
	}

	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	ctx := context.Background()
	return func(addr string) (kamune.Conn, error) {
		var opts []relayconn.Option
		if password != "" {
			opts = append(opts, relayconn.WithPassword(password))
		}
		return relayconn.DialRelay(ctx, addr, token, opts...)
	}, nil
}
