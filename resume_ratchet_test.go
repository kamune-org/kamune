package kamune

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestResumptionRestoresRatchetState is an integration test that verifies:
//  1. an established Transport persists a non-empty ratchet state via Transport.State()
//  2. that persisted state can be used by SessionResumer.restoreTransport to restore
//     a Transport with a functional ratchet assigned.
//
// This specifically covers the "complete session resumption" requirement for the
// double ratchet now that serialization/deserialization support exists.
func TestResumptionRestoresRatchetState(t *testing.T) {
	r := require.New(t)

	// Create storage (in-memory or temp db is handled by OpenStorage defaults).
	// If your Storage options require explicit db path or passphrase, adjust here.
	storage, err := OpenStorage(StorageWithNoPassphrase())
	r.NoError(err)
	t.Cleanup(func() { _ = storage.Close() })

	// We use SessionManager persistence path since resumption uses stored SessionState.
	sm := NewSessionManager(storage, 24*time.Hour)

	// Create a dialer/server pair and establish a session (full handshake + ratchet init).
	// This is the most realistic path to get an established Transport with a non-nil ratchet.
	//
	// If these constructors differ in your project, update accordingly.
	serverAttester, err := NewDefaultAttester()
	r.NoError(err)
	clientAttester, err := NewDefaultAttester()
	r.NoError(err)

	// Start a server and dial it.
	// Note: If your test harness uses a different transport (kcp, tcp, etc),
	// update NewListener/NewDialer accordingly.
	addr := "127.0.0.1:0"

	ln, err := NewListener(
		ListenerWithAddress(addr),
		ListenerWithStorage(storage),
		ListenerWithAttester(serverAttester),
	)
	r.NoError(err)
	t.Cleanup(func() { _ = ln.Close() })

	// Accept in background.
	serverCh := make(chan *Transport, 1)
	errCh := make(chan error, 1)
	go func() {
		tp, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- tp
	}()

	dialer, err := NewDialer(
		DialerWithAddress(ln.Addr().String()),
		DialerWithStorage(storage),
		DialerWithAttester(clientAttester),
	)
	r.NoError(err)

	clientT, err := dialer.Dial()
	r.NoError(err)
	t.Cleanup(func() { _ = clientT.Close() })

	var serverT *Transport
	select {
	case serverT = <-serverCh:
	case err := <-errCh:
		r.NoError(err)
	case <-time.After(5 * time.Second):
		r.FailNow("server accept timeout")
	}
	t.Cleanup(func() { _ = serverT.Close() })

	// Sanity: session established (ratchet should exist after handshake).
	r.True(clientT.IsEstablished(), "client transport not established")
	r.True(serverT.IsEstablished(), "server transport not established")

	// Force at least one ratchet-encrypted message so the chain keys advance.
	// Any message exchange route should work here as long as it goes through
	// Transport encrypt/decrypt using the ratchet.
	msg := Bytes([]byte("hello (ratchet)"))

	_, err = clientT.Send(msg, RouteExchangeMessages)
	r.NoError(err)

	got := Bytes(nil)
	_, err = serverT.ReceiveExpecting(got, RouteExchangeMessages)
	r.NoError(err)
	r.Equal([]byte("hello (ratchet)"), got.GetValue())

	// Persist session state for resumption (this picks up Transport.State(), including RatchetState).
	err = SaveSessionForResumption(serverT, sm)
	r.NoError(err)

	// Load it back and ensure ratchet state is present.
	persisted, err := sm.LoadSession(serverT.State().SessionID)
	r.NoError(err)
	r.NotEmpty(persisted.RatchetState, "expected persisted ratchet state to be non-empty")

	// Now exercise restoreTransport directly with a fake resumed connection:
	// We need a live connection to create a Transport, so we reuse the existing
	// server-side conn's underlying Conn by initiating a resumption flow.
	//
	// The test intent is ratchet restoration from bytes; we don't need to re-run
	// the full signed reconnect handshake here.
	resumer := NewSessionResumer(storage, sm, serverAttester, 24*time.Hour)

	// Use the server transport's connection as the new conn (effectively simulating reconnect).
	// Because Conn is an interface in this project, Transport's conn should satisfy it.
	// If this doesn't compile in your tree, replace with a real dial/accept of a second conn.
	conn := serverT.conn

	resumedT, err := resumer.restoreTransport(conn, persisted, persisted.SendSequence, persisted.RecvSequence)
	r.NoError(err)
	r.NotNil(resumedT)

	// Ensure the ratchet was installed.
	resumedT.mu.Lock()
	hasRatchet := resumedT.ratchet != nil
	resumedT.mu.Unlock()
	r.True(hasRatchet, "expected resumed transport to have ratchet installed")

	// Verify resumed transport can decrypt a ratchet-encrypted payload.
	// Send from client to resumed server; resumed server uses restored ratchet.
	_, err = clientT.Send(Bytes([]byte("after-resume")), RouteExchangeMessages)
	r.NoError(err)

	got2 := Bytes(nil)
	_, err = resumedT.ReceiveExpecting(got2, RouteExchangeMessages)
	r.NoError(err)
	r.Equal([]byte("after-resume"), got2.GetValue())

	// Finally: verify that if ratchet state is missing, restoreTransport fails closed.
	persistedMissing := *persisted
	persistedMissing.RatchetState = nil
	_, err = resumer.restoreTransport(conn, &persistedMissing, persistedMissing.SendSequence, persistedMissing.RecvSequence)
	r.Error(err)
	r.True(errors.Is(err, ErrResumptionFailed), "expected ErrResumptionFailed for missing ratchet state")
}
