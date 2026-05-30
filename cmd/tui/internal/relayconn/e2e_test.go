package relayconn

import (
	"context"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestRelayEndToEnd(t *testing.T) {
	relayAddr := "127.0.0.1:8888"

	alice, err := attest.New()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := attest.New()
	if err != nil {
		t.Fatal(err)
	}

	alicePKIX := alice.MarshalPublicKey()
	bobPKIX := bob.MarshalPublicKey()

	ctx := context.Background()

	bobListener, err := ListenRelay(ctx, relayAddr, bobPKIX)
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer bobListener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cn, err := bobListener.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}

		data, err := cn.ReadBytes()
		if err != nil {
			t.Errorf("bob read: %v", err)
			return
		}
		if string(data) != "hello from alice" {
			t.Errorf("bob got %q, want %q", string(data), "hello from alice")
		}

		if err := cn.WriteBytes([]byte("hello from bob")); err != nil {
			t.Errorf("bob write: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	aliceConn, err := DialRelay(ctx, relayAddr, alicePKIX, bobPKIX)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer aliceConn.Close()

	if err := aliceConn.WriteBytes([]byte("hello from alice")); err != nil {
		t.Fatalf("alice write: %v", err)
	}

	response, err := aliceConn.ReadBytes()
	if err != nil {
		t.Fatalf("alice read: %v", err)
	}
	if string(response) != "hello from bob" {
		t.Errorf("alice got %q, want %q", string(response), "hello from bob")
	}

	<-done
}
