package kamune

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestHandshake(t *testing.T) {
	a := require.New(t)
	sig := make(chan struct{})
	defer close(sig)
	alg := attest.Ed25519Algorithm
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	a.NoError(err)
	conn2, err := newConn(c2)
	a.NoError(err)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attester1, err := attest.NewAttester(alg)
	a.NoError(err)
	attester2, err := attest.NewAttester(alg)
	a.NoError(err)

	pt1 := newPlainTransport(conn1, attester2.PublicKey(), attester1, alg.Identitfier())
	pt2 := newPlainTransport(conn2, attester1.PublicKey(), attester2, alg.Identitfier())

	var t1 *Transport
	go func() {
		t1, err = requestHandshake(pt1)
		a.NoError(err)
		sig <- struct{}{}
	}()
	t2, err := acceptHandshake(pt2)
	a.NoError(err)
	<-sig
	a.NotNil(t1)
	a.NotNil(t2)

	msg1 := Bytes([]byte(rand.Text()))
	var metadata1 *Metadata
	go func() {
		metadata1, err = t1.Send(msg1)
		a.NoError(err)
		sig <- struct{}{}
	}()
	receivedMsg1 := Bytes(nil)
	receivedMetadata1, err := t2.Receive(receivedMsg1)
	a.NoError(err)
	<-sig
	a.NotNil(metadata1)
	a.NotNil(receivedMetadata1)
	a.Equal(msg1.Value, receivedMsg1.Value)
	a.Equal(metadata1.ID(), receivedMetadata1.ID())
	a.Equal(metadata1.Timestamp(), receivedMetadata1.Timestamp())
	a.Equal(metadata1.SequenceNum(), receivedMetadata1.SequenceNum())

	msg2 := Bytes([]byte(rand.Text()))
	var metadata2 *Metadata
	go func() {
		metadata2, err = t2.Send(msg2)
		a.NoError(err)
		sig <- struct{}{}
	}()
	receivedMsg2 := Bytes(nil)
	receivedMetadata2, err := t1.Receive(receivedMsg2)
	a.NoError(err)
	<-sig
	a.NotNil(metadata2)
	a.NotNil(receivedMetadata2)
	a.Equal(msg2.Value, receivedMsg2.Value)
	a.Equal(metadata2.ID(), receivedMetadata2.ID())
	a.Equal(metadata2.Timestamp(), receivedMetadata2.Timestamp())
	a.Equal(metadata2.SequenceNum(), receivedMetadata2.SequenceNum())
}
