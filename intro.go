package kamune

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/hossein1376/kamune/internal/attest"
	"github.com/hossein1376/kamune/internal/box/pb"
)

type PublicKey = *attest.PublicKey

type RemoteVerifier func(key PublicKey) (err error)

func defaultRemoteVerifier(remote PublicKey) error {
	key := base64.StdEncoding.EncodeToString(remote.Marshal())
	keyBytes := []byte(key)
	fmt.Printf("Peer's public key: %s\n", key)
	known := isPeerKnown(keyBytes)
	if !known {
		fmt.Println("Peer is not known. They will be added to the trusted list if you continue.")
	}
	fmt.Printf("Proceed? (y/N)? ")

	b := bufio.NewScanner(os.Stdin)
	b.Scan()
	answer := strings.TrimSpace(strings.ToLower(b.Text()))
	if !(answer == "y" || answer == "yes") {
		return ErrVerificationFailed
	}

	if !known {
		if err := trustPeer(keyBytes); err != nil {
			fmt.Printf("Error adding peer to the trusted list: %s\n", err)
			return nil
		}
		fmt.Println("Peer was added to the trusted list.")
	}

	return nil
}

func sendIntroduction(conn Conn, at *attest.Attest) error {
	intro := &pb.Introduce{
		Public:  at.MarshalPublicKey(),
		Padding: padding(introducePadding),
	}
	introBytes, err := proto.Marshal(intro)
	if err != nil {
		return fmt.Errorf("marshalling: %w", err)
	}
	if _, err := conn.Write(introBytes); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func receiveIntroduction(conn Conn) (*attest.PublicKey, error) {
	payload, err := read(conn)
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	var introduce pb.Introduce
	err = proto.Unmarshal(payload, &introduce)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}
	remote, err := attest.ParsePublicKey(introduce.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("parsing advertised key: %w", err)
	}

	return remote, nil
}
