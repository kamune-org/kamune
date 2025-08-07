package kamune

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/pkg/attest"
	"github.com/hossein1376/kamune/pkg/fingerprint"
)

func defaultRemoteVerifier(remote PublicKey) error {
	key := remote.Base64Encoding()
	fp := fingerprint.Emoji(remote.Marshal())
	fmt.Printf("Peer's fingerprint: %s\n", strings.Join(fp, " · "))

	known := isPeerKnown(key)
	if !known {
		fmt.Println("Peer is not known. They will be added to the known list if you continue.")
	}
	fmt.Printf("Proceed? (y/N)? ")

	b := bufio.NewScanner(os.Stdin)
	b.Scan()
	answer := strings.TrimSpace(strings.ToLower(b.Text()))
	if !(answer == "y" || answer == "yes") {
		return ErrVerificationFailed
	}

	if !known {
		if err := trustPeer(key); err != nil {
			fmt.Printf("Error adding peer to the known list: %s\n", err)
			return nil
		}
		fmt.Println("Peer was added to the known list.")
	}

	return nil
}

func sendIntroduction(conn *Conn, at attest.Attester) error {
	intro := &pb.Introduce{
		Public:  at.PublicKey().Marshal(),
		Padding: padding(introducePadding),
	}
	introBytes, err := proto.Marshal(intro)
	if err != nil {
		return fmt.Errorf("marshalling: %w", err)
	}
	if err := conn.Write(introBytes); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func receiveIntroduction(
	conn *Conn, attestation attest.Attestation,
) (attest.PublicKey, error) {
	payload, err := conn.Read()
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	var introduce pb.Introduce
	err = proto.Unmarshal(payload, &introduce)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}
	remote, err := attestation.ParsePublicKey(introduce.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("parsing advertised key: %w", err)
	}

	return remote, nil
}
