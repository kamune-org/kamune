package kamune

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

func defaultRemoteVerifier(store *Storage, remote PublicKey) error {
	key := remote.Marshal()
	fmt.Printf(
		"Recevied a connection request. Their emoji fingerprint: %s\n",
		strings.Join(fingerprint.Emoji(key), " • "),
	)

	var isPeerNew bool
	p, err := store.FindPeer(key)
	if err != nil {
		fmt.Println(
			"Peer is not known. They will be added to the storage if you continue.",
		)
		isPeerNew = true
	} else {
		fmt.Printf(
			"Peer is known. First seen was at: %s.\n",
			p.FirstSeen.Local().Format(time.DateTime),
		)
	}
	fmt.Printf("Proceed? (y/N)? ")

	b := bufio.NewScanner(os.Stdin)
	b.Scan()
	answer := strings.TrimSpace(strings.ToLower(b.Text()))
	if !(answer == "y" || answer == "yes") {
		return ErrVerificationFailed
	}

	if isPeerNew {
		now := time.Now()
		peer := &Peer{
			Title:     rand.Text(),
			Identity:  remote.Identity(),
			PublicKey: remote,
			FirstSeen: now,
		}
		if err := store.TrustPeer(peer); err != nil {
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
	conn *Conn, attestation attest.Identity,
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
