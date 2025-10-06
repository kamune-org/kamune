package kamune

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

func defaultRemoteVerifier(store *Storage, peer *Peer) error {
	key := peer.PublicKey.Marshal()
	fmt.Printf(
		"Recevied a connection request from %q. Their emoji fingerprint: %s\n",
		peer.Name, strings.Join(fingerprint.Emoji(key), " • "),
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
		peer.FirstSeen = time.Now()
		if err := store.StorePeer(peer); err != nil {
			fmt.Printf("Error adding peer to the known list: %s\n", err)
			return nil
		}
		fmt.Println("Peer was added to the known list.")
	}

	return nil
}

func sendIntroduction(
	conn Conn, name string, at attest.Attester, a attest.Algorithm,
) error {
	intro := &pb.Introduce{
		Name:      name,
		PublicKey: at.PublicKey().Marshal(),
		Algorithm: pb.Algorithm(a),
	}
	message, err := proto.Marshal(intro)
	if err != nil {
		return fmt.Errorf("marshalling intro: %w", err)
	}
	sig, err := at.Sign(message)
	if err != nil {
		return fmt.Errorf("signing message: %w", err)
	}

	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  nil,
		Padding:   padding(maxPadding),
	}
	payload, err := proto.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshalling transport: %w", err)
	}

	if err := conn.WriteBytes(payload); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func receiveIntroduction(st *pb.SignedTransport) (*Peer, error) {
	var introduce pb.Introduce
	err := proto.Unmarshal(st.GetData(), &introduce)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}

	var a attest.Algorithm
	err = a.UnmarshalText([]byte(introduce.Algorithm.String()))
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	id := a.Identitfier()
	remote, err := id.ParsePublicKey(introduce.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("parsing advertised key: %w", err)
	}

	msg := st.GetData()
	if !id.Verify(remote, msg, st.Signature) {
		return nil, ErrInvalidSignature
	}

	return &Peer{Name: introduce.Name, Algorithm: a, PublicKey: remote}, nil
}
