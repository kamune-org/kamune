package ratchet_test

import (
	"fmt"
	"log"

	"github.com/kamune-org/kamune/pkg/ratchet"
)

// ExampleState_Serialize demonstrates how to save and restore a ratchet state.
func ExampleState_Serialize() {
	// Create a shared root secret (in practice, this would come from a key exchange)
	rootSecret := make([]byte, 32)
	sessionID := "example-session"

	// Alice creates a ratchet
	alice, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	// Bob creates a ratchet
	bob, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	// Exchange public keys to initialize the ratchet
	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	if err != nil {
		log.Fatal(err)
	}
	err = bob.SetTheirPublic(alice.OurPublic(), sessionID)
	if err != nil {
		log.Fatal(err)
	}

	// Send some messages
	plaintext := []byte("Hello, Bob!")
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := bob.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)

	// Save Alice's state
	aliceState, err := alice.Save()
	if err != nil {
		log.Fatal(err)
	}

	// Serialize to JSON for storage
	jsonData, err := aliceState.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Serialized state length: %d bytes\n", len(jsonData))

	// Later, deserialize the state
	restoredState, err := ratchet.Deserialize(jsonData)
	if err != nil {
		log.Fatal(err)
	}

	// Restore the ratchet from the state
	aliceRestored, err := ratchet.Restore(restoredState)
	if err != nil {
		log.Fatal(err)
	}

	// Continue sending messages with the restored ratchet
	plaintext2 := []byte("Message after restore")
	ciphertext2, err := aliceRestored.Encrypt(plaintext2)
	if err != nil {
		log.Fatal(err)
	}

	decrypted2, err := bob.Decrypt(ciphertext2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted after restore: %s\n", decrypted2)

	// Output:
	// Decrypted: Hello, Bob!
	// Serialized state length: 415 bytes
	// Decrypted after restore: Message after restore
}

// ExampleState_Clone demonstrates how to clone a state for backup purposes.
func ExampleState_Clone() {
	rootSecret := make([]byte, 32)
	sessionID := "clone-session"

	// Create and initialize a ratchet
	alice, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	bob, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	if err != nil {
		log.Fatal(err)
	}

	// Save the state
	state, err := alice.Save()
	if err != nil {
		log.Fatal(err)
	}

	// Clone the state for backup
	backup := state.Clone()

	// Modify the original state (simulating corruption)
	state.SendCount = 9999

	// The backup is unaffected
	fmt.Printf("Original state send count: %d\n", state.SendCount)
	fmt.Printf("Backup state send count: %d\n", backup.SendCount)

	// Output:
	// Original state send count: 9999
	// Backup state send count: 0
}

// ExampleRestore demonstrates restoring a ratchet from a previously saved state.
func ExampleRestore() {
	rootSecret := make([]byte, 32)
	sessionID := "restore-session"

	// Alice creates a ratchet
	alice, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	bob, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize the ratchets
	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	if err != nil {
		log.Fatal(err)
	}
	err = bob.SetTheirPublic(alice.OurPublic(), sessionID)
	if err != nil {
		log.Fatal(err)
	}

	// Send a message
	_, err = alice.Encrypt([]byte("First message"))
	if err != nil {
		log.Fatal(err)
	}

	// Save Alice's state
	state, err := alice.Save()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Messages sent before save: %d\n", state.SendCount)

	// Restore from the saved state
	aliceRestored, err := ratchet.Restore(state)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Messages sent in restored ratchet: %d\n", aliceRestored.Sent())

	// Output:
	// Messages sent before save: 1
	// Messages sent in restored ratchet: 1
}

// ExampleRatchet_Save demonstrates saving a ratchet's current state.
func ExampleRatchet_Save() {
	rootSecret := make([]byte, 32)

	// Create a new ratchet
	r, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	// Save the state
	state, err := r.Save()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("State saved successfully\n")
	fmt.Printf("Root key length: %d\n", len(state.RootKey))
	fmt.Printf("DH public key length: %d\n", len(state.OurDHPub))

	// Output:
	// State saved successfully
	// Root key length: 32
	// DH public key length: 44
}

// ExampleDeserialize demonstrates deserializing a state from JSON.
func ExampleDeserialize() {
	rootSecret := make([]byte, 32)

	// Create and save a state
	r, err := ratchet.NewFromSecret(rootSecret)
	if err != nil {
		log.Fatal(err)
	}

	state, err := r.Save()
	if err != nil {
		log.Fatal(err)
	}

	// Serialize to JSON
	jsonData, err := state.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	// Deserialize from JSON
	deserializedState, err := ratchet.Deserialize(jsonData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully deserialized state\n")
	fmt.Printf("Send count: %d\n", deserializedState.SendCount)
	fmt.Printf("Receive count: %d\n", deserializedState.RecvCount)

	// Output:
	// Successfully deserialized state
	// Send count: 0
	// Receive count: 0
}
