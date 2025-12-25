package ratchet

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateSaveAndRestore(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create initial ratchet
	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	alice, err := NewFromSecret(rootSecret)
	r.NoError(err, "Alice init")

	bob, err := NewFromSecret(rootSecret)
	r.NoError(err, "Bob init")

	// Exchange public keys
	alicePub := alice.OurPublic()
	bobPub := bob.OurPublic()

	err = alice.SetTheirPublic(bobPub, sessionID)
	r.NoError(err, "Alice set peer")
	err = bob.SetTheirPublic(alicePub, sessionID)
	r.NoError(err, "Bob set peer")

	// Send a few messages
	for i := 0; i < 3; i++ {
		plaintext := []byte("Test message")
		ciphertext, err := alice.Encrypt(plaintext)
		r.NoError(err, "Alice encrypt")

		decrypted, err := bob.Decrypt(ciphertext)
		r.NoError(err, "Bob decrypt")
		a.Equal(plaintext, decrypted)
	}

	// Save Alice's state
	aliceState, err := alice.Save()
	r.NoError(err, "Save Alice state")

	// Restore Alice's state to a new ratchet
	aliceRestored, err := Restore(aliceState)
	r.NoError(err, "Restore Alice state")

	// Verify the restored ratchet has the same state
	a.Equal(alice.rootKey, aliceRestored.rootKey, "root key mismatch")
	a.Equal(alice.sendCK, aliceRestored.sendCK, "send chain key mismatch")
	a.Equal(alice.recvCK, aliceRestored.recvCK, "recv chain key mismatch")
	a.Equal(alice.theirPub, aliceRestored.theirPub, "their public key mismatch")
	a.Equal(alice.sendCount, aliceRestored.sendCount, "send count mismatch")
	a.Equal(alice.recvCount, aliceRestored.recvCount, "recv count mismatch")

	// Verify restored ratchet can continue encryption
	plaintext := []byte("Message after restore")
	ciphertext, err := aliceRestored.Encrypt(plaintext)
	r.NoError(err, "Restored Alice encrypt")

	decrypted, err := bob.Decrypt(ciphertext)
	r.NoError(err, "Bob decrypt from restored")
	a.Equal(plaintext, decrypted)
}

func TestStateSerializeDeserialize(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create and initialize a ratchet
	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	alice, err := NewFromSecret(rootSecret)
	r.NoError(err, "Alice init")

	bob, err := NewFromSecret(rootSecret)
	r.NoError(err, "Bob init")

	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	r.NoError(err, "Alice set peer")

	// Save state
	state, err := alice.Save()
	r.NoError(err, "Save state")

	// Serialize to JSON
	jsonBytes, err := state.Serialize()
	r.NoError(err, "Serialize state")
	a.NotEmpty(jsonBytes)

	// Deserialize from JSON
	deserializedState, err := Deserialize(jsonBytes)
	r.NoError(err, "Deserialize state")

	// Compare original and deserialized state
	a.Equal(state.RootKey, deserializedState.RootKey)
	a.Equal(state.SendCK, deserializedState.SendCK)
	a.Equal(state.RecvCK, deserializedState.RecvCK)
	a.Equal(state.OurDHPriv, deserializedState.OurDHPriv)
	a.Equal(state.OurDHPub, deserializedState.OurDHPub)
	a.Equal(state.TheirPub, deserializedState.TheirPub)
	a.Equal(state.SendCount, deserializedState.SendCount)
	a.Equal(state.RecvCount, deserializedState.RecvCount)

	// Restore from deserialized state
	restored, err := Restore(deserializedState)
	r.NoError(err, "Restore from deserialized state")
	a.NotNil(restored)
}

func TestStateJSONMarshalUnmarshal(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create a state with sample data
	state := &State{
		RootKey:   randomBytes(32),
		SendCK:    randomBytes(32),
		RecvCK:    randomBytes(32),
		OurDHPriv: randomBytes(32),
		OurDHPub:  randomBytes(32),
		TheirPub:  randomBytes(32),
		SendCount: 42,
		RecvCount: 24,
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(state)
	r.NoError(err, "Marshal to JSON")

	// Unmarshal from JSON
	var unmarshaled State
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	r.NoError(err, "Unmarshal from JSON")

	// Verify all fields
	a.Equal(state.RootKey, unmarshaled.RootKey)
	a.Equal(state.SendCK, unmarshaled.SendCK)
	a.Equal(state.RecvCK, unmarshaled.RecvCK)
	a.Equal(state.OurDHPriv, unmarshaled.OurDHPriv)
	a.Equal(state.OurDHPub, unmarshaled.OurDHPub)
	a.Equal(state.TheirPub, unmarshaled.TheirPub)
	a.Equal(state.SendCount, unmarshaled.SendCount)
	a.Equal(state.RecvCount, unmarshaled.RecvCount)
}

func TestStateClone(t *testing.T) {
	a := assert.New(t)

	// Create a state
	state := &State{
		RootKey:   randomBytes(32),
		SendCK:    randomBytes(32),
		RecvCK:    randomBytes(32),
		OurDHPriv: randomBytes(32),
		OurDHPub:  randomBytes(32),
		TheirPub:  randomBytes(32),
		SendCount: 100,
		RecvCount: 200,
	}

	// Clone the state
	cloned := state.Clone()
	a.NotNil(cloned)

	// Verify all fields are equal
	a.Equal(state.RootKey, cloned.RootKey)
	a.Equal(state.SendCK, cloned.SendCK)
	a.Equal(state.RecvCK, cloned.RecvCK)
	a.Equal(state.OurDHPriv, cloned.OurDHPriv)
	a.Equal(state.OurDHPub, cloned.OurDHPub)
	a.Equal(state.TheirPub, cloned.TheirPub)
	a.Equal(state.SendCount, cloned.SendCount)
	a.Equal(state.RecvCount, cloned.RecvCount)

	// Verify deep copy - modifying cloned doesn't affect original
	cloned.RootKey[0] ^= 0xFF
	a.NotEqual(state.RootKey[0], cloned.RootKey[0])

	cloned.SendCount = 999
	a.NotEqual(state.SendCount, cloned.SendCount)
}

func TestStateCloneNil(t *testing.T) {
	a := assert.New(t)
	var state *State
	cloned := state.Clone()
	a.Nil(cloned)
}

func TestRestoreInvalidState(t *testing.T) {
	a := assert.New(t)

	// Test nil state
	_, err := Restore(nil)
	a.Error(err)
	a.ErrorIs(err, ErrInvalidState)

	// Test state with missing root key
	state := &State{
		OurDHPriv: randomBytes(32),
		OurDHPub:  randomBytes(32),
	}
	_, err = Restore(state)
	a.Error(err)
	a.ErrorIs(err, ErrInvalidState)

	// Test state with missing DH private key
	state = &State{
		RootKey:  randomBytes(32),
		OurDHPub: randomBytes(32),
	}
	_, err = Restore(state)
	a.Error(err)
	a.ErrorIs(err, ErrInvalidState)

	// Test state with missing DH public key
	state = &State{
		RootKey:   randomBytes(32),
		OurDHPriv: randomBytes(32),
	}
	_, err = Restore(state)
	a.Error(err)
	a.ErrorIs(err, ErrInvalidState)
}

func TestSaveRestoreRoundTrip(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create two ratchets and exchange messages
	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	alice, err := NewFromSecret(rootSecret)
	r.NoError(err)
	bob, err := NewFromSecret(rootSecret)
	r.NoError(err)

	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	r.NoError(err)
	err = bob.SetTheirPublic(alice.OurPublic(), sessionID)
	r.NoError(err)

	// Exchange several messages
	messages := []string{
		"First message",
		"Second message",
		"Third message",
	}

	for _, msg := range messages {
		ct, err := alice.Encrypt([]byte(msg))
		r.NoError(err)
		pt, err := bob.Decrypt(ct)
		r.NoError(err)
		a.Equal(msg, string(pt))
	}

	// Save both states
	aliceState, err := alice.Save()
	r.NoError(err)
	bobState, err := bob.Save()
	r.NoError(err)

	// Serialize to JSON
	aliceJSON, err := aliceState.Serialize()
	r.NoError(err)
	bobJSON, err := bobState.Serialize()
	r.NoError(err)

	// Deserialize from JSON
	aliceStateRestored, err := Deserialize(aliceJSON)
	r.NoError(err)
	bobStateRestored, err := Deserialize(bobJSON)
	r.NoError(err)

	// Restore ratchets
	aliceNew, err := Restore(aliceStateRestored)
	r.NoError(err)
	bobNew, err := Restore(bobStateRestored)
	r.NoError(err)

	// Continue exchanging messages with restored ratchets
	newMessages := []string{
		"Fourth message after restore",
		"Fifth message after restore",
	}

	for _, msg := range newMessages {
		ct, err := aliceNew.Encrypt([]byte(msg))
		r.NoError(err)
		pt, err := bobNew.Decrypt(ct)
		r.NoError(err)
		a.Equal(msg, string(pt))
	}

	// Verify counters
	a.Equal(uint64(5), aliceNew.Sent())
	a.Equal(uint64(5), bobNew.Received())
}

func TestStateWithNilChainKeys(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create a ratchet but don't initialize chains
	rootSecret := randomBytes(32)
	alice, err := NewFromSecret(rootSecret)
	r.NoError(err)

	// Save state (chains will be nil)
	state, err := alice.Save()
	r.NoError(err)
	a.Nil(state.SendCK)
	a.Nil(state.RecvCK)
	a.Nil(state.TheirPub)

	// Restore should work
	restored, err := Restore(state)
	r.NoError(err)
	a.NotNil(restored)
	a.Nil(restored.sendCK)
	a.Nil(restored.recvCK)
	a.Nil(restored.theirPub)
}

func TestDeserializeInvalidJSON(t *testing.T) {
	a := assert.New(t)

	// Test with invalid JSON
	_, err := Deserialize([]byte("not valid json"))
	a.Error(err)

	// Test with empty JSON
	_, err = Deserialize([]byte("{}"))
	a.NoError(err) // Should succeed but create empty state

	// Test with malformed JSON
	_, err = Deserialize([]byte("{incomplete"))
	a.Error(err)
}

func TestStateCopyBytes(t *testing.T) {
	a := assert.New(t)

	// Test with nil
	result := copyBytes(nil)
	a.Nil(result)

	// Test with empty slice
	empty := []byte{}
	result = copyBytes(empty)
	a.NotNil(result)
	a.Equal(0, len(result))

	// Test with data
	data := []byte{1, 2, 3, 4, 5}
	result = copyBytes(data)
	a.Equal(data, result)

	// Verify it's a deep copy
	result[0] = 99
	a.NotEqual(data[0], result[0])
}

func TestRestoreWithInitiateRatchet(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	// Setup Alice and Bob
	alice, err := NewFromSecret(rootSecret)
	r.NoError(err)
	bob, err := NewFromSecret(rootSecret)
	r.NoError(err)

	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	r.NoError(err)
	err = bob.SetTheirPublic(alice.OurPublic(), sessionID)
	r.NoError(err)

	// Alice initiates a ratchet
	newAlicePub, err := alice.InitiateRatchet(sessionID)
	r.NoError(err)
	err = bob.SetTheirPublic(newAlicePub, sessionID)
	r.NoError(err)

	// Save Alice's state after ratchet
	aliceState, err := alice.Save()
	r.NoError(err)

	// Restore Alice
	aliceRestored, err := Restore(aliceState)
	r.NoError(err)

	// Verify communication still works
	msg := []byte("Message after ratchet and restore")
	ct, err := aliceRestored.Encrypt(msg)
	r.NoError(err)
	pt, err := bob.Decrypt(ct)
	r.NoError(err)
	a.Equal(msg, pt)
}

func TestMultipleRestoresFromSameState(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	alice, err := NewFromSecret(rootSecret)
	r.NoError(err)
	bob, err := NewFromSecret(rootSecret)
	r.NoError(err)

	err = alice.SetTheirPublic(bob.OurPublic(), sessionID)
	r.NoError(err)
	err = bob.SetTheirPublic(alice.OurPublic(), sessionID)
	r.NoError(err)

	// Send a message
	msg := []byte("Test")
	ct, err := alice.Encrypt(msg)
	r.NoError(err)
	_, err = bob.Decrypt(ct)
	r.NoError(err)

	// Save state
	state, err := alice.Save()
	r.NoError(err)

	// Restore multiple times
	restored1, err := Restore(state)
	r.NoError(err)
	restored2, err := Restore(state)
	r.NoError(err)

	// Both should have same state
	a.Equal(restored1.sendCount, restored2.sendCount)
	a.Equal(restored1.rootKey, restored2.rootKey)

	// Both should be able to encrypt (ciphertexts will differ due to random nonce
	// in enigma, but the internal chain state should advance identically)
	ct1, err := restored1.Encrypt(msg)
	r.NoError(err)
	a.NotEmpty(ct1)

	// Save state after first encryption
	state1After, err := restored1.Save()
	r.NoError(err)

	ct2, err := restored2.Encrypt(msg)
	r.NoError(err)
	a.NotEmpty(ct2)

	// The ciphertexts will differ due to random nonce in enigma encryption
	// but both instances should be able to decrypt messages from bob
	// After encryption, their internal states should be identical
	state2After, err := restored2.Save()
	r.NoError(err)
	a.Equal(state1After.SendCount, state2After.SendCount)
	a.Equal(state1After.SendCK, state2After.SendCK)
	a.Equal(state1After.RootKey, state2After.RootKey)
}
