package crypto_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/crypto"
)

func TestDestinationEncryptionAndDecryption(t *testing.T) {
	// Generate destination keypair
	destPriv, destPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate dest keypair: %v", err)
	}
	destPubHex := hex.EncodeToString(destPub.Bytes())

	payload := map[string]interface{}{
		"hello": "world",
		"count": float64(42),
		"nested": map[string]interface{}{
			"secret": "top-secret-data",
		},
	}

	// 1. Encrypt for destination
	cipherHex, err := crypto.EncryptForDestination(destPubHex, payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if cipherHex == "" {
		t.Fatal("empty ciphertext returned")
	}

	// 2. Decrypt with destination private key
	decrypted, err := crypto.DecryptForDestination(destPriv, cipherHex)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("decrypted payload mismatch:\nExpected: %+v\nGot: %+v", payload, decrypted)
	}

	// 3. Test that an intermediary possessing a different key CANNOT decrypt
	intermediaryPriv, _, _ := crypto.GenerateX25519KeyPair()
	_, err = crypto.DecryptForDestination(intermediaryPriv, cipherHex)
	if err == nil {
		t.Fatal("expected decryption by intermediary to fail, but it succeeded!")
	}
	t.Logf("Intermediary decryption correctly failed: %v", err)

	// 4. Test tampering with ciphertext fails GCM authentication
	cipherBytes, _ := hex.DecodeString(cipherHex)
	cipherBytes[len(cipherBytes)-1] ^= 0xFF // corrupt last byte (tag)
	corruptedHex := hex.EncodeToString(cipherBytes)
	_, err = crypto.DecryptForDestination(destPriv, corruptedHex)
	if err == nil {
		t.Fatal("expected decryption of corrupted ciphertext to fail, but it succeeded!")
	}
	t.Logf("Corrupted ciphertext correctly rejected: %v", err)
}
