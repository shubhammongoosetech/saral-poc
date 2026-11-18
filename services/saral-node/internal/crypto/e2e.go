package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	X25519KeySize = 32
	GCMNonceSize  = 12
	HKDFInfoTag   = "saral-v3-destination-e2e-encryption"
)

// HKDF-SHA256 implementation (RFC 5869)
func hkdfSha256(secret, salt, info []byte, length int) []byte {
	if salt == nil || len(salt) == 0 {
		salt = make([]byte, 32)
	}
	// Extract
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	// Expand
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// GenerateX25519KeyPair generates a new private and public key for destination encryption
func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// ParseX25519PublicKey decodes a 32-byte hex public key
func ParseX25519PublicKey(pubHex string) (*ecdh.PublicKey, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in public key: %w", err)
	}
	if len(pubBytes) != X25519KeySize {
		return nil, fmt.Errorf("invalid X25519 public key length: expected %d bytes, got %d", X25519KeySize, len(pubBytes))
	}
	return ecdh.X25519().NewPublicKey(pubBytes)
}

// ParseX25519PrivateKey decodes a 32-byte hex private key
func ParseX25519PrivateKey(privHex string) (*ecdh.PrivateKey, error) {
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in private key: %w", err)
	}
	if len(privBytes) != X25519KeySize {
		return nil, fmt.Errorf("invalid X25519 private key length: expected %d bytes, got %d", X25519KeySize, len(privBytes))
	}
	return ecdh.X25519().NewPrivateKey(privBytes)
}

// EncryptForDestination encrypts a payload so that ONLY the destination possessing the matching
// private key can decrypt it. Intermediate coordinators possess neither key and CANNOT decrypt.
func EncryptForDestination(destPubHex string, payload map[string]interface{}) (string, error) {
	if destPubHex == "" {
		return "", errors.New("missing destination encryption public key")
	}

	destPub, err := ParseX25519PublicKey(destPubHex)
	if err != nil {
		return "", fmt.Errorf("invalid destination public key: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// 1. Generate ephemeral sender keypair
	ephemPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemPubBytes := ephemPriv.PublicKey().Bytes()

	// 2. Perform ECDH key agreement with destination public key
	sharedSecret, err := ephemPriv.ECDH(destPub)
	if err != nil {
		return "", fmt.Errorf("ECDH computation failed: %w", err)
	}

	// 3. Derive 32-byte AES key via HKDF
	aesKey := hkdfSha256(sharedSecret, nil, []byte(HKDFInfoTag), 32)

	// 4. Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, payloadBytes, nil)

	// Wire package: EphemeralPub (32B) + Nonce (12B) + CiphertextWithTag
	packet := make([]byte, 0, len(ephemPubBytes)+len(nonce)+len(ciphertext))
	packet = append(packet, ephemPubBytes...)
	packet = append(packet, nonce...)
	packet = append(packet, ciphertext...)

	return hex.EncodeToString(packet), nil
}

// DecryptForDestination decrypts an authenticated payload using the destination node's private key.
// If an intermediary or unauthorized party attempts decryption, it fails with an authentication error.
func DecryptForDestination(destPriv *ecdh.PrivateKey, cipherHex string) (map[string]interface{}, error) {
	if destPriv == nil {
		return nil, errors.New("nil destination private key")
	}
	if cipherHex == "" {
		return make(map[string]interface{}), nil
	}

	packet, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex ciphertext: %w", err)
	}

	minLen := X25519KeySize + GCMNonceSize + 16 // 32 + 12 + 16 (GCM tag)
	if len(packet) < minLen {
		return nil, fmt.Errorf("ciphertext too short (%d bytes < min %d bytes)", len(packet), minLen)
	}

	ephemPubBytes := packet[:X25519KeySize]
	nonce := packet[X25519KeySize : X25519KeySize+GCMNonceSize]
	ciphertext := packet[X25519KeySize+GCMNonceSize:]

	ephemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key in packet: %w", err)
	}

	// 1. Perform ECDH key agreement with destination private key
	sharedSecret, err := destPriv.ECDH(ephemPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	// 2. Derive identical 32-byte AES key via HKDF
	aesKey := hkdfSha256(sharedSecret, nil, []byte(HKDFInfoTag), 32)

	// 3. Decrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("destination decryption failed (intermediary or key mismatch): %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted JSON: %w", err)
	}

	return payload, nil
}

