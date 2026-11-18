package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
)

// GetEncryptionKey derives a 32-byte key for AES-256-GCM
func GetEncryptionKey() []byte {
	rawKey := os.Getenv("SARAL_ENCRYPTION_KEY")
	if rawKey == "" {
		rawKey = auth.GetInternalToken()
	}
	hash := sha256.Sum256([]byte(rawKey))
	return hash[:]
}

// EncryptPayload encrypts a map payload using AES-256-GCM and returns hex-encoded string
func EncryptPayload(payload map[string]interface{}) (string, error) {
	if payload == nil {
		return "", nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	key := GetEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptPayload decrypts a hex-encoded AES-256-GCM ciphertext back into map payload
func DecryptPayload(cipherHex string) (map[string]interface{}, error) {
	if cipherHex == "" {
		return make(map[string]interface{}), nil
	}

	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext hex: %w", err)
	}

	key := GetEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication tag mismatch): %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted JSON payload: %w", err)
	}

	return payload, nil
}
