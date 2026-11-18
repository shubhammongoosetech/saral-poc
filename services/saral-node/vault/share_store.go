package vault

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
	"path/filepath"
	"sync"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrShareNotFound = errors.New("share not found in vault")
	ErrStaleEpoch    = errors.New("access denied: share belongs to a stale epoch")
)

// ShareRecordMetadata stores non-secret public metadata about the stored share
type ShareRecordMetadata struct {
	CommitteeID            string `json:"committeeId"`
	SessionID              string `json:"sessionId"`
	NodeID                 string `json:"nodeId"`
	NodeIndex              int    `json:"nodeIndex"`
	Epoch                  uint64 `json:"epoch"`
	ShareVersion           uint64 `json:"shareVersion"`
	State                  string `json:"state"` // "ACTIVE", "EXPIRED", "ERASED"
	PublicShareCommitment  string `json:"publicShareCommitment"`
	PublicSecretCommitment string `json:"publicSecretCommitment"`
	CreatedAt              int64  `json:"createdAt"`
	UpdatedAt              int64  `json:"updatedAt"`
}

// SecretPayload holds the confidential share values before local vault encryption
type SecretPayload struct {
	ShareHex      string `json:"shareHex"`
	BlindShareHex string `json:"blindShareHex"`
}

// VaultEncryptedFile is the on-disk file format storing ciphertext and authenticated metadata
type VaultEncryptedFile struct {
	Metadata       ShareRecordMetadata `json:"metadata"`
	NonceHex       string              `json:"nonceHex"`
	CiphertextHex  string              `json:"ciphertextHex"`
	VaultVersion   int                 `json:"vaultVersion"`
}

// ShareStore manages secure, encrypted, atomic on-disk persistence for a node's secret shares
type ShareStore struct {
	vaultDir string
	vaultKey []byte // 32-byte AES key derived from node private identity or local key file
	mu       sync.RWMutex
}

// NewShareStore creates a new ShareStore in vaultDir, deriving vault encryption key from identityKey
func NewShareStore(vaultDir string, identityKey []byte) (*ShareStore, error) {
	if vaultDir != "" {
		if err := os.MkdirAll(vaultDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create vault dir: %w", err)
		}
	}

	// Derive 32-byte AES-256 vault key via SHA-256(identityKey || "saral-v3-share-vault-key")
	h := sha256.New()
	h.Write(identityKey)
	h.Write([]byte("saral-v3-share-vault-key-salt"))
	vaultKey := h.Sum(nil)

	return &ShareStore{
		vaultDir: vaultDir,
		vaultKey: vaultKey,
	}, nil
}

func (s *ShareStore) getRecordPath(committeeID string, epoch uint64) string {
	return filepath.Join(s.vaultDir, fmt.Sprintf("share_%s_epoch_%d.json", committeeID, epoch))
}

// SaveShare atomically encrypts and persists a share record to disk with 0600 permissions
func (s *ShareStore) SaveShare(
	meta ShareRecordMetadata,
	share, blindShare *cryptography.FieldElement,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.vaultDir == "" {
		return nil
	}

	// 1. Prepare plaintext secret payload
	secPayload := SecretPayload{
		ShareHex:      share.Hex(),
		BlindShareHex: blindShare.Hex(),
	}
	plainBytes, err := json.Marshal(secPayload)
	if err != nil {
		return err
	}

	// 2. Encrypt with AES-256-GCM
	block, err := aes.NewCipher(s.vaultKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plainBytes, []byte(fmt.Sprintf("%s:%d", meta.CommitteeID, meta.Epoch)))

	vaultFile := VaultEncryptedFile{
		Metadata:      meta,
		NonceHex:      hex.EncodeToString(nonce),
		CiphertextHex: hex.EncodeToString(ciphertext),
		VaultVersion:  1,
	}

	data, err := json.MarshalIndent(vaultFile, "", "  ")
	if err != nil {
		return err
	}

	targetPath := s.getRecordPath(meta.CommitteeID, meta.Epoch)
	tmpPath := targetPath + ".tmp"

	// Write with 0600 permissions
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, targetPath)
}

// LoadShare reads and decrypts a share from the vault. Rejects stale epoch requests if minEpoch is specified.
func (s *ShareStore) LoadShare(
	committeeID string,
	epoch uint64,
	currentEpoch uint64,
) (*ShareRecordMetadata, *cryptography.FieldElement, *cryptography.FieldElement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if currentEpoch > 0 && epoch < currentEpoch {
		return nil, nil, nil, fmt.Errorf("%w: requested epoch %d < active epoch %d", ErrStaleEpoch, epoch, currentEpoch)
	}

	targetPath := s.getRecordPath(committeeID, epoch)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, nil, nil, ErrShareNotFound
	}

	var vaultFile VaultEncryptedFile
	if err := json.Unmarshal(data, &vaultFile); err != nil {
		return nil, nil, nil, err
	}

	if vaultFile.Metadata.State == "ERASED" {
		return nil, nil, nil, errors.New("share was securely erased")
	}

	nonce, err := hex.DecodeString(vaultFile.NonceHex)
	if err != nil {
		return nil, nil, nil, err
	}
	ciphertext, err := hex.DecodeString(vaultFile.CiphertextHex)
	if err != nil {
		return nil, nil, nil, err
	}

	block, err := aes.NewCipher(s.vaultKey)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	plainBytes, err := gcm.Open(nil, nonce, ciphertext, []byte(fmt.Sprintf("%s:%d", vaultFile.Metadata.CommitteeID, vaultFile.Metadata.Epoch)))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault decryption failed: %w", err)
	}

	var secPayload SecretPayload
	if err := json.Unmarshal(plainBytes, &secPayload); err != nil {
		return nil, nil, nil, err
	}

	share, err := cryptography.NewFieldElementFromHex(secPayload.ShareHex)
	if err != nil {
		return nil, nil, nil, err
	}
	blindShare, err := cryptography.NewFieldElementFromHex(secPayload.BlindShareHex)
	if err != nil {
		return nil, nil, nil, err
	}

	return &vaultFile.Metadata, share, blindShare, nil
}

// SecureEraseEpoch securely overwrites with random bytes and removes old epoch share files
func (s *ShareStore) SecureEraseEpoch(committeeID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := s.getRecordPath(committeeID, epoch)
	info, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Overwrite file contents in-place without truncating, followed by fsync
	size := info.Size()
	f, err := os.OpenFile(targetPath, os.O_WRONLY, 0600)
	if err == nil {
		// Multi-pass overwrite: CSPRNG random bytes, then zeros, with fsync after each pass
		for pass := 0; pass < 3; pass++ {
			randomBytes := make([]byte, size)
			_, _ = rand.Read(randomBytes)
			_, _ = f.WriteAt(randomBytes, 0)
			_ = f.Sync()
		}
		// Zeroing pass
		zeros := make([]byte, size)
		_, _ = f.WriteAt(zeros, 0)
		_ = f.Sync()
		_ = f.Close()
	}

	// Remove file from directory entry
	return os.Remove(targetPath)
}

