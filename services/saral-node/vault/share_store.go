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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrShareNotFound = errors.New("share not found in vault")
	ErrStaleEpoch    = errors.New("access denied: share belongs to a stale epoch")
)

// ShareRecordMetadata stores authenticated, non-secret metadata about the stored share.
// STRICT PRIVACY GUARANTEE: Neither complete private keys, aggregate public keys,
// nor derived blockchain addresses are EVER persisted in the vault.
type ShareRecordMetadata struct {
	WalletID                   string `json:"wallet_id,omitempty"`
	KeyID                      string `json:"key_id,omitempty"`
	UserBindingID              string `json:"user_binding_id,omitempty"`
	DKGSessionID               string `json:"dkg_session_id,omitempty"`
	SessionID                  string `json:"sessionId,omitempty"`
	CommitteeID                string `json:"committee_id,omitempty"`
	ParticipantID              string `json:"participant_id,omitempty"`
	NodeID                     string `json:"nodeId,omitempty"`
	NodeIndex                  int    `json:"nodeIndex"`
	ChainFamily                string `json:"chain_family,omitempty"`
	Curve                      string `json:"curve,omitempty"`
	Threshold                  int    `json:"threshold,omitempty"`
	ShareEpoch                 uint64 `json:"share_epoch,omitempty"`
	Epoch                      uint64 `json:"epoch,omitempty"`
	ShareVersion               uint64 `json:"shareVersion,omitempty"`
	State                      string `json:"state"` // "ACTIVE", "EXPIRED", "ERASED"
	PublicShareCommitment      string `json:"publicShareCommitment,omitempty"`
	PublicSecretCommitment     string `json:"publicSecretCommitment,omitempty"`
	CreationTimestamp          int64  `json:"creation_timestamp,omitempty"`
	CreatedAt                  int64  `json:"createdAt,omitempty"`
	UpdatedAt                  int64  `json:"updatedAt,omitempty"`
	RecordVersion              int    `json:"record_version"`
	MasterSigningPublicKeyHash string `json:"master_point_digest,omitempty"`
}

// SecretPayload holds the confidential share values before local vault encryption
type SecretPayload struct {
	ShareHex      string `json:"shareHex"`
	BlindShareHex string `json:"blindShareHex"`
}

// VaultEncryptedFile is the on-disk file format storing ciphertext and authenticated metadata
type VaultEncryptedFile struct {
	Metadata      ShareRecordMetadata `json:"metadata"`
	NonceHex      string              `json:"nonceHex"`
	CiphertextHex string              `json:"ciphertextHex"`
	VaultVersion  int                 `json:"vaultVersion"`
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

	// Derive 32-byte AES-256 vault key via SHA-256(identityKey || salt)
	h := sha256.New()
	h.Write(identityKey)
	h.Write([]byte("saral-v3-share-vault-key-salt"))
	vaultKey := h.Sum(nil)

	return &ShareStore{
		vaultDir: vaultDir,
		vaultKey: vaultKey,
	}, nil
}

func (s *ShareStore) getRecordPath(id string, epoch uint64) string {
	return filepath.Join(s.vaultDir, fmt.Sprintf("share_%s_epoch_%d.json", id, epoch))
}

func (s *ShareStore) Persistent() bool {
	return s != nil && s.vaultDir != ""
}

var recordIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$`)

func ValidRecordID(id string) bool {
	return recordIDPattern.MatchString(id)
}

// computeAad returns the cryptographic Associated Authenticated Data for AES-256-GCM.
func computeAad(meta *ShareRecordMetadata) []byte {
	if meta.RecordVersion == 2 {
		encoded, _ := json.Marshal(meta)
		return append([]byte("saral-vault-key-v2:"), encoded...)
	}
	if meta.WalletID != "" || meta.KeyID != "" {
		epoch := meta.ShareEpoch
		if epoch == 0 {
			epoch = meta.Epoch
		}
		return []byte(fmt.Sprintf("saral-vault-v2:%s:%s:%s:%s:%s:%s:%d",
			meta.WalletID, meta.KeyID, meta.UserBindingID, meta.CommitteeID,
			meta.ParticipantID, meta.Curve, epoch))
	}
	return []byte(fmt.Sprintf("%s:%d", meta.CommitteeID, meta.Epoch))
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

	// Normalize metadata fields
	if meta.Epoch == 0 && meta.ShareEpoch != 0 {
		meta.Epoch = meta.ShareEpoch
	}
	if meta.ShareEpoch == 0 && meta.Epoch != 0 {
		meta.ShareEpoch = meta.Epoch
	}
	if meta.DKGSessionID == "" && meta.SessionID != "" {
		meta.DKGSessionID = meta.SessionID
	}
	if meta.SessionID == "" && meta.DKGSessionID != "" {
		meta.SessionID = meta.DKGSessionID
	}
	if meta.ParticipantID == "" && meta.NodeID != "" {
		meta.ParticipantID = meta.NodeID
	}
	if meta.NodeID == "" && meta.ParticipantID != "" {
		meta.NodeID = meta.ParticipantID
	}
	if meta.CreatedAt == 0 {
		meta.CreatedAt = time.Now().UnixMilli()
	}
	if meta.CreationTimestamp == 0 {
		meta.CreationTimestamp = meta.CreatedAt
	}
	meta.UpdatedAt = time.Now().UnixMilli()
	if meta.RecordVersion == 0 {
		meta.RecordVersion = 1
	}
	primaryID := meta.KeyID
	if primaryID == "" {
		primaryID = meta.CommitteeID
	}
	if meta.RecordVersion == 2 && meta.KeyID == "" {
		primaryID = meta.DKGSessionID
	}
	if meta.RecordVersion == 2 {
		curve, err := cryptography.ParseCurve(meta.Curve)
		if err != nil || share.Curve() != curve || blindShare.Curve() != curve {
			return fmt.Errorf("share curve does not match authenticated metadata")
		}
	}
	for _, id := range []string{primaryID, meta.CommitteeID, meta.KeyID, meta.DKGSessionID} {
		if id != "" && !ValidRecordID(id) {
			return fmt.Errorf("invalid share record identifier")
		}
	}
	if primaryID == "" {
		return fmt.Errorf("missing share record identifier")
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
	defer func() {
		for i := range plainBytes {
			plainBytes[i] = 0
		}
	}()

	// 2. Encrypt with AES-256-GCM using authenticated metadata binding (AAD)
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

	aad := computeAad(&meta)
	ciphertext := gcm.Seal(nil, nonce, plainBytes, aad)

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

	targetPath := s.getRecordPath(primaryID, meta.Epoch)
	if meta.RecordVersion == 2 {
		return s.writeDurableState(targetPath, data)
	}
	tmpPath := targetPath + ".tmp"

	// Write atomically with 0600 permissions
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}

	// Also link by committeeID if primaryID is KeyID to satisfy legacy AVSS lookups
	if meta.KeyID != "" && meta.CommitteeID != "" && meta.KeyID != meta.CommitteeID {
		commPath := s.getRecordPath(meta.CommitteeID, meta.Epoch)
		commTmp := commPath + ".tmp"
		_ = os.WriteFile(commTmp, data, 0600)
		_ = os.Rename(commTmp, commPath)
	}

	// Also link by sessionID / DKGSessionID
	sessID := meta.DKGSessionID
	if sessID == "" {
		sessID = meta.SessionID
	}
	if sessID != "" && sessID != primaryID && sessID != meta.CommitteeID {
		sessPath := s.getRecordPath(sessID, meta.Epoch)
		sessTmp := sessPath + ".tmp"
		_ = os.WriteFile(sessTmp, data, 0600)
		_ = os.Rename(sessTmp, sessPath)
	}

	return nil
}

// SaveKeyShare saves a key share with full user-binding metadata
func (s *ShareStore) SaveKeyShare(
	meta ShareRecordMetadata,
	share, blindShare *cryptography.FieldElement,
) error {
	return s.SaveShare(meta, share, blindShare)
}

// LoadShare reads and decrypts a share from the vault. Rejects stale epoch requests if currentEpoch > 0.
func (s *ShareStore) LoadShare(
	id string,
	epoch uint64,
	currentEpoch uint64,
) (*ShareRecordMetadata, *cryptography.FieldElement, *cryptography.FieldElement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.Persistent() || !ValidRecordID(id) {
		return nil, nil, nil, ErrShareNotFound
	}
	if currentEpoch > 0 && epoch < currentEpoch {
		return nil, nil, nil, fmt.Errorf("%w: requested epoch %d < active epoch %d", ErrStaleEpoch, epoch, currentEpoch)
	}

	targetPath := s.getRecordPath(id, epoch)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		// Scan directory for files matching metadata
		found := false
		if entries, dirErr := os.ReadDir(s.vaultDir); dirErr == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasPrefix(entry.Name(), "share_") || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				content, readErr := os.ReadFile(filepath.Join(s.vaultDir, entry.Name()))
				if readErr != nil {
					continue
				}
				var checkFile VaultEncryptedFile
				if json.Unmarshal(content, &checkFile) == nil {
					if checkFile.Metadata.RecordVersion < 2 && checkFile.Metadata.Epoch == epoch &&
						(checkFile.Metadata.KeyID == id || checkFile.Metadata.CommitteeID == id ||
							checkFile.Metadata.SessionID == id || checkFile.Metadata.WalletID == id) {
						data = content
						found = true
						break
					}
				}
			}
		}
		if !found {
			return nil, nil, nil, ErrShareNotFound
		}
	}

	var vaultFile VaultEncryptedFile
	if err := json.Unmarshal(data, &vaultFile); err != nil {
		return nil, nil, nil, err
	}

	if vaultFile.Metadata.State == "ERASED" {
		return nil, nil, nil, errors.New("share was securely erased")
	}
	if vaultFile.Metadata.Epoch != epoch {
		return nil, nil, nil, ErrStaleEpoch
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
	if len(nonce) != gcm.NonceSize() {
		return nil, nil, nil, errors.New("invalid vault nonce")
	}

	// Try AAD v2 (full authenticated metadata binding)
	aadV2 := computeAad(&vaultFile.Metadata)
	plainBytes, err := gcm.Open(nil, nonce, ciphertext, aadV2)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault decryption failed: %w", err)
	}
	defer func() {
		for i := range plainBytes {
			plainBytes[i] = 0
		}
	}()

	var secPayload SecretPayload
	if err := json.Unmarshal(plainBytes, &secPayload); err != nil {
		return nil, nil, nil, err
	}

	curve := cryptography.CurveP256
	if vaultFile.Metadata.RecordVersion == 2 {
		curve, err = cryptography.ParseCurve(vaultFile.Metadata.Curve)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	share, err := curve.ParseScalar(secPayload.ShareHex)
	if err != nil {
		return nil, nil, nil, err
	}
	blindShare, err := curve.ParseScalar(secPayload.BlindShareHex)
	if err != nil {
		share.Zero()
		return nil, nil, nil, err
	}

	return &vaultFile.Metadata, share, blindShare, nil
}

// LoadKeyShare retrieves a key share by key reference ID
func (s *ShareStore) LoadKeyShare(keyID string, epoch uint64) (*ShareRecordMetadata, *cryptography.FieldElement, *cryptography.FieldElement, error) {
	return s.LoadShare(keyID, epoch, 0)
}

// SecureEraseEpoch securely overwrites with random bytes and removes old epoch share files
func (s *ShareStore) SecureEraseEpoch(committeeID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !ValidRecordID(committeeID) {
		return ErrShareNotFound
	}
	targetPath := s.getRecordPath(committeeID, epoch)
	info, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	size := info.Size()
	f, err := os.OpenFile(targetPath, os.O_WRONLY, 0600)
	if err == nil {
		for pass := 0; pass < 3; pass++ {
			randomBytes := make([]byte, size)
			_, _ = rand.Read(randomBytes)
			_, _ = f.WriteAt(randomBytes, 0)
			_ = f.Sync()
		}
		zeros := make([]byte, size)
		_, _ = f.WriteAt(zeros, 0)
		_ = f.Sync()
		_ = f.Close()
	}

	return os.Remove(targetPath)
}
