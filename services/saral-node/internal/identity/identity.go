package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type NodeIdentity struct {
	NodeID       string `json:"nodeId"`
	Domain       string `json:"domain"`
	NodeIndex    int    `json:"nodeIndex"`
	PublicKeyHex string `json:"publicKeyHex"`
	PrivateKey   string `json:"privateKeyHex"`
	CreatedAt    string `json:"createdAt"`
}

type IdentityManager struct {
	Identity   *NodeIdentity
	vaultDir   string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func LoadOrGenerateIdentity(vaultDir, defaultNodeID, domain string, nodeIndex int) (*IdentityManager, error) {
	if vaultDir == "" {
		vaultDir = filepath.Join(os.TempDir(), "saral-vault-"+defaultNodeID)
	}

	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	idPath := filepath.Join(vaultDir, "identity.json")

	// 1. Try loading existing identity
	if data, err := os.ReadFile(idPath); err == nil {
		var id NodeIdentity
		if jsonErr := json.Unmarshal(data, &id); jsonErr == nil && id.NodeID != "" && id.PrivateKey != "" {
			privBytes, pErr := hex.DecodeString(id.PrivateKey)
			if pErr == nil && len(privBytes) == ed25519.PrivateKeySize {
				return &IdentityManager{
					Identity:   &id,
					vaultDir:   vaultDir,
					privateKey: ed25519.PrivateKey(privBytes),
					publicKey:  ed25519.PrivateKey(privBytes).Public().(ed25519.PublicKey),
				}, nil
			}
		}
	}

	// 2. Generate new cryptographically secure Ed25519 identity
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	nodeID := defaultNodeID
	if nodeID == "" {
		randBytes := make([]byte, 4)
		_, _ = rand.Read(randBytes)
		nodeID = fmt.Sprintf("saral-%s-%x", domain, randBytes)
	}

	id := &NodeIdentity{
		NodeID:       nodeID,
		Domain:       domain,
		NodeIndex:    nodeIndex,
		PublicKeyHex: hex.EncodeToString(pub),
		PrivateKey:   hex.EncodeToString(priv),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(idPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("failed to persist identity to vault: %w", err)
	}

	return &IdentityManager{
		Identity:   id,
		vaultDir:   vaultDir,
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

func (im *IdentityManager) Sign(data []byte) string {
	sig := ed25519.Sign(im.privateKey, data)
	return hex.EncodeToString(sig)
}

func VerifySignature(publicKeyHex string, data []byte, sigHex string) bool {
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes)
}

func (im *IdentityManager) GetVaultPath() string {
	return im.vaultDir
}

func (im *IdentityManager) UpdateNodeID(newNodeID string) error {
	if newNodeID == "" {
		return errors.New("empty node id")
	}
	im.Identity.NodeID = newNodeID
	data, err := json.MarshalIndent(im.Identity, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(im.vaultDir, "identity.json"), data, 0o600)
}
