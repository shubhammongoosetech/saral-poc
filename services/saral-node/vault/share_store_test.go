package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestShareStore_SaveAndLoadKeyShare(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identKey := []byte("test-node-identity-key-32-bytes!!")
	store, err := NewShareStore(tmpDir, identKey)
	if err != nil {
		t.Fatal(err)
	}

	meta := ShareRecordMetadata{
		WalletID:          "wal_test_12345",
		KeyID:             "key_mst_67890",
		UserBindingID:     "usr_alice_111",
		DKGSessionID:      "dkg_session_999",
		CommitteeID:       "comm_foundation_5",
		ParticipantID:     "node-foundation-1",
		NodeIndex:         1,
		ChainFamily:       "evm",
		Curve:             "secp256k1",
		Threshold:         3,
		ShareEpoch:        1,
		State:             "ACTIVE",
		CreationTimestamp: time.Now().UnixMilli(),
		RecordVersion:     1,
	}

	share := cryptography.NewFieldElement(123456789)
	blind := cryptography.NewFieldElement(987654321)

	if err := store.SaveKeyShare(meta, share, blind); err != nil {
		t.Fatalf("failed saving key share: %v", err)
	}

	// 1. Verify file exists on disk with 0600 permissions
	recordPath := filepath.Join(tmpDir, "share_key_mst_67890_epoch_1.json")
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatalf("share file not found on disk: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}

	// 2. ZERO PUBLIC KEY & ADDRESS PERSISTENCE AUDIT:
	// Verify file content does NOT contain raw secret, unencrypted share, or addresses
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, share.Hex()) {
		t.Fatalf("SECURITY VIOLATION: plaintext share found in vault file!")
	}
	for _, forbidden := range []string{"address", "public_key", "master_public_key", "derived_address"} {
		if strings.Contains(strings.ToLower(content), forbidden) {
			t.Fatalf("SECURITY VIOLATION: forbidden persistence field '%s' found in vault file: %s", forbidden, content)
		}
	}

	// 3. Node restart simulation: open vault with a fresh ShareStore instance
	storeAfterRestart, err := NewShareStore(tmpDir, identKey)
	if err != nil {
		t.Fatal(err)
	}

	loadedMeta, loadedShare, loadedBlind, err := storeAfterRestart.LoadKeyShare("key_mst_67890", 1)
	if err != nil {
		t.Fatalf("failed loading key share after restart: %v", err)
	}

	if loadedMeta.WalletID != meta.WalletID || loadedMeta.UserBindingID != meta.UserBindingID {
		t.Fatalf("metadata mismatch: expected %s / %s, got %s / %s",
			meta.WalletID, meta.UserBindingID, loadedMeta.WalletID, loadedMeta.UserBindingID)
	}
	if !loadedShare.Equal(share) || !loadedBlind.Equal(blind) {
		t.Fatalf("decrypted share mismatch!")
	}

	// 4. Mismatched key store (wrong identity key) cannot decrypt
	wrongIdentKey := []byte("wrong-node-identity-key-32-bytes")
	wrongStore, err := NewShareStore(tmpDir, wrongIdentKey)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = wrongStore.LoadKeyShare("key_mst_67890", 1)
	if err == nil {
		t.Fatalf("expected decryption failure with wrong vault key, but succeeded!")
	}
}

