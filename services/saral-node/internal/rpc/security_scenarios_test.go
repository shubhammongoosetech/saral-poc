package rpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

func generateNodeTestToken(priv ed25519.PrivateKey, claims map[string]interface{}) string {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "node-test-kid"}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(claims)

	h64 := base64.RawURLEncoding.EncodeToString(hBytes)
	p64 := base64.RawURLEncoding.EncodeToString(pBytes)
	sigInput := []byte(h64 + "." + p64)
	sig := ed25519.Sign(priv, sigInput)
	s64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", h64, p64, s64)
}

func TestNodeSecurity_ComprehensiveScenarios(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	verifier := auth.GetNodeTokenVerifier()
	verifier.SetDefaultKey(pub)

	tmpDir, err := os.MkdirTemp("", "node_sec_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	identKey := []byte("node-ident-key-32-bytes-secure!!")
	shareStore, err := vault.NewShareStore(tmpDir, identKey)
	if err != nil {
		t.Fatal(err)
	}

	// Save Alice's key share in the vault
	aliceMeta := vault.ShareRecordMetadata{
		WalletID:          "wal_alice_1",
		KeyID:             "key_mst_alice",
		UserBindingID:     "usr_alice_123",
		DKGSessionID:      "dkg_sess_001",
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
	aliceShare := cryptography.NewFieldElement(11223344)
	aliceBlind := cryptography.NewFieldElement(55667788)
	if err := shareStore.SaveKeyShare(aliceMeta, aliceShare, aliceBlind); err != nil {
		t.Fatal(err)
	}

	dkgEngine := dkg.NewEngine("node-foundation-1", "FOUNDATION", tmpDir, shareStore, nil, nil)
	mux := http.NewServeMux()
	RegisterDKGRoutes(mux, dkgEngine)

	// -------------------------------------------------------------
	// SCENARIO 11: NODE VAULT INTEGRITY AUDIT
	// -------------------------------------------------------------
	t.Run("Scenario 11: Node Vault Integrity (Zero Unencrypted Secret/Address)", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "share_key_mst_alice_epoch_1.json")
		rawBytes, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		fileStr := string(rawBytes)

		// Assert file does not contain raw share
		if strings.Contains(fileStr, aliceShare.Hex()) {
			t.Fatalf("SECURITY VIOLATION: Plaintext share leaked into vault file!")
		}

		// Prohibit address / public key persistence
		for _, forbidden := range []string{"wallet_address", "public_wallet_address", "aggregate_public_key", "master_public_key", "signing_public_key", "derived_address"} {
			if strings.Contains(strings.ToLower(fileStr), forbidden) {
				t.Fatalf("SECURITY VIOLATION: Forbidden persistence field %s found in vault file!", forbidden)
			}
		}
		t.Log("✅ Node vault file integrity verified: zero unencrypted private keys, zero public keys, zero addresses")
	})

	// -------------------------------------------------------------
	// SCENARIO 12: AEAD AUTHENTICATION & TAMPER DETECTION
	// -------------------------------------------------------------
	t.Run("Scenario 12: AEAD Authentication & Tamper Detection", func(t *testing.T) {
		filePath := filepath.Join(tmpDir, "share_key_mst_alice_epoch_1.json")
		rawBytes, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatal(err)
		}

		var vf vault.VaultEncryptedFile
		if err := json.Unmarshal(rawBytes, &vf); err != nil {
			t.Fatal(err)
		}

		// Flip a bit in ciphertext
		ctBytes, _ := hex.DecodeString(vf.CiphertextHex)
		ctBytes[len(ctBytes)-1] ^= 0x01
		vf.CiphertextHex = hex.EncodeToString(ctBytes)
		tampered, _ := json.Marshal(vf)
		_ = os.WriteFile(filePath, tampered, 0600)

		_, _, _, err = shareStore.LoadKeyShare("key_mst_alice", 1)
		if err == nil {
			t.Fatalf("CRITICAL SECURITY FLAW: Tampered ciphertext was accepted!")
		}
		t.Log("✅ AEAD successfully rejected tampered ciphertext")

		// Restore valid file
		_ = os.WriteFile(filePath, rawBytes, 0600)
	})

	// -------------------------------------------------------------
	// SCENARIO 14: REPLAY ATTACK DEFENSE (EXPIRED TOKEN REJECTED)
	// -------------------------------------------------------------
	t.Run("Scenario 14: Replay Attack Defense (Expired Token Rejected)", func(t *testing.T) {
		expiredClaims := map[string]interface{}{
			"sub":         "usr_alice_123",
			"userId":      "usr_alice_123",
			"walletId":    "wal_alice_1",
			"keyId":       "key_mst_alice",
			"operation":   "derive_public_key",
			"mfaVerified": true,
			"exp":         time.Now().Unix() - 120, // Expired
			"iat":         time.Now().Unix() - 180,
		}
		token := generateNodeTestToken(priv, expiredClaims)

		reqBody := `{"keyId":"key_mst_alice","userId":"usr_alice_123"}`
		req := httptest.NewRequest("POST", "/node/dkg/share-contribution", strings.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 Forbidden for expired token, got %d: %s", w.Code, w.Body.String())
		}
		t.Log("✅ Replay attack defense verified: expired token rejected with HTTP 403")
	})

	// -------------------------------------------------------------
	// SCENARIO 16: CROSS-USER ACCESS DENIAL (USER B ON USER A'S KEY)
	// -------------------------------------------------------------
	t.Run("Scenario 16: Cross-User Access Denial (403 Forbidden)", func(t *testing.T) {
		eveClaims := map[string]interface{}{
			"sub":         "usr_eve_attacker",
			"userId":      "usr_eve_attacker",
			"walletId":    "wal_alice_1",
			"keyId":       "key_mst_alice",
			"operation":   "derive_public_key",
			"mfaVerified": true,
			"exp":         time.Now().Unix() + 60,
			"iat":         time.Now().Unix(),
		}
		eveToken := generateNodeTestToken(priv, eveClaims)

		reqBody := `{"keyId":"key_mst_alice","userId":"usr_eve_attacker"}`
		req := httptest.NewRequest("POST", "/node/dkg/share-contribution", strings.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+eveToken)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 Forbidden when User B requests User A's key, got %d: %s", w.Code, w.Body.String())
		}
		t.Log("✅ Cross-user attack blocked: Eve denied access to Alice's key share with HTTP 403")
	})

	// -------------------------------------------------------------
	// SCENARIO 17: UNAUTHENTICATED ACCESS DENIAL
	// -------------------------------------------------------------
	t.Run("Scenario 17: Unauthenticated Access Denial", func(t *testing.T) {
		reqBody := `{"keyId":"key_mst_alice","userId":"usr_alice_123"}`
		req := httptest.NewRequest("POST", "/node/dkg/share-contribution", strings.NewReader(reqBody))
		// No Authorization header!
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
			t.Fatalf("expected HTTP 401/403 for unauthenticated request, got %d", w.Code)
		}
		t.Log("✅ Unauthenticated access denied with HTTP 403")
	})

	// -------------------------------------------------------------
	// SCENARIO 18: MISSING MFA CLAIM DENIAL
	// -------------------------------------------------------------
	t.Run("Scenario 18: Missing MFA Claim Denial", func(t *testing.T) {
		noMfaClaims := map[string]interface{}{
			"sub":         "usr_alice_123",
			"userId":      "usr_alice_123",
			"walletId":    "wal_alice_1",
			"keyId":       "key_mst_alice",
			"operation":   "derive_public_key",
			"mfaVerified": false, // MFA False!
			"exp":         time.Now().Unix() + 60,
			"iat":         time.Now().Unix(),
		}
		token := generateNodeTestToken(priv, noMfaClaims)

		reqBody := `{"keyId":"key_mst_alice","userId":"usr_alice_123"}`
		req := httptest.NewRequest("POST", "/node/dkg/share-contribution", strings.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 for missing MFA, got %d: %s", w.Code, w.Body.String())
		}
		t.Log("✅ Missing MFA claim correctly rejected with HTTP 403")
	})

	// -------------------------------------------------------------
	// SUCCESS PATH: AUTHORIZED USER DERIVES PUBLIC CONTRIBUTION
	// -------------------------------------------------------------
	t.Run("Success Path: Authorized Alice Derives Public Contribution", func(t *testing.T) {
		validClaims := map[string]interface{}{
			"sub":         "usr_alice_123",
			"userId":      "usr_alice_123",
			"walletId":    "wal_alice_1",
			"keyId":       "key_mst_alice",
			"operation":   "derive_public_key",
			"mfaVerified": true,
			"exp":         time.Now().Unix() + 60,
			"iat":         time.Now().Unix(),
		}
		token := generateNodeTestToken(priv, validClaims)

		reqBody := `{"keyId":"key_mst_alice","userId":"usr_alice_123","curve":"secp256k1"}`
		req := httptest.NewRequest("POST", "/node/dkg/share-contribution", strings.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK for authorized Alice, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		ptHex, ok := resp["publicPoint"].(string)
		if !ok || len(ptHex) != 130 {
			t.Fatalf("invalid publicPoint hex in response: %v", resp["publicPoint"])
		}
		t.Logf("✅ Authorized Alice successfully received public point contribution Y_i: %s...", ptHex[:32])
	})
}

