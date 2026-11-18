package rpc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWalletCreationCurveValidation(t *testing.T) {
	srv := &Server{
		dkgSessions: make(map[string]*DKGSessionMeta),
		wallets:     make(map[string]*WalletRecord),
	}

	// Step 1: Empty parameters must return -32000
	_, err := srv.handleCreateWallet(nil, "")
	if err == nil || err.Code != -32000 {
		t.Fatalf("expected error -32000 for empty params, got: %v", err)
	}

	// Step 2: Register a completed DKG session on NIST P-256
	srv.dkgSessions["dkg-test-wallet"] = &DKGSessionMeta{
		SessionID:              "dkg-test-wallet",
		CommitteeID:            "saral-global-15",
		Epoch:                  1,
		N:                      15,
		K:                      5,
		T:                      4,
		State:                  "COMPLETED",
		MasterSigningPublicKey: "04e703a48aec8c41d2b76f7e2035ad7c64ddf7e81c8add799e1e0560bffc72bf5882dc4ac70d0771421bb9f4450dd3165dff2d90257c370b6cc3e384f7b8cfdc53",
		MasterSecretCommitment: "0407cda022b6b6ba43f3ca464290b4735d9f85e238a7d1cab50125a22c9c1405179204dd208f05a08c5e203cd58990b1dad18557b342ea4e463cb95730f430fdda",
		MasterPublicKey:        "04e703a48aec8c41d2b76f7e2035ad7c64ddf7e81c8add799e1e0560bffc72bf5882dc4ac70d0771421bb9f4450dd3165dff2d90257c370b6cc3e384f7b8cfdc53",
		Curve:                  "NIST P-256",
	}

	// Step 3: Attempt to create Ethereum wallet with NIST P-256 DKG key
	// MUST be strictly rejected due to INCOMPATIBLE_CURVE (-32002)
	ethParams, _ := json.Marshal(map[string]interface{}{
		"name":         "Treasury ETH",
		"blockchain":   "ethereum",
		"network":      "sepolia",
		"dkgSessionId": "dkg-test-wallet",
	})
	_, ethErr := srv.handleCreateWallet(ethParams, "")
	if ethErr == nil || ethErr.Code != -32002 || !strings.Contains(ethErr.Message, "INCOMPATIBLE_CURVE") {
		t.Fatalf("expected -32002 INCOMPATIBLE_CURVE for Ethereum on NIST P-256, got: %v", ethErr)
	}

	// Step 4: Attempt to create Bitcoin Taproot wallet with NIST P-256 key
	// MUST be strictly rejected due to INCOMPATIBLE_CURVE (-32002)
	btcParams, _ := json.Marshal(map[string]interface{}{
		"name":         "Treasury BTC",
		"blockchain":   "bitcoin",
		"network":      "mainnet",
		"dkgSessionId": "dkg-test-wallet",
	})
	_, btcErr := srv.handleCreateWallet(btcParams, "")
	if btcErr == nil || btcErr.Code != -32002 || !strings.Contains(btcErr.Message, "INCOMPATIBLE_CURVE") {
		t.Fatalf("expected -32002 INCOMPATIBLE_CURVE for Bitcoin on NIST P-256, got: %v", btcErr)
	}

	// Step 5: Attempt to create Solana wallet with NIST P-256 key
	// MUST be strictly rejected due to INCOMPATIBLE_CURVE (-32002)
	solParams, _ := json.Marshal(map[string]interface{}{
		"name":         "Treasury SOL",
		"blockchain":   "solana",
		"network":      "devnet",
		"dkgSessionId": "dkg-test-wallet",
	})
	_, solErr := srv.handleCreateWallet(solParams, "")
	if solErr == nil || solErr.Code != -32002 || !strings.Contains(solErr.Message, "INCOMPATIBLE_CURVE") {
		t.Fatalf("expected -32002 INCOMPATIBLE_CURVE for Solana on NIST P-256, got: %v", solErr)
	}

	// Step 6: Create WebAuthn / Passkey P-256 wallet -> MUST SUCCEED
	passkeyParams, _ := json.Marshal(map[string]interface{}{
		"name":         "Corporate Passkey Smart Account",
		"blockchain":   "passkey-p256",
		"network":      "sepolia",
		"dkgSessionId": "dkg-test-wallet",
	})
	wResult, passErr := srv.handleCreateWallet(passkeyParams, "")
	if passErr != nil {
		t.Fatalf("unexpected error creating passkey wallet: %v", passErr)
	}
	record := wResult.(*WalletRecord)
	if record.Status != "ADDRESS_CREATED" {
		t.Fatalf("expected status ADDRESS_CREATED, got: %s", record.Status)
	}
	if !strings.HasPrefix(record.Address, "0x") || len(record.Address) != 42 {
		t.Fatalf("invalid derived address format: %s", record.Address)
	}
	if record.SigningEnabled {
		t.Fatalf("signingEnabled must be false in Phase 3")
	}

	// Step 7: Query wallets list and verify persistence
	wListResult, _ := srv.handleGetWallets(nil)
	wList := wListResult.([]*WalletRecord)
	if len(wList) != 1 || wList[0].WalletID != record.WalletID {
		t.Fatalf("failed retrieving wallet list from coordinator store")
	}

	// Step 8: Verify dispatch routing
	dispatchRes, dErr := srv.dispatch("saral_getWalletById", []byte(`{"walletId":"`+record.WalletID+`"}`), "")
	if dErr != nil {
		t.Fatalf("dispatch error: %v", dErr)
	}
	retrieved := dispatchRes.(*WalletRecord)
	if retrieved.Address != record.Address {
		t.Fatalf("retrieved address mismatch")
	}

	// Step 9: Verify saral_signTransaction stub compliance
	_, signErr := srv.dispatch("saral_signTransaction", []byte(`{}`), "")
	if signErr == nil || signErr.Code != -32000 || !strings.Contains(signErr.Message, "NOT_IMPLEMENTED") {
		t.Fatalf("expected -32000 NOT_IMPLEMENTED for signTransaction, got: %v", signErr)
	}

	t.Log("✅ Wallet coordinator RPC methods and curve rejection validation PASSED")
}
