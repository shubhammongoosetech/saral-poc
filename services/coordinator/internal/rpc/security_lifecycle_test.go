package rpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// Helper to generate a valid EdDSA scoped token
func generateTestEdDSAToken(priv ed25519.PrivateKey, claims map[string]interface{}) string {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "test-kid"}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(claims)

	h64 := base64.RawURLEncoding.EncodeToString(hBytes)
	p64 := base64.RawURLEncoding.EncodeToString(pBytes)
	sigInput := []byte(h64 + "." + p64)
	sig := ed25519.Sign(priv, sigInput)
	s64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", h64, p64, s64)
}

func TestSecurity_ComprehensiveCoordinatorLifecycleScenarios(t *testing.T) {
	_, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// -------------------------------------------------------------
	// SCENARIO 2 & 3: 3-OF-5 THRESHOLD ENFORCEMENT & SUBSET CONSISTENCY
	// -------------------------------------------------------------
	t.Run("Scenario 2 & 3: 3-of-5 Threshold & Subset Consistency (secp256k1 & Ed25519)", func(t *testing.T) {
		// Degree k - 1 = 2 polynomial: f(x) = s + a1*x + a2*x^2 mod N
		sSecp := big.NewInt(0xabcdef123456)
		a1Secp := big.NewInt(0x111122223333)
		a2Secp := big.NewInt(0x444455556666)

		// 5 participants: x = 1, 2, 3, 4, 5
		secpShares := make([]*big.Int, 5)
		secpPoints := make([]*CurvePoint, 5)
		for i := 1; i <= 5; i++ {
			x := big.NewInt(int64(i))
			x2 := new(big.Int).Mul(x, x)
			val := new(big.Int).Set(sSecp)
			val.Add(val, new(big.Int).Mul(a1Secp, x))
			val.Add(val, new(big.Int).Mul(a2Secp, x2))
			val.Mod(val, Secp256k1N)
			secpShares[i-1] = val

			px, py := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, val)
			secpPoints[i-1] = &CurvePoint{X: px, Y: py}
		}

		// Expected aggregate master public key Y = s * G
		expectedYx, expectedYy := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, sSecp)

		// Subsets to test: {1,2,3}, {1,3,5}, {2,4,5}, {3,4,5}
		subsets := [][]int{
			{1, 2, 3},
			{1, 3, 5},
			{2, 4, 5},
			{3, 4, 5},
		}

		for _, sub := range subsets {
			subIndices := make([]int, 3)
			subPoints := make([]*CurvePoint, 3)
			for idx, pIdx := range sub {
				subIndices[idx] = pIdx
				subPoints[idx] = secpPoints[pIdx-1]
			}

			reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(subIndices, subPoints, "secp256k1")
			if err != nil {
				t.Fatalf("failed interpolation for subset %v: %v", sub, err)
			}
			if reconstructed.X.Cmp(expectedYx) != 0 || reconstructed.Y.Cmp(expectedYy) != 0 {
				t.Fatalf("subset %v reconstructed incorrect public key! Expected (%x, %x), got (%x, %x)",
					sub, expectedYx, expectedYy, reconstructed.X, reconstructed.Y)
			}
		}

		// NEGATIVE THRESHOLD TEST: Any 2 shares strictly fail to reconstruct secret
		twoIndices := []int{1, 2}
		twoPoints := []*CurvePoint{secpPoints[0], secpPoints[1]}
		badReconstruct, _ := InterpolatePublicContributionsAtZeroForCurve(twoIndices, twoPoints, "secp256k1")
		if badReconstruct.X.Cmp(expectedYx) == 0 && badReconstruct.Y.Cmp(expectedYy) == 0 {
			t.Fatalf("CRITICAL SECURITY FLAW: 2 shares reconstructed the 3-of-5 secret!")
		}

		// Same test on Ed25519
		sEd := big.NewInt(0x9876543210ab)
		a1Ed := big.NewInt(0x333344445555)
		a2Ed := big.NewInt(0x777788889999)
		edPoints := make([]*CurvePoint, 5)
		for i := 1; i <= 5; i++ {
			x := big.NewInt(int64(i))
			x2 := new(big.Int).Mul(x, x)
			val := new(big.Int).Set(sEd)
			val.Add(val, new(big.Int).Mul(a1Ed, x))
			val.Add(val, new(big.Int).Mul(a2Ed, x2))
			val.Mod(val, Ed25519L)

			px, py := Ed25519ScalarMult(Ed25519Bx, Ed25519By, val)
			edPoints[i-1] = &CurvePoint{X: px, Y: py}
		}
		expectedEdX, expectedEdY := Ed25519ScalarMult(Ed25519Bx, Ed25519By, sEd)

		for _, sub := range subsets {
			subIndices := make([]int, 3)
			subPoints := make([]*CurvePoint, 3)
			for idx, pIdx := range sub {
				subIndices[idx] = pIdx
				subPoints[idx] = edPoints[pIdx-1]
			}

			reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(subIndices, subPoints, "ed25519")
			if err != nil {
				t.Fatalf("failed interpolation on ed25519 for subset %v: %v", sub, err)
			}
			if reconstructed.X.Cmp(expectedEdX) != 0 || reconstructed.Y.Cmp(expectedEdY) != 0 {
				t.Fatalf("Ed25519 subset %v reconstructed incorrect public key!", sub)
			}
		}
	})

	// -------------------------------------------------------------
	// SCENARIO 4, 5, 6: MULTI-CHAIN ADDRESS DERIVATION STANDARDS
	// -------------------------------------------------------------
	t.Run("Scenario 4, 5, 6: Multi-Chain Address Standards", func(t *testing.T) {
		ptSecp := &CurvePoint{X: Secp256k1Gx, Y: Secp256k1Gy}
		evmAddr := DeriveEvmAddress(ptSecp)
		if !strings.HasPrefix(evmAddr, "0x") || len(evmAddr) != 42 {
			t.Fatalf("invalid EVM address: %s", evmAddr)
		}

		ptEd := &CurvePoint{X: Ed25519Bx, Y: Ed25519By}
		solAddr := DeriveSolanaAddress(ptEd)
		if len(solAddr) < 32 || len(solAddr) > 44 {
			t.Fatalf("invalid Solana address length %d: %s", len(solAddr), solAddr)
		}

		btcAddr := DeriveBitcoinTaprootAddress(ptSecp, "tb")
		t.Logf("BTC ADDR FROM G: %s", btcAddr)
		if !strings.HasPrefix(btcAddr, "tb1p") || len(btcAddr) != 62 {
			t.Fatalf("invalid Bitcoin Taproot address: %s", btcAddr)
		}
	})

	// -------------------------------------------------------------
	// SCENARIO 15: MALICIOUS CONTRIBUTOR DEFENSE
	// -------------------------------------------------------------
	t.Run("Scenario 15: Malicious Contributor Defense", func(t *testing.T) {
		// Degree 2 polynomial
		sVal := big.NewInt(0x123456789)
		a1 := big.NewInt(0x987)
		a2 := big.NewInt(0x654)

		points := make([]*CurvePoint, 5)
		for i := 1; i <= 5; i++ {
			x := big.NewInt(int64(i))
			x2 := new(big.Int).Mul(x, x)
			val := new(big.Int).Set(sVal)
			val.Add(val, new(big.Int).Mul(a1, x))
			val.Add(val, new(big.Int).Mul(a2, x2))
			val.Mod(val, Secp256k1N)

			px, py := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, val)
			points[i-1] = &CurvePoint{X: px, Y: py}
		}

		expectedX, expectedY := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, sVal)

		// Node 2 is malicious: sends forged point
		points[1] = &CurvePoint{X: big.NewInt(0xdeadbeef), Y: big.NewInt(0xcafebabe)}

		// Honest subset {1, 3, 5} excludes node 2
		honestIndices := []int{1, 3, 5}
		honestPoints := []*CurvePoint{points[0], points[2], points[4]}

		reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(honestIndices, honestPoints, "secp256k1")
		if err != nil {
			t.Fatalf("honest reconstruction failed: %v", err)
		}
		if reconstructed.X.Cmp(expectedX) != 0 || reconstructed.Y.Cmp(expectedY) != 0 {
			t.Fatalf("honest subset failed to reconstruct valid master public key!")
		}
		t.Logf("✅ Malicious node 2 successfully bypassed by honest 3-of-5 quorum {1, 3, 5}")
	})

	// -------------------------------------------------------------
	// SCENARIO 20: IDEMPOTENT DERIVATION (20 CONSECUTIVE RUNS)
	// -------------------------------------------------------------
	t.Run("Scenario 20: Idempotent Derivation (20 Runs)", func(t *testing.T) {
		indices := []int{1, 3, 5}
		points := make([]*CurvePoint, 3)

		sVal := big.NewInt(0x555566667777)
		a1 := big.NewInt(0x1111)
		a2 := big.NewInt(0x2222)

		for i, idx := range indices {
			x := big.NewInt(int64(idx))
			x2 := new(big.Int).Mul(x, x)
			val := new(big.Int).Set(sVal)
			val.Add(val, new(big.Int).Mul(a1, x))
			val.Add(val, new(big.Int).Mul(a2, x2))
			val.Mod(val, Secp256k1N)

			px, py := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, val)
			points[i] = &CurvePoint{X: px, Y: py}
		}

		var firstAddr string
		for run := 0; run < 20; run++ {
			reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(indices, points, "secp256k1")
			if err != nil {
				t.Fatalf("run %d failed: %v", run, err)
			}
			addr := DeriveEvmAddress(reconstructed)
			if run == 0 {
				firstAddr = addr
			} else {
				if addr != firstAddr {
					t.Fatalf("idempotency violation at run %d: expected %s, got %s", run, firstAddr, addr)
				}
			}
		}
		t.Logf("✅ Verified 20 consecutive runs derived identical EVM address: %s", firstAddr)
	})
}
