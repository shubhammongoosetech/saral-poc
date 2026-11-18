package cryptography_test

import (
	"fmt"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestChaumPedersenDLEQProof(t *testing.T) {
	sk, err := cryptography.RandScalar()
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}

	G := cryptography.GeneratorG
	PK := G.ScalarMult(sk)

	H, err := cryptography.HashToCurve("test-tag-dleq")
	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}
	Sigma := H.ScalarMult(sk)

	// Generate valid proof
	proof, err := cryptography.GenerateDLEQProof(sk, G, PK, H, Sigma)
	if err != nil {
		t.Fatalf("GenerateDLEQProof failed: %v", err)
	}

	// Verify valid proof
	if !cryptography.VerifyDLEQProof(proof, G, PK, H, Sigma) {
		t.Fatalf("valid DLEQ proof failed verification")
	}

	// Adversarial test 1: Corrupted response scalar
	corruptedProof := &cryptography.DLEQProof{
		Challenge: proof.Challenge,
		Response:  proof.Response.Add(cryptography.NewFieldElement(1)),
	}
	if cryptography.VerifyDLEQProof(corruptedProof, G, PK, H, Sigma) {
		t.Fatalf("corrupted response must fail DLEQ verification")
	}

	// Adversarial test 2: Wrong public key
	wrongSK, _ := cryptography.RandScalar()
	wrongPK := G.ScalarMult(wrongSK)
	if cryptography.VerifyDLEQProof(proof, G, wrongPK, H, Sigma) {
		t.Fatalf("proof verified with wrong public key")
	}

	// Adversarial test 3: Wrong Sigma
	wrongSigma := H.ScalarMult(wrongSK)
	if cryptography.VerifyDLEQProof(proof, G, PK, H, wrongSigma) {
		t.Fatalf("proof verified with wrong Sigma point")
	}
}

func TestThresholdCommonCoinReconstruction(t *testing.T) {
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	n := 5
	tVal := 1 // requires t + 1 = 2 shares

	keyShares, _, err := cryptography.SetupThresholdCoinKeys("comm-5", committee, tVal, "coin-seed-test")
	if err != nil {
		t.Fatalf("SetupThresholdCoinKeys failed: %v", err)
	}
	if len(keyShares) != n {
		t.Fatalf("expected %d key shares, got %d", n, len(keyShares))
	}

	sessionTag := "proactive-refresh-epoch-2"
	round := 1

	// All 5 nodes generate coin shares for round 1
	coinShares := make(map[string]*cryptography.CoinShare)
	for _, id := range committee {
		cs, err := keyShares[id].GenerateShare(round, sessionTag)
		if err != nil {
			t.Fatalf("GenerateShare failed for %s: %v", id, err)
		}
		// Verify individual coin share against public key
		if !cryptography.VerifyCoinShare(cs, keyShares[id].PublicKeyShare, sessionTag) {
			t.Fatalf("VerifyCoinShare failed for %s", id)
		}
		coinShares[id] = cs
	}

	// Subset A: {n1, n2} (2 shares)
	subsetA := []*cryptography.CoinShare{coinShares["n1"], coinShares["n2"]}
	coinBitA, err := cryptography.CombineCoinShares(subsetA, tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for subset A: %v", err)
	}

	// Subset B: {n3, n5} (2 completely different shares)
	subsetB := []*cryptography.CoinShare{coinShares["n3"], coinShares["n5"]}
	coinBitB, err := cryptography.CombineCoinShares(subsetB, tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for subset B: %v", err)
	}

	// Subset C: {n2, n4}
	subsetC := []*cryptography.CoinShare{coinShares["n2"], coinShares["n4"]}
	coinBitC, err := cryptography.CombineCoinShares(subsetC, tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for subset C: %v", err)
	}

	// Invariance check: ALL subsets of size t+1 MUST yield identical coin bit!
	if coinBitA != coinBitB || coinBitA != coinBitC {
		t.Fatalf("COMMON COIN UNPREDICTABILITY/CONSISTENCY FAILED: bitA=%d, bitB=%d, bitC=%d",
			coinBitA, coinBitB, coinBitC)
	}

	// Adversarial test: Only 1 share (<= t) is insufficient
	singleShare := []*cryptography.CoinShare{coinShares["n1"]}
	_, err = cryptography.CombineCoinShares(singleShare, tVal)
	if err == nil {
		t.Fatalf("expected error when combining < t+1 shares")
	}

	// Distinct round test: Round 2 must produce a fresh, independent common coin
	csRound2Node1, _ := keyShares["n1"].GenerateShare(2, sessionTag)
	csRound2Node2, _ := keyShares["n2"].GenerateShare(2, sessionTag)
	subsetRound2 := []*cryptography.CoinShare{csRound2Node1, csRound2Node2}
	_, err = cryptography.CombineCoinShares(subsetRound2, tVal)
	if err != nil {
		t.Fatalf("failed combining round 2 shares: %v", err)
	}
}

func TestThresholdCommonCoin15Nodes(t *testing.T) {
	committee := make([]string, 15)
	for i := 0; i < 15; i++ {
		committee[i] = fmt.Sprintf("node-%02d", i+1)
	}
	tVal := 4 // requires t + 1 = 5 shares

	keyShares, _, err := cryptography.SetupThresholdCoinKeys("comm-15", committee, tVal, "seed-15-nodes")
	if err != nil {
		t.Fatalf("SetupThresholdCoinKeys failed: %v", err)
	}

	sessionTag := "refresh-session-15"
	round := 3

	// Generate shares for all 15 nodes
	allShares := make([]*cryptography.CoinShare, 15)
	for i, id := range committee {
		cs, err := keyShares[id].GenerateShare(round, sessionTag)
		if err != nil {
			t.Fatalf("failed generating share for %s: %v", id, err)
		}
		if !cryptography.VerifyCoinShare(cs, keyShares[id].PublicKeyShare, sessionTag) {
			t.Fatalf("coin share verification failed for %s", id)
		}
		allShares[i] = cs
	}

	// Take first 5 shares: {node-01 .. node-05}
	bit1, err := cryptography.CombineCoinShares(allShares[:5], tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for first 5: %v", err)
	}

	// Take last 5 shares: {node-11 .. node-15} (completely disjoint!)
	bit2, err := cryptography.CombineCoinShares(allShares[10:], tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for last 5: %v", err)
	}

	// Take middle 5 shares: {node-06 .. node-10}
	bit3, err := cryptography.CombineCoinShares(allShares[5:10], tVal)
	if err != nil {
		t.Fatalf("CombineCoinShares failed for middle 5: %v", err)
	}

	if bit1 != bit2 || bit1 != bit3 {
		t.Fatalf("15-node common coin mismatch between disjoint subsets: bit1=%d, bit2=%d, bit3=%d",
			bit1, bit2, bit3)
	}
}
