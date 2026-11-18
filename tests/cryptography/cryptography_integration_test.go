package cryptography_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestCryptographicTestVectors(t *testing.T) {
	// 1. Verify exact NIST P-256 group order
	expectedOrderHex := "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
	if hex.EncodeToString(cryptography.OrderQ.Bytes()) != expectedOrderHex {
		t.Fatalf("unexpected P-256 group order: got %s, want %s",
			hex.EncodeToString(cryptography.OrderQ.Bytes()), expectedOrderHex)
	}

	// 2. Deterministic test vector generation
	seed := "saral-avss-vector-2026"
	s0 := cryptography.DeterministicScalar(seed, 0)
	s1 := cryptography.DeterministicScalar(seed, 1)
	s2 := cryptography.DeterministicScalar(seed, 2)

	if s0.Equal(s1) || s1.Equal(s2) || s0.Equal(s2) {
		t.Fatalf("deterministic scalars collided")
	}

	// 3. Mathematical consistency of commitments under scalar multiplication
	v := cryptography.NewFieldElement(123456789)
	r := cryptography.NewFieldElement(987654321)
	c := cryptography.PedersenCommitment(v, r)

	scalar := cryptography.NewFieldElement(17)
	scaledC := c.ScalarMult(scalar)

	vScaled := v.Mul(scalar)
	rScaled := r.Mul(scalar)
	expectedScaledC := cryptography.PedersenCommitment(vScaled, rScaled)

	if !scaledC.Equal(expectedScaledC) {
		t.Fatalf("scalar multiplication of commitment mismatch")
	}

	// 4. Strict Non-Canonical Rejection: values >= OrderQ must be rejected without silent modulo reduction
	badScalar := new(big.Int).Add(cryptography.OrderQ, big.NewInt(5))
	_, err := cryptography.NewFieldElementFromBigInt(badScalar)
	if err == nil {
		t.Fatalf("expected error on non-canonical scalar >= OrderQ")
	}

	// 5. Point rejection for non-curve coordinates
	badX := big.NewInt(1)
	badY := big.NewInt(2)
	_, err = cryptography.NewCurvePoint(badX, badY)
	if err == nil {
		t.Fatalf("expected error on point not on curve")
	}
}

