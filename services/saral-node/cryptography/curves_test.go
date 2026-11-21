package cryptography

import (
	"math/big"
	"testing"
)

func TestSecp256k1BaseMult(t *testing.T) {
	// 1 * G = G
	one := big.NewInt(1)
	x, y := Secp256k1ScalarBaseMult(one)
	if x.Cmp(Secp256k1Gx) != 0 || y.Cmp(Secp256k1Gy) != 0 {
		t.Fatalf("1*G did not match secp256k1 generator: got (%x, %x)", x, y)
	}

	// 2 * G
	two := big.NewInt(2)
	x2, y2 := Secp256k1ScalarBaseMult(two)
	dx, dy := Secp256k1Add(Secp256k1Gx, Secp256k1Gy, Secp256k1Gx, Secp256k1Gy)
	if x2.Cmp(dx) != 0 || y2.Cmp(dy) != 0 {
		t.Fatalf("2*G did not match G+G: got (%x, %x), expected (%x, %x)", x2, y2, dx, dy)
	}
}

func TestEd25519BaseMult(t *testing.T) {
	// 1 * B = B
	one := big.NewInt(1)
	x, y := Ed25519ScalarBaseMult(one)
	if x.Cmp(Ed25519Bx) != 0 || y.Cmp(Ed25519By) != 0 {
		t.Fatalf("1*B did not match Ed25519 base: got (%x, %x)", x, y)
	}
}

func TestComputePublicContributionPoint(t *testing.T) {
	curves := []string{"secp256k1", "ed25519", "nist-p256"}
	scalarHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	for _, c := range curves {
		ptHex, err := ComputePublicContributionPoint(c, scalarHex)
		if err != nil {
			t.Fatalf("failed computing contribution point for curve %s: %v", c, err)
		}
		if len(ptHex) != 130 {
			t.Fatalf("expected 130 hex chars (65 bytes), got %d for curve %s", len(ptHex), c)
		}
		if ptHex[:2] != "04" {
			t.Fatalf("expected 04 prefix, got %s for curve %s", ptHex[:2], c)
		}
	}
}

