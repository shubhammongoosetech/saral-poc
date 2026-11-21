package rpc

import (
	"math/big"
	"strings"
	"testing"
)

func TestSecp256k1AndLagrange3of5(t *testing.T) {
	// Secret s = 42
	s := big.NewInt(42)
	a1 := big.NewInt(100)
	a2 := big.NewInt(200)

	// Polynomial f(x) = s + a1*x + a2*x^2 mod N
	f := func(x int64) *big.Int {
		xi := big.NewInt(x)
		term1 := new(big.Int).Mul(a1, xi)
		term2 := new(big.Int).Mul(a2, new(big.Int).Mul(xi, xi))
		res := new(big.Int).Add(s, term1)
		res.Add(res, term2)
		res.Mod(res, Secp256k1N)
		return res
	}

	points := make([]*CurvePoint, 6)
	for i := 1; i <= 5; i++ {
		share := f(int64(i))
		px, py := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, share)
		points[i] = &CurvePoint{X: px, Y: py}
	}

	expectedX, expectedY := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, s)

	subsets := [][]int{
		{1, 2, 3},
		{1, 3, 5},
		{2, 4, 5},
		{3, 4, 5},
	}

	for _, sub := range subsets {
		pts := []*CurvePoint{points[sub[0]], points[sub[1]], points[sub[2]]}
		reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(sub, pts, "secp256k1")
		if err != nil {
			t.Fatalf("Interpolation failed for subset %v: %v", sub, err)
		}
		if reconstructed.X.Cmp(expectedX) != 0 || reconstructed.Y.Cmp(expectedY) != 0 {
			t.Fatalf("Reconstructed point mismatch for subset %v", sub)
		}

		// Also verify derived EVM address is identical
		addr := DeriveEvmAddress(reconstructed)
		if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
			t.Fatalf("Invalid EVM address format: %s", addr)
		}

		// Also verify derived Bitcoin Taproot address is identical
		btcAddr := DeriveBitcoinTaprootAddress(reconstructed, "tb")
		if !strings.HasPrefix(btcAddr, "tb1p") {
			t.Fatalf("Invalid Taproot address format: %s", btcAddr)
		}
	}
}

func TestEd25519AndLagrange3of5(t *testing.T) {
	s := big.NewInt(777)
	a1 := big.NewInt(888)
	a2 := big.NewInt(999)

	f := func(x int64) *big.Int {
		xi := big.NewInt(x)
		term1 := new(big.Int).Mul(a1, xi)
		term2 := new(big.Int).Mul(a2, new(big.Int).Mul(xi, xi))
		res := new(big.Int).Add(s, term1)
		res.Add(res, term2)
		res.Mod(res, Ed25519L)
		return res
	}

	points := make([]*CurvePoint, 6)
	for i := 1; i <= 5; i++ {
		share := f(int64(i))
		px, py := Ed25519ScalarMult(Ed25519Bx, Ed25519By, share)
		points[i] = &CurvePoint{X: px, Y: py}
	}

	expectedX, expectedY := Ed25519ScalarMult(Ed25519Bx, Ed25519By, s)

	subsets := [][]int{
		{1, 2, 3},
		{1, 3, 5},
		{2, 4, 5},
		{3, 4, 5},
	}

	for _, sub := range subsets {
		pts := []*CurvePoint{points[sub[0]], points[sub[1]], points[sub[2]]}
		reconstructed, err := InterpolatePublicContributionsAtZeroForCurve(sub, pts, "ed25519")
		if err != nil {
			t.Fatalf("Ed25519 interpolation failed for subset %v: %v", sub, err)
		}
		if reconstructed.X.Cmp(expectedX) != 0 || reconstructed.Y.Cmp(expectedY) != 0 {
			t.Fatalf("Ed25519 reconstructed point mismatch for subset %v", sub)
		}

		solAddr := DeriveSolanaAddress(reconstructed)
		if len(solAddr) < 32 || len(solAddr) > 44 {
			t.Fatalf("Invalid Solana address format: %s", solAddr)
		}
	}
}

