package cryptography

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Secp256k1 Curve Constants
var (
	Secp256k1P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	Secp256k1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	Secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Secp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	// Ed25519 Constants
	Ed25519P, _  = new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16) // 2^255 - 19
	Ed25519L, _  = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16) // Order L
	Ed25519D, _  = new(big.Int).SetString("52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3", 16) // d = -121665/121666 mod P
	Ed25519Bx, _ = new(big.Int).SetString("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A", 16)
	Ed25519By, _ = new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16) // 4/5 mod P
)

// Secp256k1Add computes P1 + P2 on y^2 = x^3 + 7 mod P
func Secp256k1Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			return big.NewInt(0), big.NewInt(0)
		}
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1))
		num.Mod(num, Secp256k1P)
		den := new(big.Int).Mul(big.NewInt(2), y1)
		den.Mod(den, Secp256k1P)
		inv := new(big.Int).ModInverse(den, Secp256k1P)
		if inv == nil {
			return big.NewInt(0), big.NewInt(0)
		}
		m := new(big.Int).Mul(num, inv)
		m.Mod(m, Secp256k1P)

		x3 := new(big.Int).Mul(m, m)
		x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x1))
		x3.Mod(x3, Secp256k1P)
		if x3.Sign() < 0 {
			x3.Add(x3, Secp256k1P)
		}

		y3 := new(big.Int).Sub(x1, x3)
		y3.Mul(y3, m)
		y3.Sub(y3, y1)
		y3.Mod(y3, Secp256k1P)
		if y3.Sign() < 0 {
			y3.Add(y3, Secp256k1P)
		}
		return x3, y3
	}

	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, Secp256k1P)
	if num.Sign() < 0 {
		num.Add(num, Secp256k1P)
	}
	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, Secp256k1P)
	if den.Sign() < 0 {
		den.Add(den, Secp256k1P)
	}
	inv := new(big.Int).ModInverse(den, Secp256k1P)
	if inv == nil {
		return big.NewInt(0), big.NewInt(0)
	}
	m := new(big.Int).Mul(num, inv)
	m.Mod(m, Secp256k1P)

	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, Secp256k1P)
	if x3.Sign() < 0 {
		x3.Add(x3, Secp256k1P)
	}

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y1)
	y3.Mod(y3, Secp256k1P)
	if y3.Sign() < 0 {
		y3.Add(y3, Secp256k1P)
	}
	return x3, y3
}

// Secp256k1ScalarMult computes k * (x, y) on secp256k1 using double-and-add
func Secp256k1ScalarMult(x, y, k *big.Int) (*big.Int, *big.Int) {
	kMod := new(big.Int).Mod(k, Secp256k1N)
	if kMod.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	rx := big.NewInt(0)
	ry := big.NewInt(0)
	bx := new(big.Int).Set(x)
	by := new(big.Int).Set(y)

	for i := 0; i < kMod.BitLen(); i++ {
		if kMod.Bit(i) == 1 {
			rx, ry = Secp256k1Add(rx, ry, bx, by)
		}
		bx, by = Secp256k1Add(bx, by, bx, by)
	}
	return rx, ry
}

// Secp256k1ScalarBaseMult computes k * G on secp256k1
func Secp256k1ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, k)
}

// Ed25519Add computes P1 + P2 on -x^2 + y^2 = 1 + d*x^2*y^2 mod P
func Ed25519Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	numX := new(big.Int).Add(new(big.Int).Mul(x1, y2), new(big.Int).Mul(y1, x2))
	numX.Mod(numX, Ed25519P)

	x1x2y1y2 := new(big.Int).Mul(new(big.Int).Mul(x1, x2), new(big.Int).Mul(y1, y2))
	x1x2y1y2.Mod(x1x2y1y2, Ed25519P)
	dx1x2y1y2 := new(big.Int).Mul(Ed25519D, x1x2y1y2)
	dx1x2y1y2.Mod(dx1x2y1y2, Ed25519P)

	denX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	denX.Mod(denX, Ed25519P)
	invDenX := new(big.Int).ModInverse(denX, Ed25519P)
	if invDenX == nil {
		return big.NewInt(0), big.NewInt(1)
	}
	x3 := new(big.Int).Mul(numX, invDenX)
	x3.Mod(x3, Ed25519P)

	y1y2 := new(big.Int).Mul(y1, y2)
	y1y2.Mod(y1y2, Ed25519P)
	x1x2 := new(big.Int).Mul(x1, x2)
	x1x2.Mod(x1x2, Ed25519P)
	numY := new(big.Int).Add(y1y2, x1x2)
	numY.Mod(numY, Ed25519P)

	denY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	denY.Mod(denY, Ed25519P)
	if denY.Sign() < 0 {
		denY.Add(denY, Ed25519P)
	}
	invDenY := new(big.Int).ModInverse(denY, Ed25519P)
	if invDenY == nil {
		return big.NewInt(0), big.NewInt(1)
	}
	y3 := new(big.Int).Mul(numY, invDenY)
	y3.Mod(y3, Ed25519P)

	return x3, y3
}

// Ed25519ScalarMult computes k * (x, y) on Ed25519
func Ed25519ScalarMult(x, y, k *big.Int) (*big.Int, *big.Int) {
	kMod := new(big.Int).Mod(k, Ed25519L)
	if kMod.Sign() == 0 {
		return big.NewInt(0), big.NewInt(1) // identity point
	}

	rx := big.NewInt(0)
	ry := big.NewInt(1)
	bx := new(big.Int).Set(x)
	by := new(big.Int).Set(y)

	for i := 0; i < kMod.BitLen(); i++ {
		if kMod.Bit(i) == 1 {
			rx, ry = Ed25519Add(rx, ry, bx, by)
		}
		bx, by = Ed25519Add(bx, by, bx, by)
	}
	return rx, ry
}

// Ed25519ScalarBaseMult computes k * B on Ed25519
func Ed25519ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return Ed25519ScalarMult(Ed25519Bx, Ed25519By, k)
}

// ComputePublicContributionPoint computes Y_i = x_i * G on the designated curve,
// returning 65-byte uncompressed hex 04<X><Y>.
// Explicitly clears intermediate scalar representation before returning.
func ComputePublicContributionPoint(curve string, scalarHex string) (string, error) {
	scalarBytes, err := hex.DecodeString(strings.TrimPrefix(scalarHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid scalar hex: %w", err)
	}
	defer func() {
		// Zero out plaintext buffer
		for i := range scalarBytes {
			scalarBytes[i] = 0
		}
	}()

	scalarInt := new(big.Int).SetBytes(scalarBytes)
	defer func() {
		scalarInt.SetInt64(0)
	}()

	normCurve := strings.ToLower(strings.TrimSpace(curve))
	var px, py *big.Int

	switch {
	case strings.Contains(normCurve, "secp256k1"):
		px, py = Secp256k1ScalarBaseMult(scalarInt)

	case strings.Contains(normCurve, "ed25519"):
		px, py = Ed25519ScalarBaseMult(scalarInt)

	default: // NIST P-256
		p256 := elliptic.P256()
		px, py = p256.ScalarBaseMult(scalarBytes)
	}

	if px == nil || py == nil || (px.Sign() == 0 && py.Sign() == 0) {
		return "", fmt.Errorf("scalar multiplication resulted in point at infinity")
	}

	// Format as 65-byte uncompressed point hex: 04 || 32-byte X || 32-byte Y
	ptBytes := make([]byte, 65)
	ptBytes[0] = 0x04
	xBytes := px.Bytes()
	yBytes := py.Bytes()
	copy(ptBytes[1+32-len(xBytes):33], xBytes)
	copy(ptBytes[33+32-len(yBytes):65], yBytes)

	return hex.EncodeToString(ptBytes), nil
}

