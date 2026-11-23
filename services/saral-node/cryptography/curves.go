package cryptography

import (
	"crypto/elliptic"
	"crypto/sha256"
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

	// Curve Generators
	Secp256k1GeneratorG *CurvePoint
	Secp256k1GeneratorH *CurvePoint

	Ed25519GeneratorG *CurvePoint
	Ed25519GeneratorH *CurvePoint
)

const (
	PedersenSeedH_Secp256k1 = "SARAL_SECP256K1_PEDERSEN_H_V1_NUMS"
	PedersenSeedH_Ed25519   = "SARAL_ED25519_PEDERSEN_H_V1_NUMS"
)

func init() {
	Secp256k1GeneratorG = &CurvePoint{X: new(big.Int).Set(Secp256k1Gx), Y: new(big.Int).Set(Secp256k1Gy), Curve: "secp256k1"}
	hx, hy, err := deriveSecp256k1H(PedersenSeedH_Secp256k1)
	if err != nil {
		panic(fmt.Sprintf("failed to derive secp256k1 NUMS generator H: %v", err))
	}
	Secp256k1GeneratorH = &CurvePoint{X: hx, Y: hy, Curve: "secp256k1"}

	Ed25519GeneratorG = &CurvePoint{X: new(big.Int).Set(Ed25519Bx), Y: new(big.Int).Set(Ed25519By), Curve: "ed25519"}
	edHx, edHy, err := deriveEd25519H(PedersenSeedH_Ed25519)
	if err != nil {
		panic(fmt.Sprintf("failed to derive ed25519 NUMS generator H: %v", err))
	}
	Ed25519GeneratorH = &CurvePoint{X: edHx, Y: edHy, Curve: "ed25519"}
}

// NormalizeCurveName maps curve aliases to standard names: "secp256k1", "ed25519", "nist-p256".
func NormalizeCurveName(curve string) string {
	norm := strings.ToLower(strings.TrimSpace(curve))
	switch {
	case strings.Contains(norm, "secp256k1") || norm == "secp" || norm == "k1":
		return "secp256k1"
	case strings.Contains(norm, "ed25519") || norm == "ed" || norm == "solana":
		return "ed25519"
	case strings.Contains(norm, "p256") || strings.Contains(norm, "p-256") || strings.Contains(norm, "nist"):
		return "nist-p256"
	default:
		if norm == "" {
			return "nist-p256"
		}
		return norm
	}
}

// GetCurveOrder returns the scalar subgroup order for the designated curve.
func GetCurveOrder(curve string) *big.Int {
	switch NormalizeCurveName(curve) {
	case "secp256k1":
		return new(big.Int).Set(Secp256k1N)
	case "ed25519":
		return new(big.Int).Set(Ed25519L)
	default:
		if OrderQ != nil {
			return new(big.Int).Set(OrderQ)
		}
		return new(big.Int).Set(elliptic.P256().Params().N)
	}
}

// GetGeneratorG returns the base generator G for the designated curve.
func GetGeneratorG(curve string) *CurvePoint {
	switch NormalizeCurveName(curve) {
	case "secp256k1":
		return Secp256k1GeneratorG
	case "ed25519":
		return Ed25519GeneratorG
	default:
		return GeneratorG
	}
}

// GetGeneratorH returns the Pedersen NUMS generator H for the designated curve.
func GetGeneratorH(curve string) *CurvePoint {
	switch NormalizeCurveName(curve) {
	case "secp256k1":
		return Secp256k1GeneratorH
	case "ed25519":
		return Ed25519GeneratorH
	default:
		return GeneratorH
	}
}

// ZeroPointForCurve returns the neutral/identity point for the designated curve.
func ZeroPointForCurve(curve string) *CurvePoint {
	norm := NormalizeCurveName(curve)
	switch norm {
	case "secp256k1":
		return &CurvePoint{X: big.NewInt(0), Y: big.NewInt(0), Curve: "secp256k1"}
	case "ed25519":
		return &CurvePoint{X: big.NewInt(0), Y: big.NewInt(1), Curve: "ed25519"}
	default:
		return &CurvePoint{X: big.NewInt(0), Y: big.NewInt(0), Curve: "nist-p256"}
	}
}

// deriveSecp256k1H derives a transparent NUMS point on secp256k1 with unknown discrete log w.r.t G
func deriveSecp256k1H(seed string) (*big.Int, *big.Int, error) {
	exp := new(big.Int).Add(Secp256k1P, big.NewInt(1))
	exp.Rsh(exp, 2) // (P + 1) / 4
	for counter := 0; counter < 100000; counter++ {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write([]byte(fmt.Sprintf(":%d", counter)))
		x := new(big.Int).SetBytes(h.Sum(nil))
		x.Mod(x, Secp256k1P)

		// rhs = x^3 + 7 mod P
		x3 := new(big.Int).Exp(x, big.NewInt(3), Secp256k1P)
		rhs := new(big.Int).Add(x3, big.NewInt(7))
		rhs.Mod(rhs, Secp256k1P)

		y := new(big.Int).Exp(rhs, exp, Secp256k1P)
		y2 := new(big.Int).Exp(y, big.NewInt(2), Secp256k1P)
		if y2.Cmp(rhs) == 0 && y.Sign() != 0 {
			// Verify order is Secp256k1N
			nx, ny := Secp256k1ScalarMult(x, y, Secp256k1N)
			if nx.Sign() == 0 && ny.Sign() == 0 {
				return x, y, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("failed to derive secp256k1 NUMS point")
}

// deriveEd25519H derives a transparent NUMS point in the prime-order subgroup of Ed25519
func deriveEd25519H(seed string) (*big.Int, *big.Int, error) {
	iModP := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(Ed25519P, big.NewInt(1)), 2), Ed25519P)
	sqrtExp := new(big.Int).Rsh(new(big.Int).Add(Ed25519P, big.NewInt(3)), 3) // (P + 3) / 8

	for counter := 0; counter < 100000; counter++ {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write([]byte(fmt.Sprintf(":%d", counter)))
		y := new(big.Int).SetBytes(h.Sum(nil))
		y.Mod(y, Ed25519P)

		// x^2 = (y^2 - 1) / (1 + d y^2) mod P
		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, Ed25519P)
		u := new(big.Int).Sub(y2, big.NewInt(1))
		u.Mod(u, Ed25519P)
		if u.Sign() < 0 {
			u.Add(u, Ed25519P)
		}

		v := new(big.Int).Mul(Ed25519D, y2)
		v.Add(v, big.NewInt(1))
		v.Mod(v, Ed25519P)
		invV := new(big.Int).ModInverse(v, Ed25519P)
		if invV == nil {
			continue
		}
		x2 := new(big.Int).Mul(u, invV)
		x2.Mod(x2, Ed25519P)

		candX := new(big.Int).Exp(x2, sqrtExp, Ed25519P)
		candX2 := new(big.Int).Exp(candX, big.NewInt(2), Ed25519P)
		if candX2.Cmp(x2) != 0 {
			candX.Mul(candX, iModP)
			candX.Mod(candX, Ed25519P)
			candX2 = new(big.Int).Exp(candX, big.NewInt(2), Ed25519P)
		}

		if candX2.Cmp(x2) == 0 && candX.Sign() != 0 {
			// Multiply by cofactor 8 to guarantee point is strictly in prime-order subgroup
			hx, hy := Ed25519ScalarMult(candX, y, big.NewInt(8))
			if hx.Sign() != 0 || hy.Cmp(big.NewInt(1)) != 0 {
				lx, ly := Ed25519ScalarMult(hx, hy, Ed25519L)
				if lx.Sign() == 0 && ly.Cmp(big.NewInt(1)) == 0 {
					return hx, hy, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("failed to derive ed25519 NUMS point")
}

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
		for i := range scalarBytes {
			scalarBytes[i] = 0
		}
	}()

	scalarInt := new(big.Int).SetBytes(scalarBytes)
	defer func() {
		scalarInt.SetInt64(0)
	}()

	normCurve := NormalizeCurveName(curve)
	var px, py *big.Int

	switch normCurve {
	case "secp256k1":
		px, py = Secp256k1ScalarBaseMult(scalarInt)
	case "ed25519":
		px, py = Ed25519ScalarBaseMult(scalarInt)
	case "nist-p256":
		p256 := elliptic.P256()
		px, py = p256.ScalarBaseMult(scalarBytes)
	default:
		return "", fmt.Errorf("unsupported curve: %s", curve)
	}

	if px == nil || py == nil || (px.Sign() == 0 && py.Sign() == 0 && normCurve != "ed25519") {
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
