package cryptography

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// Curve identifies the group and its corresponding scalar field.
type Curve string

const (
	CurveP256      Curve = "nist-p256"
	CurveSecp256k1 Curve = "secp256k1"
	CurveEd25519   Curve = "ed25519"
)

func ParseCurve(name string) (Curve, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "nist-p256", "nist p-256", "p-256":
		return CurveP256, nil
	case "secp256k1":
		return CurveSecp256k1, nil
	case "ed25519":
		return CurveEd25519, nil
	default:
		return "", fmt.Errorf("unsupported curve %q", name)
	}
}

func (c Curve) canonical() Curve {
	if c == "" {
		return CurveP256
	}
	return c
}

func (c Curve) order() *big.Int {
	switch c.canonical() {
	case CurveP256:
		return OrderQ
	case CurveSecp256k1:
		return Secp256k1N
	case CurveEd25519:
		return Ed25519L
	default:
		panic("invalid group")
	}
}

func (c Curve) Scalar(value int64) *FieldElement {
	return &FieldElement{val: new(big.Int).Mod(big.NewInt(value), c.order()), curve: c}
}

func (c Curve) RandomScalar() (*FieldElement, error) {
	for {
		value, err := rand.Int(rand.Reader, c.order())
		if err != nil {
			return nil, fmt.Errorf("failed to sample scalar: %w", err)
		}
		if value.Sign() != 0 {
			return &FieldElement{val: value, curve: c}, nil
		}
	}
}

func (c Curve) BaseMult(f *FieldElement) *CurvePoint {
	switch c.canonical() {
	case CurveP256:
		return GeneratorG.ScalarMult(f)
	case CurveSecp256k1:
		return (&CurvePoint{X: Secp256k1Gx, Y: Secp256k1Gy, curve: c}).ScalarMult(f)
	case CurveEd25519:
		return (&CurvePoint{X: Ed25519Bx, Y: Ed25519By, curve: c}).ScalarMult(f)
	default:
		panic("invalid group")
	}
}

func (c Curve) Identity() *CurvePoint {
	y := int64(0)
	if c == CurveEd25519 {
		y = 1
	}
	return &CurvePoint{X: big.NewInt(0), Y: big.NewInt(y), curve: c}
}

// ParsePoint accepts the canonical affine representation used in wallet protocols.
func (c Curve) ParsePoint(encoded string) (*CurvePoint, error) {
	if c.canonical() == CurveP256 {
		return ParseCurvePointFromHex(encoded)
	}
	b, err := hex.DecodeString(encoded)
	if err != nil || len(b) != 65 || b[0] != 4 {
		return nil, ErrInvalidPointEncoding
	}
	point := &CurvePoint{X: new(big.Int).SetBytes(b[1:33]), Y: new(big.Int).SetBytes(b[33:]), curve: c}
	if !point.IsOnCurve() {
		return nil, ErrPointNotOnCurve
	}
	if c == CurveEd25519 {
		x, y := ed25519ScalarMultUnreduced(point.X, point.Y, Ed25519L)
		if x.Sign() != 0 || y.Cmp(One) != 0 {
			return nil, ErrPointNotOnCurve
		}
	}
	return point, nil
}

var (
	secpGeneratorH = sync.OnceValue(func() *CurvePoint { return deriveWalletGeneratorH(CurveSecp256k1, Secp256k1P) })
	edGeneratorH   = sync.OnceValue(func() *CurvePoint { return deriveWalletGeneratorH(CurveEd25519, Ed25519P) })
)

func (c Curve) blindGenerator() *CurvePoint {
	switch c.canonical() {
	case CurveP256:
		return GeneratorH
	case CurveSecp256k1:
		return secpGeneratorH()
	case CurveEd25519:
		return edGeneratorH()
	default:
		panic("invalid group")
	}
}

// Derive the second Pedersen generator by sampling a point from a public seed,
// without deriving or learning a scalar relative to the standard generator.
func deriveWalletGeneratorH(curve Curve, modulus *big.Int) *CurvePoint {
	for counter := uint32(0); ; counter++ {
		prefix := []byte("SARAL_PEDERSEN_H_V1:" + string(curve) + ":")
		digest := sha256.Sum256(binary.BigEndian.AppendUint32(prefix, counter))
		x := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), modulus)
		x2 := new(big.Int).Mul(x, x)
		var rhs *big.Int
		if curve == CurveSecp256k1 {
			rhs = new(big.Int).Add(new(big.Int).Mul(x2, x), big.NewInt(7))
		} else {
			den := new(big.Int).Sub(One, new(big.Int).Mul(Ed25519D, x2))
			inverse := new(big.Int).ModInverse(den, modulus)
			if inverse == nil {
				continue
			}
			rhs = new(big.Int).Mul(new(big.Int).Add(One, x2), inverse)
		}
		y := new(big.Int).ModSqrt(rhs.Mod(rhs, modulus), modulus)
		if y == nil {
			continue
		}
		if y.Bit(0) != 0 {
			y.Sub(modulus, y)
		}
		if curve == CurveEd25519 {
			x, y = ed25519ScalarMultUnreduced(x, y, big.NewInt(8))
		}
		point := &CurvePoint{X: x, Y: y, curve: curve}
		if point.IsOnCurve() {
			return point
		}
	}
}
