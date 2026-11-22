package cryptography

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var (
	// P256 is the NIST P-256 elliptic curve
	P256 elliptic.Curve

	// GeneratorG is the standard P-256 base generator
	GeneratorG *CurvePoint

	// GeneratorH is the secondary Pedersen generator, with provably unknown discrete log w.r.t G
	GeneratorH *CurvePoint

	// ErrPointNotOnCurve is returned when a point is not on the curve
	ErrPointNotOnCurve = errors.New("point is not on NIST P-256 curve")
	// ErrPointAtInfinity is returned when a point is at infinity
	ErrPointAtInfinity = errors.New("point at infinity is not allowed in commitments")
	// ErrInvalidPointEncoding is returned when point bytes cannot be deserialized
	ErrInvalidPointEncoding = errors.New("invalid elliptic curve point encoding")
)

const (
	// PedersenSeedH is the transparent domain separator for deriving generator H
	PedersenSeedH = "SARAL_PEDERSEN_H_GENERATOR_V3_TRANSPARENT_NUMS"
)

func init() {
	P256 = elliptic.P256()
	params := P256.Params()
	GeneratorG = &CurvePoint{
		X: new(big.Int).Set(params.Gx),
		Y: new(big.Int).Set(params.Gy),
	}

	var err error
	GeneratorH, err = deriveGeneratorH(PedersenSeedH)
	if err != nil {
		panic(fmt.Sprintf("failed to derive Pedersen generator H: %v", err))
	}
}

// HashToCurve deterministically maps an arbitrary seed string to a valid point on NIST P-256
// with prime subgroup order N using transparent trial-and-increment.
func HashToCurve(seed string) (*CurvePoint, error) {
	params := P256.Params()
	// y^2 = x^3 - 3x + b mod p
	p := params.P
	b := params.B

	counter := uint32(0)
	for counter < 100000 {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write([]byte(fmt.Sprintf(":%d", counter)))
		candBytes := h.Sum(nil)
		x := new(big.Int).SetBytes(candBytes)
		x.Mod(x, p)

		// Compute rhs = x^3 - 3x + b mod p
		x3 := new(big.Int).Exp(x, big.NewInt(3), p)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		threeX.Mod(threeX, p)
		rhs := new(big.Int).Sub(x3, threeX)
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)
		if rhs.Sign() < 0 {
			rhs.Add(rhs, p)
		}

		// Check if rhs is quadratic residue mod p: y = rhs^((p+1)/4) mod p (p = 3 mod 4 for P-256)
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		y := new(big.Int).Exp(rhs, exp, p)

		// Verify y^2 == rhs mod p
		y2 := new(big.Int).Exp(y, big.NewInt(2), p)
		if y2.Cmp(rhs) == 0 && y.Sign() != 0 {
			// Found valid point on curve! Check that order is N (since cofactor is 1, any point != inf has order N)
			pt := &CurvePoint{X: x, Y: y}
			if pt.IsOnCurve() {
				// Multiply by curve order N; must equal point at infinity
				nx, ny := P256.ScalarMult(x, y, params.N.Bytes())
				if nx.Sign() == 0 && ny.Sign() == 0 {
					return pt, nil
				}
			}
		}
		counter++
	}
	return nil, errors.New("could not find valid curve point on NIST P-256")
}

// deriveGeneratorH derives a nothing-up-my-sleeve (NUMS) curve point from a public seed
// using transparent trial-and-increment hash-to-curve on P-256.
func deriveGeneratorH(seed string) (*CurvePoint, error) {
	return HashToCurve(seed)
}

// CurvePoint represents an affine point (X, Y), defaulting to NIST P-256.
type CurvePoint struct {
	X     *big.Int
	Y     *big.Int
	curve Curve
}

// NewCurvePoint creates and validates a point on NIST P-256.
func NewCurvePoint(x, y *big.Int) (*CurvePoint, error) {
	if x == nil || y == nil {
		return nil, ErrPointAtInfinity
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, ErrPointAtInfinity
	}
	if !P256.IsOnCurve(x, y) {
		return nil, ErrPointNotOnCurve
	}
	return &CurvePoint{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
	}, nil
}

func (cp *CurvePoint) Curve() Curve {
	return cp.curve.canonical()
}

func (cp *CurvePoint) isIdentity() bool {
	return cp.X.Sign() == 0 && (cp.Y.Sign() == 0 || (cp.Curve() == CurveEd25519 && cp.Y.Cmp(One) == 0))
}

// IsOnCurve checks whether the point is a finite, nonidentity group member.
func (cp *CurvePoint) IsOnCurve() bool {
	if cp == nil || cp.X == nil || cp.Y == nil || cp.isIdentity() {
		return false
	}
	switch cp.Curve() {
	case CurveP256:
		return P256.IsOnCurve(cp.X, cp.Y)
	case CurveSecp256k1:
		if !coordinatesInField(cp, Secp256k1P) {
			return false
		}
		y2 := new(big.Int).Mul(cp.Y, cp.Y)
		x3 := new(big.Int).Mul(cp.X, cp.X)
		x3.Mul(x3, cp.X).Add(x3, big.NewInt(7))
		return y2.Mod(y2, Secp256k1P).Cmp(x3.Mod(x3, Secp256k1P)) == 0
	case CurveEd25519:
		if !coordinatesInField(cp, Ed25519P) {
			return false
		}
		x2 := new(big.Int).Mul(cp.X, cp.X)
		y2 := new(big.Int).Mul(cp.Y, cp.Y)
		left := new(big.Int).Sub(y2, x2)
		right := new(big.Int).Mul(Ed25519D, new(big.Int).Mul(x2, y2))
		right.Add(right, One)
		return left.Mod(left, Ed25519P).Cmp(right.Mod(right, Ed25519P)) == 0
	default:
		return false
	}
}

func coordinatesInField(cp *CurvePoint, max *big.Int) bool {
	return cp.X.Sign() >= 0 && cp.Y.Sign() >= 0 && cp.X.Cmp(max) < 0 && cp.Y.Cmp(max) < 0
}

// Equal returns constant-time comparison of two curve points.
func (cp *CurvePoint) Equal(other *CurvePoint) bool {
	if cp == nil || other == nil {
		return cp == other
	}
	b1 := cp.Bytes()
	b2 := other.Bytes()
	return cp.Curve() == other.Curve() && subtle.ConstantTimeCompare(b1, b2) == 1
}

// Add computes cp + other in their group.
func (cp *CurvePoint) Add(other *CurvePoint) *CurvePoint {
	if cp == nil {
		return other
	}
	if other == nil {
		return cp
	}
	if cp.Curve() != other.Curve() {
		panic("point group mismatch")
	}
	if cp.isIdentity() {
		return other
	}
	if other.isIdentity() {
		return cp
	}
	var rx, ry *big.Int
	switch cp.Curve() {
	case CurveSecp256k1:
		rx, ry = Secp256k1Add(cp.X, cp.Y, other.X, other.Y)
	case CurveEd25519:
		rx, ry = Ed25519Add(cp.X, cp.Y, other.X, other.Y)
	default:
		rx, ry = P256.Add(cp.X, cp.Y, other.X, other.Y)
	}
	return &CurvePoint{X: rx, Y: ry, curve: cp.Curve()}
}

// ScalarMult computes scalar * cp in their group.
func (cp *CurvePoint) ScalarMult(scalar *FieldElement) *CurvePoint {
	if cp.Curve() != scalar.Curve() {
		panic("point and scalar group mismatch")
	}
	if scalar.IsZero() || cp.isIdentity() {
		return cp.Curve().Identity()
	}
	var rx, ry *big.Int
	switch cp.Curve() {
	case CurveSecp256k1:
		rx, ry = Secp256k1ScalarMult(cp.X, cp.Y, scalar.val)
	case CurveEd25519:
		rx, ry = Ed25519ScalarMult(cp.X, cp.Y, scalar.val)
	default:
		rx, ry = P256.ScalarMult(cp.X, cp.Y, scalar.Bytes())
	}
	return &CurvePoint{X: rx, Y: ry, curve: cp.Curve()}
}

// Bytes returns the uncompressed 65-byte representation: 0x04 || X (32 bytes) || Y (32 bytes).
func (cp *CurvePoint) Bytes() []byte {
	if cp == nil || cp.X == nil || cp.Y == nil {
		return make([]byte, 65)
	}
	out := make([]byte, 65)
	out[0] = 4
	cp.X.FillBytes(out[1:33])
	cp.Y.FillBytes(out[33:])
	return out
}

// Hex returns the 130-char hex string of the uncompressed point.
func (cp *CurvePoint) Hex() string {
	return hex.EncodeToString(cp.Bytes())
}

// ParseCurvePointFromBytes parses an uncompressed (65-byte) or compressed (33-byte) point.
func ParseCurvePointFromBytes(b []byte) (*CurvePoint, error) {
	if len(b) == 65 {
		if b[0] != 0x04 {
			return nil, fmt.Errorf("%w: invalid prefix %02x for uncompressed point", ErrInvalidPointEncoding, b[0])
		}
		x, y := elliptic.Unmarshal(P256, b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("%w: unmarshal failed or point not on curve", ErrPointNotOnCurve)
		}
		return NewCurvePoint(x, y)
	} else if len(b) == 33 {
		x, y := elliptic.UnmarshalCompressed(P256, b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("%w: compressed unmarshal failed", ErrPointNotOnCurve)
		}
		return NewCurvePoint(x, y)
	}
	return nil, fmt.Errorf("%w: expected 65 or 33 bytes, got %d", ErrInvalidPointEncoding, len(b))
}

// ParseCurvePointFromHex parses a hex string into a CurvePoint.
func ParseCurvePointFromHex(h string) (*CurvePoint, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return ParseCurvePointFromBytes(b)
}

// PedersenCommitment computes C = v*G + r*H in the scalar field's group.
func PedersenCommitment(value, blinding *FieldElement) *CurvePoint {
	curve := value.Curve()
	vg := curve.BaseMult(value)
	rh := curve.blindGenerator().ScalarMult(blinding)
	return vg.Add(rh)
}
