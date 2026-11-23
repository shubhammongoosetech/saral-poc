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

	// GeneratorH is the secondary Pedersen generator on P-256
	GeneratorH *CurvePoint

	// ErrPointNotOnCurve is returned when a point is not on the curve
	ErrPointNotOnCurve = errors.New("point is not on curve")
	// ErrPointAtInfinity is returned when a point is at infinity
	ErrPointAtInfinity = errors.New("point at infinity is not allowed in commitments")
	// ErrInvalidPointEncoding is returned when point bytes cannot be deserialized
	ErrInvalidPointEncoding = errors.New("invalid elliptic curve point encoding")
)

const (
	// PedersenSeedH is the transparent domain separator for deriving generator H on P-256
	PedersenSeedH = "SARAL_PEDERSEN_H_GENERATOR_V3_TRANSPARENT_NUMS"
)

func init() {
	P256 = elliptic.P256()
	params := P256.Params()
	GeneratorG = &CurvePoint{
		X:     new(big.Int).Set(params.Gx),
		Y:     new(big.Int).Set(params.Gy),
		Curve: "nist-p256",
	}

	var err error
	GeneratorH, err = deriveGeneratorH(PedersenSeedH)
	if err != nil {
		panic(fmt.Sprintf("failed to derive Pedersen generator H: %v", err))
	}
}

// HashToCurve deterministically maps an arbitrary seed string to a valid point on NIST P-256.
func HashToCurve(seed string) (*CurvePoint, error) {
	params := P256.Params()
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

		x3 := new(big.Int).Exp(x, big.NewInt(3), p)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		threeX.Mod(threeX, p)
		rhs := new(big.Int).Sub(x3, threeX)
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)
		if rhs.Sign() < 0 {
			rhs.Add(rhs, p)
		}

		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		y := new(big.Int).Exp(rhs, exp, p)

		y2 := new(big.Int).Exp(y, big.NewInt(2), p)
		if y2.Cmp(rhs) == 0 && y.Sign() != 0 {
			pt := &CurvePoint{X: x, Y: y, Curve: "nist-p256"}
			if pt.IsOnCurve() {
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

func deriveGeneratorH(seed string) (*CurvePoint, error) {
	return HashToCurve(seed)
}

// CurvePoint represents an affine point (X, Y) on an elliptic curve.
type CurvePoint struct {
	X     *big.Int
	Y     *big.Int
	Curve string
}

// NewCurvePoint creates and validates a point on NIST P-256.
func NewCurvePoint(x, y *big.Int) (*CurvePoint, error) {
	return NewCurvePointForCurve(x, y, "nist-p256")
}

// NewCurvePointForCurve creates and validates a point on the designated curve.
func NewCurvePointForCurve(x, y *big.Int, curve string) (*CurvePoint, error) {
	if x == nil || y == nil {
		return nil, ErrPointAtInfinity
	}
	norm := NormalizeCurveName(curve)
	if norm != "ed25519" && x.Sign() == 0 && y.Sign() == 0 {
		return nil, ErrPointAtInfinity
	}
	pt := &CurvePoint{
		X:     new(big.Int).Set(x),
		Y:     new(big.Int).Set(y),
		Curve: norm,
	}
	if !pt.IsOnCurve() {
		return nil, ErrPointNotOnCurve
	}
	return pt, nil
}

// IsOnCurve checks if the point lies on its designated curve.
func (cp *CurvePoint) IsOnCurve() bool {
	if cp == nil || cp.X == nil || cp.Y == nil {
		return false
	}
	norm := NormalizeCurveName(cp.Curve)
	switch norm {
	case "secp256k1":
		if cp.X.Sign() == 0 && cp.Y.Sign() == 0 {
			return true
		}
		y2 := new(big.Int).Mul(cp.Y, cp.Y)
		y2.Mod(y2, Secp256k1P)
		x3 := new(big.Int).Exp(cp.X, big.NewInt(3), Secp256k1P)
		rhs := new(big.Int).Add(x3, big.NewInt(7))
		rhs.Mod(rhs, Secp256k1P)
		return y2.Cmp(rhs) == 0
	case "ed25519":
		if cp.X.Sign() == 0 && cp.Y.Cmp(big.NewInt(1)) == 0 {
			return true
		}
		x2 := new(big.Int).Mul(cp.X, cp.X)
		x2.Mod(x2, Ed25519P)
		y2 := new(big.Int).Mul(cp.Y, cp.Y)
		y2.Mod(y2, Ed25519P)
		lhs := new(big.Int).Sub(y2, x2)
		lhs.Mod(lhs, Ed25519P)
		if lhs.Sign() < 0 {
			lhs.Add(lhs, Ed25519P)
		}
		x2y2 := new(big.Int).Mul(x2, y2)
		x2y2.Mod(x2y2, Ed25519P)
		dx2y2 := new(big.Int).Mul(Ed25519D, x2y2)
		dx2y2.Mod(dx2y2, Ed25519P)
		rhs := new(big.Int).Add(big.NewInt(1), dx2y2)
		rhs.Mod(rhs, Ed25519P)
		return lhs.Cmp(rhs) == 0
	default:
		return P256.IsOnCurve(cp.X, cp.Y)
	}
}

// Equal returns constant-time comparison of two curve points.
func (cp *CurvePoint) Equal(other *CurvePoint) bool {
	if cp == nil || other == nil {
		return cp == other
	}
	b1 := cp.Bytes()
	b2 := other.Bytes()
	return subtle.ConstantTimeCompare(b1, b2) == 1
}

// Add computes cp + other on the point's curve.
func (cp *CurvePoint) Add(other *CurvePoint) *CurvePoint {
	norm := ""
	if cp != nil && cp.Curve != "" {
		norm = cp.Curve
	} else if other != nil && other.Curve != "" {
		norm = other.Curve
	}
	norm = NormalizeCurveName(norm)

	switch norm {
	case "secp256k1":
		x1, y1 := big.NewInt(0), big.NewInt(0)
		if cp != nil && cp.X != nil && cp.Y != nil {
			x1, y1 = cp.X, cp.Y
		}
		x2, y2 := big.NewInt(0), big.NewInt(0)
		if other != nil && other.X != nil && other.Y != nil {
			x2, y2 = other.X, other.Y
		}
		rx, ry := Secp256k1Add(x1, y1, x2, y2)
		return &CurvePoint{X: rx, Y: ry, Curve: "secp256k1"}
	case "ed25519":
		x1, y1 := big.NewInt(0), big.NewInt(1)
		if cp != nil && cp.X != nil && cp.Y != nil {
			x1, y1 = cp.X, cp.Y
		}
		x2, y2 := big.NewInt(0), big.NewInt(1)
		if other != nil && other.X != nil && other.Y != nil {
			x2, y2 = other.X, other.Y
		}
		rx, ry := Ed25519Add(x1, y1, x2, y2)
		return &CurvePoint{X: rx, Y: ry, Curve: "ed25519"}
	default:
		if cp == nil || (cp.X.Sign() == 0 && cp.Y.Sign() == 0) {
			return other
		}
		if other == nil || (other.X.Sign() == 0 && other.Y.Sign() == 0) {
			return cp
		}
		rx, ry := P256.Add(cp.X, cp.Y, other.X, other.Y)
		return &CurvePoint{X: rx, Y: ry, Curve: "nist-p256"}
	}
}

// ScalarMult computes scalar * cp on the point's curve.
func (cp *CurvePoint) ScalarMult(scalar *FieldElement) *CurvePoint {
	norm := ""
	if cp != nil && cp.Curve != "" {
		norm = cp.Curve
	}
	norm = NormalizeCurveName(norm)

	if cp == nil || scalar == nil || scalar.IsZero() {
		return ZeroPointForCurve(norm)
	}

	switch norm {
	case "secp256k1":
		rx, ry := Secp256k1ScalarMult(cp.X, cp.Y, scalar.val)
		return &CurvePoint{X: rx, Y: ry, Curve: "secp256k1"}
	case "ed25519":
		rx, ry := Ed25519ScalarMult(cp.X, cp.Y, scalar.val)
		return &CurvePoint{X: rx, Y: ry, Curve: "ed25519"}
	default:
		rx, ry := P256.ScalarMult(cp.X, cp.Y, scalar.Bytes())
		return &CurvePoint{X: rx, Y: ry, Curve: "nist-p256"}
	}
}

// Bytes returns the uncompressed 65-byte representation: 0x04 || X (32 bytes) || Y (32 bytes).
func (cp *CurvePoint) Bytes() []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	if cp == nil || cp.X == nil || cp.Y == nil {
		return out
	}
	xb := cp.X.Bytes()
	yb := cp.Y.Bytes()
	copy(out[1+32-len(xb):33], xb)
	copy(out[33+32-len(yb):65], yb)
	return out
}

// Hex returns the 130-char hex string of the uncompressed point.
func (cp *CurvePoint) Hex() string {
	return hex.EncodeToString(cp.Bytes())
}

// ParseCurvePointFromBytes parses a point from bytes (65-byte uncompressed or 33-byte compressed).
func ParseCurvePointFromBytes(b []byte) (*CurvePoint, error) {
	return ParseCurvePointFromBytesForCurve(b, "nist-p256")
}

// ParseCurvePointFromBytesForCurve parses a point on a designated curve.
func ParseCurvePointFromBytesForCurve(b []byte, curve string) (*CurvePoint, error) {
	norm := NormalizeCurveName(curve)
	if len(b) == 65 {
		if b[0] != 0x04 {
			return nil, fmt.Errorf("%w: invalid prefix %02x for uncompressed point", ErrInvalidPointEncoding, b[0])
		}
		x := new(big.Int).SetBytes(b[1:33])
		y := new(big.Int).SetBytes(b[33:65])
		pt := &CurvePoint{X: x, Y: y, Curve: norm}
		if !pt.IsOnCurve() {
			return nil, fmt.Errorf("%w: point not on curve", ErrPointNotOnCurve)
		}
		return pt, nil
	} else if len(b) == 33 {
		if norm == "nist-p256" {
			x, y := elliptic.UnmarshalCompressed(P256, b)
			if x == nil || y == nil {
				return nil, fmt.Errorf("%w: compressed unmarshal failed", ErrPointNotOnCurve)
			}
			return &CurvePoint{X: x, Y: y, Curve: "nist-p256"}, nil
		}
		// Generic 33-byte uncompressed fallback
		x := new(big.Int).SetBytes(b[1:33])
		return &CurvePoint{X: x, Y: big.NewInt(0), Curve: norm}, nil
	}
	return nil, fmt.Errorf("%w: expected 65 or 33 bytes, got %d", ErrInvalidPointEncoding, len(b))
}

// ParseCurvePointFromHex parses a hex string into a CurvePoint.
func ParseCurvePointFromHex(h string) (*CurvePoint, error) {
	return ParseCurvePointFromHexForCurve(h, "nist-p256")
}

// ParseCurvePointFromHexForCurve parses a hex string into a CurvePoint on a designated curve.
func ParseCurvePointFromHexForCurve(h string, curve string) (*CurvePoint, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return ParseCurvePointFromBytesForCurve(b, curve)
}

// DetectCurveFromOrder detects curve identifier from scalar subgroup order
func DetectCurveFromOrder(order *big.Int) string {
	if order != nil {
		if order.Cmp(Secp256k1N) == 0 {
			return "secp256k1"
		}
		if order.Cmp(Ed25519L) == 0 {
			return "ed25519"
		}
		if order.Cmp(OrderQ) == 0 {
			return "nist-p256"
		}
	}
	return "nist-p256"
}

// PedersenCommitment computes C = v*G + r*H automatically matching scalar curve order.
func PedersenCommitment(value, blinding *FieldElement) *CurvePoint {
	var curve string
	if value != nil && value.order != nil {
		if value.order.Cmp(Secp256k1N) == 0 {
			curve = "secp256k1"
		} else if value.order.Cmp(Ed25519L) == 0 {
			curve = "ed25519"
		}
	}
	return PedersenCommitmentForCurve(curve, value, blinding)
}

// PedersenCommitmentForCurve computes C = v*G + r*H on the designated curve.
func PedersenCommitmentForCurve(curve string, value, blinding *FieldElement) *CurvePoint {
	g := GetGeneratorG(curve)
	h := GetGeneratorH(curve)
	vg := g.ScalarMult(value)
	rh := h.ScalarMult(blinding)
	return vg.Add(rh)
}

// LagrangeInterpolateInExponent computes Y = \sum_{i \in S} \lambda_i(0) * Y_i in the exponent on the designated curve.
func LagrangeInterpolateInExponent(indices []int, points []*CurvePoint, curve string) (*CurvePoint, error) {
	if len(indices) != len(points) || len(indices) == 0 {
		return nil, fmt.Errorf("indices and points count mismatch or empty")
	}
	ord := GetCurveOrder(curve)
	xTarget := NewFieldElementWithOrder(0, ord)

	xs := make([]*FieldElement, len(indices))
	for i, idx := range indices {
		xs[i] = NewFieldElementWithOrder(int64(idx), ord)
	}

	acc := ZeroPointForCurve(curve)
	for i := 0; i < len(indices); i++ {
		lambda, err := LagrangeCoefficient(xTarget, xs[i], xs)
		if err != nil {
			return nil, err
		}
		term := points[i].ScalarMult(lambda)
		acc = acc.Add(term)
	}
	return acc, nil
}
