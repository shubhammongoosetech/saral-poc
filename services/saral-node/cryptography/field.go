package cryptography

import (
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var (
	// OrderQ is the prime subgroup order N of NIST P-256 (secp256r1).
	// All scalar arithmetic, polynomial coefficients, secret shares, and blinding factors
	// are elements of Z_N.
	// In hex: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	OrderQ *big.Int

	// FieldP is the base field prime P of NIST P-256 (P = 2^256 - 2^224 + 2^192 + 2^96 - 1).
	// In hex: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
	// Point coordinates (X, Y) lie in F_P, while scalar multipliers lie in Z_N (OrderQ).
	FieldP *big.Int

	// Zero and One field constants
	Zero *big.Int
	One  *big.Int

	// ErrInvalidScalarEncoding is returned when a scalar is not canonical (>= q or wrong length)
	ErrInvalidScalarEncoding = errors.New("invalid scalar encoding: must be canonical 32-byte big-endian < q")
	// ErrZeroDivision is returned on division by zero modulo q
	ErrZeroDivision = errors.New("division by zero in finite field")
)

func init() {
	curve := elliptic.P256()
	OrderQ = new(big.Int).Set(curve.Params().N)
	FieldP = new(big.Int).Set(curve.Params().P)
	Zero = big.NewInt(0)
	One = big.NewInt(1)
}

// FieldElement represents a scalar in Z_q.
type FieldElement struct {
	val   *big.Int
	curve Curve
}

// Zero explicitly clears the underlying big.Int to prevent memory lingering
func (fe *FieldElement) Zero() {
	if fe != nil && fe.val != nil {
		fe.val.SetInt64(0)
	}
}

// NewFieldElement creates a new FieldElement from an int64, reduced mod q.
func NewFieldElement(v int64) *FieldElement {
	return CurveP256.Scalar(v)
}

// NewFieldElementFromBigInt creates a new FieldElement from *big.Int, checking canonical range [0, q-1].
func NewFieldElementFromBigInt(b *big.Int) (*FieldElement, error) {
	if b == nil {
		return nil, errors.New("nil big.Int")
	}
	if b.Sign() < 0 || b.Cmp(OrderQ) >= 0 {
		return nil, ErrInvalidScalarEncoding
	}
	return &FieldElement{val: new(big.Int).Set(b)}, nil
}

// NewFieldElementFromBytes parses a canonical 32-byte big-endian scalar.
func NewFieldElementFromBytes(b []byte) (*FieldElement, error) {
	return CurveP256.parseScalarBytes(b)
}

func (c Curve) parseScalarBytes(b []byte) (*FieldElement, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidScalarEncoding, len(b))
	}
	val := new(big.Int).SetBytes(b)
	if val.Cmp(c.order()) >= 0 {
		return nil, ErrInvalidScalarEncoding
	}
	return &FieldElement{val: val, curve: c}, nil
}

// NewFieldElementFromHex parses a 64-char hex string as a canonical scalar.
func NewFieldElementFromHex(h string) (*FieldElement, error) {
	return CurveP256.ParseScalar(h)
}

func (c Curve) ParseScalar(h string) (*FieldElement, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	defer clear(b)
	return c.parseScalarBytes(b)
}

func (fe *FieldElement) Curve() Curve {
	return fe.curve.canonical()
}

func (fe *FieldElement) assertSameCurve(other *FieldElement) {
	if fe.Curve() != other.Curve() {
		panic("scalar field mismatch")
	}
}

// Bytes returns the canonical 32-byte big-endian representation.
func (fe *FieldElement) Bytes() []byte {
	out := make([]byte, 32)
	b := fe.val.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// Hex returns the 64-character lowercase hex string.
func (fe *FieldElement) Hex() string {
	return hex.EncodeToString(fe.Bytes())
}

// BigInt returns a copy of the underlying big.Int.
func (fe *FieldElement) BigInt() *big.Int {
	return new(big.Int).Set(fe.val)
}

// IsZero returns true if the field element is 0.
func (fe *FieldElement) IsZero() bool {
	return fe.val.Sign() == 0
}

// Equal returns constant-time equality check between two FieldElements.
func (fe *FieldElement) Equal(other *FieldElement) bool {
	if fe == nil || other == nil {
		return fe == other
	}
	b1 := fe.Bytes()
	b2 := other.Bytes()
	return fe.Curve() == other.Curve() && subtle.ConstantTimeCompare(b1, b2) == 1
}

// Add returns (fe + other) mod q.
func (fe *FieldElement) Add(other *FieldElement) *FieldElement {
	fe.assertSameCurve(other)
	res := new(big.Int).Add(fe.val, other.val)
	res.Mod(res, fe.Curve().order())
	return &FieldElement{val: res, curve: fe.Curve()}
}

// Sub returns (fe - other) mod q.
func (fe *FieldElement) Sub(other *FieldElement) *FieldElement {
	fe.assertSameCurve(other)
	res := new(big.Int).Sub(fe.val, other.val)
	res.Mod(res, fe.Curve().order())
	return &FieldElement{val: res, curve: fe.Curve()}
}

// Mul returns (fe * other) mod q.
func (fe *FieldElement) Mul(other *FieldElement) *FieldElement {
	fe.assertSameCurve(other)
	res := new(big.Int).Mul(fe.val, other.val)
	res.Mod(res, fe.Curve().order())
	return &FieldElement{val: res, curve: fe.Curve()}
}

// Neg returns (-fe) mod q.
func (fe *FieldElement) Neg() *FieldElement {
	if fe.IsZero() {
		return fe.Curve().Scalar(0)
	}
	res := new(big.Int).Sub(fe.Curve().order(), fe.val)
	return &FieldElement{val: res, curve: fe.Curve()}
}

// Inv returns fe^(-1) mod q. Returns ErrZeroDivision if fe is zero.
func (fe *FieldElement) Inv() (*FieldElement, error) {
	if fe.IsZero() {
		return nil, ErrZeroDivision
	}
	res := new(big.Int).ModInverse(fe.val, fe.Curve().order())
	if res == nil {
		return nil, ErrZeroDivision
	}
	return &FieldElement{val: res, curve: fe.Curve()}, nil
}

// Div returns (fe * other^(-1)) mod q.
func (fe *FieldElement) Div(other *FieldElement) (*FieldElement, error) {
	inv, err := other.Inv()
	if err != nil {
		return nil, err
	}
	return fe.Mul(inv), nil
}

// Exp returns fe^e mod q.
func (fe *FieldElement) Exp(e *big.Int) *FieldElement {
	res := new(big.Int).Exp(fe.val, e, fe.Curve().order())
	return &FieldElement{val: res, curve: fe.Curve()}
}

// LagrangeCoefficient computes the Lagrange interpolation basis coefficient:
// \lambda_i = \prod_{j \in S, j \ne i} \frac{x - x_j}{x_i - x_j} \pmod q
// evaluated at xTarget (typically xTarget = 0 to recover secret).
func LagrangeCoefficient(xTarget *FieldElement, xi *FieldElement, allX []*FieldElement) (*FieldElement, error) {
	num := xi.Curve().Scalar(1)
	den := xi.Curve().Scalar(1)

	for _, xj := range allX {
		if xj.Equal(xi) {
			continue
		}
		// num = num * (xTarget - xj)
		diffNum := xTarget.Sub(xj)
		num = num.Mul(diffNum)

		// den = den * (xi - xj)
		diffDen := xi.Sub(xj)
		if diffDen.IsZero() {
			return nil, fmt.Errorf("duplicate participant point in Lagrange interpolation: %s", xi.Hex())
		}
		den = den.Mul(diffDen)
	}

	coeff, err := num.Div(den)
	if err != nil {
		return nil, fmt.Errorf("lagrange inversion failed: %w", err)
	}
	return coeff, nil
}
