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
	// OrderQ is the prime group order of NIST P-256.
	// q = 2^256 - 2^224 + 2^192 + 2^96 - 1
	// In hex: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	OrderQ *big.Int

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
	Zero = big.NewInt(0)
	One = big.NewInt(1)
}

// FieldElement represents a scalar in Z_q.
type FieldElement struct {
	val *big.Int
}

// NewFieldElement creates a new FieldElement from an int64, reduced mod q.
func NewFieldElement(v int64) *FieldElement {
	z := big.NewInt(v)
	z.Mod(z, OrderQ)
	if z.Sign() < 0 {
		z.Add(z, OrderQ)
	}
	return &FieldElement{val: z}
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
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidScalarEncoding, len(b))
	}
	val := new(big.Int).SetBytes(b)
	if val.Cmp(OrderQ) >= 0 {
		return nil, fmt.Errorf("%w: scalar %s >= group order q", ErrInvalidScalarEncoding, hex.EncodeToString(b))
	}
	return &FieldElement{val: val}, nil
}

// NewFieldElementFromHex parses a 64-char hex string as a canonical scalar.
func NewFieldElementFromHex(h string) (*FieldElement, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return NewFieldElementFromBytes(b)
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
	return subtle.ConstantTimeCompare(b1, b2) == 1
}

// Add returns (fe + other) mod q.
func (fe *FieldElement) Add(other *FieldElement) *FieldElement {
	res := new(big.Int).Add(fe.val, other.val)
	res.Mod(res, OrderQ)
	return &FieldElement{val: res}
}

// Sub returns (fe - other) mod q.
func (fe *FieldElement) Sub(other *FieldElement) *FieldElement {
	res := new(big.Int).Sub(fe.val, other.val)
	res.Mod(res, OrderQ)
	if res.Sign() < 0 {
		res.Add(res, OrderQ)
	}
	return &FieldElement{val: res}
}

// Mul returns (fe * other) mod q.
func (fe *FieldElement) Mul(other *FieldElement) *FieldElement {
	res := new(big.Int).Mul(fe.val, other.val)
	res.Mod(res, OrderQ)
	return &FieldElement{val: res}
}

// Neg returns (-fe) mod q.
func (fe *FieldElement) Neg() *FieldElement {
	if fe.IsZero() {
		return &FieldElement{val: big.NewInt(0)}
	}
	res := new(big.Int).Sub(OrderQ, fe.val)
	return &FieldElement{val: res}
}

// Inv returns fe^(-1) mod q. Returns ErrZeroDivision if fe is zero.
func (fe *FieldElement) Inv() (*FieldElement, error) {
	if fe.IsZero() {
		return nil, ErrZeroDivision
	}
	res := new(big.Int).ModInverse(fe.val, OrderQ)
	if res == nil {
		return nil, ErrZeroDivision
	}
	return &FieldElement{val: res}, nil
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
	res := new(big.Int).Exp(fe.val, e, OrderQ)
	return &FieldElement{val: res}
}

// LagrangeCoefficient computes the Lagrange interpolation basis coefficient:
// \lambda_i = \prod_{j \in S, j \ne i} \frac{x - x_j}{x_i - x_j} \pmod q
// evaluated at xTarget (typically xTarget = 0 to recover secret).
func LagrangeCoefficient(xTarget *FieldElement, xi *FieldElement, allX []*FieldElement) (*FieldElement, error) {
	num := NewFieldElement(1)
	den := NewFieldElement(1)

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

