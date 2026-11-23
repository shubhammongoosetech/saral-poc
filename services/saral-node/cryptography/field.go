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

// FieldElement represents a scalar in Z_q, bound to a specific curve scalar field order.
type FieldElement struct {
	val   *big.Int
	order *big.Int
}

// Order returns the modulus order of this field element (defaulting to OrderQ for P-256).
func (fe *FieldElement) Order() *big.Int {
	if fe != nil && fe.order != nil {
		return new(big.Int).Set(fe.order)
	}
	return new(big.Int).Set(OrderQ)
}

func (fe *FieldElement) orderVal() *big.Int {
	if fe != nil && fe.order != nil {
		return fe.order
	}
	return OrderQ
}

// Zero explicitly clears the underlying big.Int to prevent memory lingering
func (fe *FieldElement) Zero() {
	if fe != nil && fe.val != nil {
		fe.val.SetInt64(0)
	}
}

// NewFieldElement creates a new FieldElement from an int64, reduced mod OrderQ (P-256).
func NewFieldElement(v int64) *FieldElement {
	return NewFieldElementWithOrder(v, OrderQ)
}

// NewFieldElementWithOrder creates a new FieldElement from an int64 with explicit order.
func NewFieldElementWithOrder(v int64, order *big.Int) *FieldElement {
	if order == nil {
		order = OrderQ
	}
	z := big.NewInt(v)
	z.Mod(z, order)
	if z.Sign() < 0 {
		z.Add(z, order)
	}
	return &FieldElement{val: z, order: order}
}

// NewFieldElementForCurve creates a new FieldElement for a designated curve.
func NewFieldElementForCurve(v int64, curve string) *FieldElement {
	return NewFieldElementWithOrder(v, GetCurveOrder(curve))
}

// NewFieldElementFromBigInt creates a new FieldElement from *big.Int, checking canonical range [0, OrderQ-1].
func NewFieldElementFromBigInt(b *big.Int) (*FieldElement, error) {
	return NewFieldElementFromBigIntWithOrder(b, OrderQ)
}

// NewFieldElementFromBigIntWithOrder creates a new FieldElement from *big.Int with explicit order.
func NewFieldElementFromBigIntWithOrder(b *big.Int, order *big.Int) (*FieldElement, error) {
	if b == nil {
		return nil, errors.New("nil big.Int")
	}
	if order == nil {
		order = OrderQ
	}
	if b.Sign() < 0 || b.Cmp(order) >= 0 {
		return nil, ErrInvalidScalarEncoding
	}
	return &FieldElement{val: new(big.Int).Set(b), order: order}, nil
}

// NewFieldElementFromBytes parses a canonical 32-byte big-endian scalar.
func NewFieldElementFromBytes(b []byte) (*FieldElement, error) {
	return NewFieldElementFromBytesWithOrder(b, OrderQ)
}

// NewFieldElementFromBytesWithOrder parses a canonical 32-byte big-endian scalar with explicit order.
func NewFieldElementFromBytesWithOrder(b []byte, order *big.Int) (*FieldElement, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidScalarEncoding, len(b))
	}
	if order == nil {
		order = OrderQ
	}
	val := new(big.Int).SetBytes(b)
	if val.Cmp(order) >= 0 {
		return nil, fmt.Errorf("%w: scalar %s >= group order q", ErrInvalidScalarEncoding, hex.EncodeToString(b))
	}
	return &FieldElement{val: val, order: order}, nil
}

// NewFieldElementFromHex parses a 64-char hex string as a canonical scalar.
func NewFieldElementFromHex(h string) (*FieldElement, error) {
	return NewFieldElementFromHexWithOrder(h, OrderQ)
}

// NewFieldElementFromHexWithOrder parses a 64-char hex string as a canonical scalar with explicit order.
func NewFieldElementFromHexWithOrder(h string, order *big.Int) (*FieldElement, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return NewFieldElementFromBytesWithOrder(b, order)
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
	ord := fe.orderVal()
	res := new(big.Int).Add(fe.val, other.val)
	res.Mod(res, ord)
	return &FieldElement{val: res, order: ord}
}

// Sub returns (fe - other) mod q.
func (fe *FieldElement) Sub(other *FieldElement) *FieldElement {
	ord := fe.orderVal()
	res := new(big.Int).Sub(fe.val, other.val)
	res.Mod(res, ord)
	if res.Sign() < 0 {
		res.Add(res, ord)
	}
	return &FieldElement{val: res, order: ord}
}

// Mul returns (fe * other) mod q.
func (fe *FieldElement) Mul(other *FieldElement) *FieldElement {
	ord := fe.orderVal()
	res := new(big.Int).Mul(fe.val, other.val)
	res.Mod(res, ord)
	return &FieldElement{val: res, order: ord}
}

// Neg returns (-fe) mod q.
func (fe *FieldElement) Neg() *FieldElement {
	ord := fe.orderVal()
	if fe.IsZero() {
		return &FieldElement{val: big.NewInt(0), order: ord}
	}
	res := new(big.Int).Sub(ord, fe.val)
	return &FieldElement{val: res, order: ord}
}

// Inv returns fe^(-1) mod q. Returns ErrZeroDivision if fe is zero.
func (fe *FieldElement) Inv() (*FieldElement, error) {
	if fe.IsZero() {
		return nil, ErrZeroDivision
	}
	ord := fe.orderVal()
	res := new(big.Int).ModInverse(fe.val, ord)
	if res == nil {
		return nil, ErrZeroDivision
	}
	return &FieldElement{val: res, order: ord}, nil
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
	ord := fe.orderVal()
	res := new(big.Int).Exp(fe.val, e, ord)
	return &FieldElement{val: res, order: ord}
}

// LagrangeCoefficient computes the Lagrange interpolation basis coefficient:
// \lambda_i = \prod_{j \in S, j \ne i} \frac{x - x_j}{x_i - x_j} \pmod q
// evaluated at xTarget (typically xTarget = 0 to recover secret).
func LagrangeCoefficient(xTarget *FieldElement, xi *FieldElement, allX []*FieldElement) (*FieldElement, error) {
	ord := xi.orderVal()
	num := NewFieldElementWithOrder(1, ord)
	den := NewFieldElementWithOrder(1, ord)

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
