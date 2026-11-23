package cryptography

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// RandScalar generates a cryptographically secure random scalar in [1, OrderQ-1] (P-256).
func RandScalar() (*FieldElement, error) {
	return RandScalarForCurve("nist-p256")
}

// RandScalarWithOrder generates a cryptographically secure random scalar in [1, order-1].
func RandScalarWithOrder(order *big.Int) (*FieldElement, error) {
	if order == nil {
		order = OrderQ
	}
	b := make([]byte, 32)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to read cryptographically secure randomness: %w", err)
		}
		val := new(big.Int).SetBytes(b)
		if val.Sign() > 0 && val.Cmp(order) < 0 {
			return &FieldElement{val: val, order: order}, nil
		}
	}
}

// RandScalarForCurve generates a cryptographically secure random scalar in [1, q-1] for the designated curve.
func RandScalarForCurve(curve string) (*FieldElement, error) {
	return RandScalarWithOrder(GetCurveOrder(curve))
}

// DeterministicScalar generates a deterministic scalar in [1, OrderQ-1] from a seed and index.
func DeterministicScalar(seed string, index int) *FieldElement {
	return DeterministicScalarForCurve(seed, index, "nist-p256")
}

// DeterministicScalarForCurve generates a deterministic scalar in [1, q-1] for the designated curve.
// STRICTLY FOR UNIT TESTING AND DETERMINISTIC TEST VECTORS.
func DeterministicScalarForCurve(seed string, index int, curve string) *FieldElement {
	order := GetCurveOrder(curve)
	h := sha256.New()
	h.Write([]byte(seed))
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(index))
	h.Write(idxBuf[:])

	counter := uint32(0)
	for {
		hLoop := sha256.New()
		hLoop.Write(h.Sum(nil))
		var cBuf [4]byte
		binary.BigEndian.PutUint32(cBuf[:], counter)
		hLoop.Write(cBuf[:])
		b := hLoop.Sum(nil)

		val := new(big.Int).SetBytes(b)
		if val.Sign() > 0 && val.Cmp(order) < 0 {
			return &FieldElement{val: val, order: order}
		}
		counter++
	}
}
