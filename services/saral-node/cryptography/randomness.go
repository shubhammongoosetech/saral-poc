package cryptography

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// RandScalar generates a cryptographically secure random scalar in [1, q-1]
func RandScalar() (*FieldElement, error) {
	// Rejection sampling modulo OrderQ
	b := make([]byte, 32)
	for {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to read cryptographically secure randomness: %w", err)
		}
		val := new(big.Int).SetBytes(b)
		if val.Sign() > 0 && val.Cmp(OrderQ) < 0 {
			return &FieldElement{val: val}, nil
		}
	}
}

// DeterministicScalar generates a deterministic scalar in [1, q-1] from a seed and index.
// STRICTLY FOR UNIT TESTING AND DETERMINISTIC TEST VECTORS.
func DeterministicScalar(seed string, index int) *FieldElement {
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
		if val.Sign() > 0 && val.Cmp(OrderQ) < 0 {
			return &FieldElement{val: val}
		}
		counter++
	}
}

