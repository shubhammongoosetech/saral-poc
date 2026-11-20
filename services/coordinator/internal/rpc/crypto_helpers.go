package rpc

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// CurvePoint represents an affine point on NIST P-256 (secp256r1).
type CurvePoint struct {
	X *big.Int
	Y *big.Int
}

// ParseCurvePointFromBytes parses uncompressed (65-byte) or compressed (33-byte) NIST P-256 point bytes.
func ParseCurvePointFromBytes(b []byte) (*CurvePoint, error) {
	curve := elliptic.P256()
	if len(b) == 65 {
		if b[0] != 0x04 {
			return nil, fmt.Errorf("invalid prefix 0x%02x for uncompressed point", b[0])
		}
		x, y := elliptic.Unmarshal(curve, b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("unmarshal failed or point not on curve")
		}
		return &CurvePoint{X: x, Y: y}, nil
	} else if len(b) == 33 {
		x, y := elliptic.UnmarshalCompressed(curve, b)
		if x == nil || y == nil {
			return nil, fmt.Errorf("compressed unmarshal failed or point not on curve")
		}
		return &CurvePoint{X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("invalid point length %d (expected 33 or 65 bytes)", len(b))
}

// LagrangeCoefficientAtZero computes the Lagrange coefficient lambda_i(0) = \prod_{j \neq i} (x_j) / (x_j - x_i) mod N.
func LagrangeCoefficientAtZero(iIndex int, allIndices []int, order *big.Int) (*big.Int, error) {
	xi := big.NewInt(int64(iIndex))
	num := big.NewInt(1)
	den := big.NewInt(1)

	for _, jIndex := range allIndices {
		if jIndex == iIndex {
			continue
		}
		xj := big.NewInt(int64(jIndex))

		// num = num * (0 - xj) mod N = num * (-xj) mod N
		negXj := new(big.Int).Neg(xj)
		negXj.Mod(negXj, order)
		num.Mul(num, negXj)
		num.Mod(num, order)

		// den = den * (xi - xj) mod N
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, order)
		if diff.Sign() == 0 {
			return nil, fmt.Errorf("duplicate participant index in Lagrange interpolation: %d", iIndex)
		}
		den.Mul(den, diff)
		den.Mod(den, order)
	}

	// denInv = den^(-1) mod N
	denInv := new(big.Int).ModInverse(den, order)
	if denInv == nil {
		return nil, fmt.Errorf("modular inverse does not exist for denominator in Lagrange interpolation")
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, order)
	return lambda, nil
}

// InterpolatePublicContributionsAtZero computes Y = \sum_{i=1}^k \lambda_i(0) * Y_i on NIST P-256.
func InterpolatePublicContributionsAtZero(indices []int, points []*CurvePoint) (*CurvePoint, error) {
	if len(indices) != len(points) || len(indices) == 0 {
		return nil, fmt.Errorf("indices and points count mismatch or empty")
	}

	curve := elliptic.P256()
	order := curve.Params().N

	accX := big.NewInt(0)
	accY := big.NewInt(0)

	for i, pt := range points {
		lambda, err := LagrangeCoefficientAtZero(indices[i], indices, order)
		if err != nil {
			return nil, err
		}

		// term = lambda_i * Y_i
		tx, ty := curve.ScalarMult(pt.X, pt.Y, lambda.Bytes())
		if accX.Sign() == 0 && accY.Sign() == 0 {
			accX = tx
			accY = ty
		} else {
			accX, accY = curve.Add(accX, accY, tx, ty)
		}
	}

	return &CurvePoint{X: accX, Y: accY}, nil
}

