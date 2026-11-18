package avss

import (
	"errors"
	"fmt"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrDegreeMismatch      = errors.New("polynomial degree mismatch")
	ErrInsufficientPoints  = errors.New("insufficient points for polynomial interpolation")
	ErrDuplicateEvaluation = errors.New("duplicate evaluation point")
)

// Polynomial represents a univariate polynomial over Z_q: P(x) = \sum_{j=0}^d Coeffs[j] * x^j
type Polynomial struct {
	Coeffs []*cryptography.FieldElement
}

// NewPolynomial creates a polynomial with the given coefficients.
func NewPolynomial(coeffs []*cryptography.FieldElement) *Polynomial {
	c := make([]*cryptography.FieldElement, len(coeffs))
	copy(c, coeffs)
	return &Polynomial{Coeffs: c}
}

// Degree returns the degree of the polynomial.
func (p *Polynomial) Degree() int {
	return len(p.Coeffs) - 1
}

// Evaluate evaluates P(x) at x using Horner's method.
func (p *Polynomial) Evaluate(x *cryptography.FieldElement) *cryptography.FieldElement {
	if len(p.Coeffs) == 0 {
		return cryptography.NewFieldElement(0)
	}
	res := p.Coeffs[len(p.Coeffs)-1]
	for i := len(p.Coeffs) - 2; i >= 0; i-- {
		res = res.Mul(x).Add(p.Coeffs[i])
	}
	return res
}

// InterpolateUnivariate interpolates a polynomial of degree <= len(points)-1 from points (x_i, y_i)
func InterpolateUnivariate(xs []*cryptography.FieldElement, ys []*cryptography.FieldElement) (*Polynomial, error) {
	if len(xs) != len(ys) {
		return nil, errors.New("xs and ys length mismatch")
	}
	k := len(xs)
	if k == 0 {
		return nil, ErrInsufficientPoints
	}

	// Resulting polynomial coefficients initialized to 0
	resCoeffs := make([]*cryptography.FieldElement, k)
	for i := 0; i < k; i++ {
		resCoeffs[i] = cryptography.NewFieldElement(0)
	}

	for i := 0; i < k; i++ {
		// Compute basis polynomial \ell_i(x) = \prod_{j \ne i} \frac{x - x_j}{x_i - x_j}
		basis := []*cryptography.FieldElement{cryptography.NewFieldElement(1)}
		den := cryptography.NewFieldElement(1)

		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			diff := xs[i].Sub(xs[j])
			if diff.IsZero() {
				return nil, fmt.Errorf("%w: %s", ErrDuplicateEvaluation, xs[i].Hex())
			}
			den = den.Mul(diff)

			// Multiply basis by (x - xs[j])
			// basis = basis * x - basis * xs[j]
			newBasis := make([]*cryptography.FieldElement, len(basis)+1)
			for idx := range newBasis {
				newBasis[idx] = cryptography.NewFieldElement(0)
			}
			negXj := xs[j].Neg()
			for bIdx, bVal := range basis {
				// term * x
				newBasis[bIdx+1] = newBasis[bIdx+1].Add(bVal)
				// term * (-xs[j])
				newBasis[bIdx] = newBasis[bIdx].Add(bVal.Mul(negXj))
			}
			basis = newBasis
		}

		invDen, err := den.Inv()
		if err != nil {
			return nil, err
		}
		weight := ys[i].Mul(invDen)

		for bIdx, bVal := range basis {
			term := bVal.Mul(weight)
			resCoeffs[bIdx] = resCoeffs[bIdx].Add(term)
		}
	}

	return &Polynomial{Coeffs: resCoeffs}, nil
}

// BivariatePolynomial represents F(x, y) = \sum_{j=0}^{k-1} \sum_{l=0}^{k-1} Coeffs[j][l] * x^j * y^l
type BivariatePolynomial struct {
	DegX   int // degree in x (k-1)
	DegY   int // degree in y (k-1)
	Coeffs [][]*cryptography.FieldElement
}

// NewBivariatePolynomial creates a bivariate polynomial from a 2D matrix of coefficients [x][y].
func NewBivariatePolynomial(coeffs [][]*cryptography.FieldElement) (*BivariatePolynomial, error) {
	if len(coeffs) == 0 || len(coeffs[0]) == 0 {
		return nil, errors.New("empty coefficients matrix")
	}
	degX := len(coeffs) - 1
	degY := len(coeffs[0]) - 1
	for j := 1; j < len(coeffs); j++ {
		if len(coeffs[j]) != degY+1 {
			return nil, errors.New("ragged coefficient matrix in bivariate polynomial")
		}
	}
	return &BivariatePolynomial{
		DegX:   degX,
		DegY:   degY,
		Coeffs: coeffs,
	}, nil
}

// SampleRandomBivariatePolynomial samples a random symmetric bivariate polynomial of degree deg
// with specified secret at (0, 0): F(0, 0) = secret.
// Symmetry ensures F(x, y) = F(y, x), matching Cachin et al. 2002.
func SampleRandomBivariatePolynomial(deg int, secret *cryptography.FieldElement) (*BivariatePolynomial, error) {
	k := deg + 1
	coeffs := make([][]*cryptography.FieldElement, k)
	for i := range coeffs {
		coeffs[i] = make([]*cryptography.FieldElement, k)
	}

	coeffs[0][0] = secret

	for j := 0; j < k; j++ {
		for l := j; l < k; l++ {
			if j == 0 && l == 0 {
				continue
			}
			val, err := cryptography.RandScalar()
			if err != nil {
				return nil, err
			}
			coeffs[j][l] = val
			coeffs[l][j] = val // Enforce symmetry
		}
	}

	return &BivariatePolynomial{
		DegX:   deg,
		DegY:   deg,
		Coeffs: coeffs,
	}, nil
}

// Evaluate evaluates F(x, y) at specific coordinates.
func (bp *BivariatePolynomial) Evaluate(x, y *cryptography.FieldElement) *cryptography.FieldElement {
	res := cryptography.NewFieldElement(0)
	xPow := cryptography.NewFieldElement(1)

	for j := 0; j <= bp.DegX; j++ {
		yPow := cryptography.NewFieldElement(1)
		rowSum := cryptography.NewFieldElement(0)
		for l := 0; l <= bp.DegY; l++ {
			term := bp.Coeffs[j][l].Mul(yPow)
			rowSum = rowSum.Add(term)
			yPow = yPow.Mul(y)
		}
		res = res.Add(rowSum.Mul(xPow))
		xPow = xPow.Mul(x)
	}

	return res
}

// RowPolynomial computes a_i(y) = F(i, y).
// Degree is <= DegY.
func (bp *BivariatePolynomial) RowPolynomial(i *cryptography.FieldElement) *Polynomial {
	rowCoeffs := make([]*cryptography.FieldElement, bp.DegY+1)
	for l := 0; l <= bp.DegY; l++ {
		coeffL := cryptography.NewFieldElement(0)
		iPow := cryptography.NewFieldElement(1)
		for j := 0; j <= bp.DegX; j++ {
			term := bp.Coeffs[j][l].Mul(iPow)
			coeffL = coeffL.Add(term)
			iPow = iPow.Mul(i)
		}
		rowCoeffs[l] = coeffL
	}
	return &Polynomial{Coeffs: rowCoeffs}
}

// ColPolynomial computes b_i(x) = F(x, i).
// Degree is <= DegX.
func (bp *BivariatePolynomial) ColPolynomial(i *cryptography.FieldElement) *Polynomial {
	colCoeffs := make([]*cryptography.FieldElement, bp.DegX+1)
	for j := 0; j <= bp.DegX; j++ {
		coeffJ := cryptography.NewFieldElement(0)
		iPow := cryptography.NewFieldElement(1)
		for l := 0; l <= bp.DegY; l++ {
			term := bp.Coeffs[j][l].Mul(iPow)
			coeffJ = coeffJ.Add(term)
			iPow = iPow.Mul(i)
		}
		colCoeffs[j] = coeffJ
	}
	return &Polynomial{Coeffs: colCoeffs}
}

