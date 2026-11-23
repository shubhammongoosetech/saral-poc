package avss

import (
	"errors"
	"fmt"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrInvalidCommitmentDimensions = errors.New("invalid commitment matrix dimensions")
	ErrCommitmentVerificationFail  = errors.New("cryptographic commitment verification failed")
)

// CommitmentMatrix represents the k x k Pedersen commitments to bivariate polynomial coefficients:
// C_{j,l} = F_{j,l} * G + F'_{j,l} * H
type CommitmentMatrix struct {
	Rows   int // k
	Cols   int // k
	Points [][]*cryptography.CurvePoint
}

// ComputeCommitmentMatrix computes the k x k Pedersen commitment matrix for bivariate polynomials F and F'.
func ComputeCommitmentMatrix(F, FPrime *BivariatePolynomial) (*CommitmentMatrix, error) {
	if F.DegX != FPrime.DegX || F.DegY != FPrime.DegY {
		return nil, ErrDegreeMismatch
	}
	kX := F.DegX + 1
	kY := F.DegY + 1

	pts := make([][]*cryptography.CurvePoint, kX)
	for j := 0; j < kX; j++ {
		pts[j] = make([]*cryptography.CurvePoint, kY)
		for l := 0; l < kY; l++ {
			pts[j][l] = cryptography.PedersenCommitment(F.Coeffs[j][l], FPrime.Coeffs[j][l])
		}
	}

	return &CommitmentMatrix{
		Rows:   kX,
		Cols:   kY,
		Points: pts,
	}, nil
}

// Curve returns the underlying curve name of this commitment matrix
func (cm *CommitmentMatrix) Curve() string {
	if cm != nil && cm.Rows > 0 && cm.Cols > 0 && cm.Points[0][0] != nil {
		return cm.Points[0][0].Curve
	}
	return "nist-p256"
}

// SecretCommitment returns C_{0,0} = s*G + s'*H
func (cm *CommitmentMatrix) SecretCommitment() *cryptography.CurvePoint {
	if cm.Rows > 0 && cm.Cols > 0 {
		return cm.Points[0][0]
	}
	return nil
}

// VerifyRowPolynomial verifies that row polynomials a_i(y) and a'_i(y) match the commitment matrix:
// For each coefficient l in [0, k-1]:
// Commit(a_{i,l}, a'_{i,l}) == \sum_{j=0}^{k-1} i^j * C_{j,l}
func (cm *CommitmentMatrix) VerifyRowPolynomial(
	i *cryptography.FieldElement,
	rowPoly *Polynomial,
	rowBlindPoly *Polynomial,
) bool {
	if rowPoly == nil || rowBlindPoly == nil {
		return false
	}
	if len(rowPoly.Coeffs) != cm.Cols || len(rowBlindPoly.Coeffs) != cm.Cols {
		return false
	}

	for l := 0; l < cm.Cols; l++ {
		actualCommit := cryptography.PedersenCommitment(rowPoly.Coeffs[l], rowBlindPoly.Coeffs[l])

		// Expected commit = \sum_{j=0}^{k-1} i^j * C_{j,l}
		expectedCommit := cryptography.ZeroPointForCurve(cm.Curve())
		iPow := cryptography.NewFieldElementWithOrder(1, i.Order())
		for j := 0; j < cm.Rows; j++ {
			term := cm.Points[j][l].ScalarMult(iPow)
			expectedCommit = expectedCommit.Add(term)
			iPow = iPow.Mul(i)
		}

		if !actualCommit.Equal(expectedCommit) {
			return false
		}
	}
	return true
}

// VerifyPoly implements the research paper's verify-poly predicate (Figure 1, Kate-Huang-Goldberg):
// verify-poly(C, i, a, a') := for each l in [0, t]: Commit(a_{i, l}, a'_{i, l}) == \sum_{j=0}^t i^j * C_{j, l}
// Guarantees that the received univariate slice belongs to the committed symmetric bivariate polynomial.
func (cm *CommitmentMatrix) VerifyPoly(
	i *cryptography.FieldElement,
	rowPoly *Polynomial,
	rowBlindPoly *Polynomial,
) bool {
	return cm.VerifyRowPolynomial(i, rowPoly, rowBlindPoly)
}

// VerifyColPolynomial verifies that column polynomials b_i(x) and b'_i(x) match the commitment matrix:
// For each coefficient j in [0, k-1]:
// Commit(b_{i,j}, b'_{i,j}) == \sum_{l=0}^{k-1} i^l * C_{j,l}
func (cm *CommitmentMatrix) VerifyColPolynomial(
	i *cryptography.FieldElement,
	colPoly *Polynomial,
	colBlindPoly *Polynomial,
) bool {
	if colPoly == nil || colBlindPoly == nil {
		return false
	}
	if len(colPoly.Coeffs) != cm.Rows || len(colBlindPoly.Coeffs) != cm.Rows {
		return false
	}

	for j := 0; j < cm.Rows; j++ {
		actualCommit := cryptography.PedersenCommitment(colPoly.Coeffs[j], colBlindPoly.Coeffs[j])

		// Expected commit = \sum_{l=0}^{k-1} i^l * C_{j,l}
		expectedCommit := cryptography.ZeroPointForCurve(cm.Curve())
		iPow := cryptography.NewFieldElementWithOrder(1, i.Order())
		for l := 0; l < cm.Cols; l++ {
			term := cm.Points[j][l].ScalarMult(iPow)
			expectedCommit = expectedCommit.Add(term)
			iPow = iPow.Mul(i)
		}

		if !actualCommit.Equal(expectedCommit) {
			return false
		}
	}
	return true
}

// VerifyPoint verifies an evaluation point p = F(i, j) and p' = F'(i, j) against C:
// Commit(p, p') == \sum_{u=0}^{k-1} \sum_{v=0}^{k-1} (i^u * j^v) * C_{u, v}
func (cm *CommitmentMatrix) VerifyPoint(
	i, j *cryptography.FieldElement,
	p, pPrime *cryptography.FieldElement,
) bool {
	if p == nil || pPrime == nil {
		return false
	}
	actualCommit := cryptography.PedersenCommitment(p, pPrime)

	expectedCommit := cryptography.ZeroPointForCurve(cm.Curve())
	uPow := cryptography.NewFieldElementWithOrder(1, i.Order())
	for u := 0; u < cm.Rows; u++ {
		vPow := cryptography.NewFieldElementWithOrder(1, j.Order())
		for v := 0; v < cm.Cols; v++ {
			uvScalar := uPow.Mul(vPow)
			term := cm.Points[u][v].ScalarMult(uvScalar)
			expectedCommit = expectedCommit.Add(term)
			vPow = vPow.Mul(j)
		}
		uPow = uPow.Mul(i)
	}

	return actualCommit.Equal(expectedCommit)
}

// VerifyShare verifies an individual participant share S_i = F(i, 0) and S'_i = F'(i, 0):
// Commit(S_i, S'_i) == \sum_{u=0}^{k-1} i^u * C_{u, 0}
func (cm *CommitmentMatrix) VerifyShare(
	i *cryptography.FieldElement,
	share, sharePrime *cryptography.FieldElement,
) bool {
	if share == nil || sharePrime == nil {
		return false
	}
	actualCommit := cryptography.PedersenCommitment(share, sharePrime)

	expectedCommit := cryptography.ZeroPointForCurve(cm.Curve())
	uPow := cryptography.NewFieldElementWithOrder(1, i.Order())
	for u := 0; u < cm.Rows; u++ {
		term := cm.Points[u][0].ScalarMult(uPow)
		expectedCommit = expectedCommit.Add(term)
		uPow = uPow.Mul(i)
	}

	return actualCommit.Equal(expectedCommit)
}

// ComputeShareCommitment computes Q_i = \sum_{u=0}^{k-1} i^u * C_{u, 0}
func (cm *CommitmentMatrix) ComputeShareCommitment(i *cryptography.FieldElement) *cryptography.CurvePoint {
	expectedCommit := cryptography.ZeroPointForCurve(cm.Curve())
	uPow := cryptography.NewFieldElementWithOrder(1, i.Order())
	for u := 0; u < cm.Rows; u++ {
		term := cm.Points[u][0].ScalarMult(uPow)
		expectedCommit = expectedCommit.Add(term)
		uPow = uPow.Mul(i)
	}
	return expectedCommit
}

// ToHexMatrix serializes the commitment matrix into a 2D array of uncompressed point hex strings.
func (cm *CommitmentMatrix) ToHexMatrix() [][]string {
	res := make([][]string, cm.Rows)
	for j := 0; j < cm.Rows; j++ {
		res[j] = make([]string, cm.Cols)
		for l := 0; l < cm.Cols; l++ {
			res[j][l] = cm.Points[j][l].Hex()
		}
	}
	return res
}

// ParseCommitmentMatrixFromHex parses a 2D hex array into a CommitmentMatrix on the designated curve.
func ParseCommitmentMatrixFromHex(hexMatrix [][]string) (*CommitmentMatrix, error) {
	return ParseCommitmentMatrixFromHexForCurve(hexMatrix, "nist-p256")
}

// ParseCommitmentMatrixFromHexForCurve parses a 2D hex array into a CommitmentMatrix on a designated curve.
func ParseCommitmentMatrixFromHexForCurve(hexMatrix [][]string, curve string) (*CommitmentMatrix, error) {
	if len(hexMatrix) == 0 || len(hexMatrix[0]) == 0 {
		return nil, ErrInvalidCommitmentDimensions
	}
	rows := len(hexMatrix)
	cols := len(hexMatrix[0])

	pts := make([][]*cryptography.CurvePoint, rows)
	for j := 0; j < rows; j++ {
		if len(hexMatrix[j]) != cols {
			return nil, ErrInvalidCommitmentDimensions
		}
		pts[j] = make([]*cryptography.CurvePoint, cols)
		for l := 0; l < cols; l++ {
			pt, err := cryptography.ParseCurvePointFromHexForCurve(hexMatrix[j][l], curve)
			if err != nil {
				return nil, fmt.Errorf("%w at [%d][%d]: %v", ErrInvalidCommitmentDimensions, j, l, err)
			}
			pts[j][l] = pt
		}
	}

	return &CommitmentMatrix{
		Rows:   rows,
		Cols:   cols,
		Points: pts,
	}, nil
}
