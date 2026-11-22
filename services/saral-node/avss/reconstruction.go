package avss

import (
	"errors"
	"fmt"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrThresholdNotMet        = errors.New("insufficient valid shares: reconstruction threshold k not met")
	ErrInvalidShareCommitment = errors.New("individual share fails verification against public commitment")
)

// ReconstructionShare holds an individual participant's share submitted for test reconstruction
type ReconstructionShare struct {
	NodeID     string
	NodeIndex  int // 1-based index in committee
	Share      *cryptography.FieldElement
	BlindShare *cryptography.FieldElement
}

// ReconstructedSecret holds the recovered secret and verification proof
type ReconstructedSecret struct {
	Secret            *cryptography.FieldElement
	BlindSecret       *cryptography.FieldElement
	SecretCommitment  *cryptography.CurvePoint
	ValidShareCount   int
	ThresholdRequired int
}

// ReconstructSecret executes strictly isolated verifiable share reconstruction for test workflows:
// 1. Checks that at least k valid shares from distinct participants are provided.
// 2. Verifies each share against the public commitment matrix: Commit(S_i, S'_i) == C(i, 0).
// 3. Computes Lagrange coefficients at x = 0.
// 4. Interpolates secret s = \sum \lambda_i S_i mod q and blinding s' = \sum \lambda_i S'_i mod q.
// 5. Verifies reconstructed secret against C_{0, 0}: Commit(s, s') == C_{0, 0}.
// 6. Returns error if fewer than k shares, or if any share is corrupted.
func ReconstructSecret(
	shares []*ReconstructionShare,
	commitMatrix *CommitmentMatrix,
	k int,
) (*ReconstructedSecret, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("%w: provided %d shares, required threshold k=%d",
			ErrThresholdNotMet, len(shares), k)
	}

	curve := commitMatrix.SecretCommitment().Curve()
	// 1. Validate distinct indices and verify individual shares against commitments
	seenIndices := make(map[int]bool)
	validShares := make([]*ReconstructionShare, 0, len(shares))
	allX := make([]*cryptography.FieldElement, 0, len(shares))

	for _, sh := range shares {
		if sh.NodeIndex <= 0 {
			return nil, fmt.Errorf("invalid 1-based node index: %d", sh.NodeIndex)
		}
		if seenIndices[sh.NodeIndex] {
			continue // skip duplicates
		}
		seenIndices[sh.NodeIndex] = true

		xFE := curve.Scalar(int64(sh.NodeIndex))
		// Verify share against C(i, 0)
		if !commitMatrix.VerifyShare(xFE, sh.Share, sh.BlindShare) {
			return nil, fmt.Errorf("%w for node %s (index %d)", ErrInvalidShareCommitment, sh.NodeID, sh.NodeIndex)
		}

		validShares = append(validShares, sh)
		allX = append(allX, xFE)
	}

	if len(validShares) < k {
		return nil, fmt.Errorf("%w: valid distinct shares (%d) < required threshold (%d)",
			ErrThresholdNotMet, len(validShares), k)
	}

	// Take the first k valid shares for interpolation
	kShares := validShares[:k]
	kX := allX[:k]

	xTarget := curve.Scalar(0)
	reconstructedSecret := curve.Scalar(0)
	reconstructedBlind := curve.Scalar(0)

	for i := 0; i < k; i++ {
		lambda, err := cryptography.LagrangeCoefficient(xTarget, kX[i], kX)
		if err != nil {
			return nil, fmt.Errorf("failed computing lagrange coefficient: %w", err)
		}

		termS := lambda.Mul(kShares[i].Share)
		termB := lambda.Mul(kShares[i].BlindShare)

		reconstructedSecret = reconstructedSecret.Add(termS)
		reconstructedBlind = reconstructedBlind.Add(termB)
	}

	// 5. Verify reconstructed secret against C_{0, 0}
	actualCommit := cryptography.PedersenCommitment(reconstructedSecret, reconstructedBlind)
	expectedCommit := commitMatrix.SecretCommitment()

	if !actualCommit.Equal(expectedCommit) {
		return nil, errors.New("reconstructed secret commitment mismatch with C_{0,0}")
	}

	return &ReconstructedSecret{
		Secret:            reconstructedSecret,
		BlindSecret:       reconstructedBlind,
		SecretCommitment:  actualCommit,
		ValidShareCount:   len(validShares),
		ThresholdRequired: k,
	}, nil
}
