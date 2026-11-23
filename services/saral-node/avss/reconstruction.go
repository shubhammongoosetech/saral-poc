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
//
// HARD SECURITY INVARIANT (Requirement R4):
// Secret reconstruction is NEVER reachable in any wallet or production key flow.
// Private signing keys are NEVER created, assembled, reconstructed, or persisted on any server, node,
// coordinator, database, or client device. Only public points (Y_i = x_i*G) and encrypted shares
// in local AES-256-GCM vaults exist.
func ReconstructSecret(
	shares []*ReconstructionShare,
	commitMatrix *CommitmentMatrix,
	k int,
) (*ReconstructedSecret, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("%w: provided %d shares, required threshold k=%d",
			ErrThresholdNotMet, len(shares), k)
	}

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

		xFE := cryptography.NewFieldElement(int64(sh.NodeIndex))
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

	xTarget := cryptography.NewFieldElement(0)
	reconstructedSecret := cryptography.NewFieldElement(0)
	reconstructedBlind := cryptography.NewFieldElement(0)

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

