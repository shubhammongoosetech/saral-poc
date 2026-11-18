package avss

import (
	"fmt"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

// DealerPackage contains the dealer's generated secrets, polynomials, commitments and messages
type DealerPackage struct {
	SessionID        string
	Secret           *cryptography.FieldElement
	BlindSecret      *cryptography.FieldElement
	F                *BivariatePolynomial
	FPrime           *BivariatePolynomial
	CommitmentMatrix *CommitmentMatrix
	SendMessages     map[string]*SendMessage // RecipientNodeID -> SendMessage
}

// GenerateDealerSharing executes the dealer sharing stage:
// 1. Samples secret s and blinding s' using CSPRNG.
// 2. Samples symmetric bivariate polynomials F(x, y) and F'(x, y) of degree k-1.
// 3. Generates Pedersen commitment matrix C.
// 4. Generates private polynomial evaluations (a_j, a'_j, b_j, b'_j) for each participant.
// 5. Packages SendMessage payloads for distribution via authenticated relay.
func GenerateDealerSharing(
	sessionID, committeeID, dealerID string,
	epoch uint64,
	committee []string, // ordered list of NodeIDs
	k int,
	explicitSecret *cryptography.FieldElement, // optional, nil to generate fresh CSPRNG secret
	explicitBlindSecret *cryptography.FieldElement,
) (*DealerPackage, error) {
	deg := k - 1
	n := len(committee)
	t := (n - 1) / 3 // baseline corruption bound for parameter validation
	// Find applicable t such that n - 2t >= k and k > t
	validT := false
	for candT := (n - k) / 2; candT >= 0; candT-- {
		if k > candT && n-2*candT >= k {
			t = candT
			validT = true
			break
		}
	}
	_ = t
	if !validT {
		return nil, fmt.Errorf("committee size n=%d cannot satisfy AVSS bounds with threshold k=%d", n, k)
	}

	// 1. Generate or use secret
	secret := explicitSecret
	if secret == nil {
		var err error
		secret, err = cryptography.RandScalar()
		if err != nil {
			return nil, fmt.Errorf("failed to sample secret scalar: %w", err)
		}
	}

	blindSecret := explicitBlindSecret
	if blindSecret == nil {
		var err error
		blindSecret, err = cryptography.RandScalar()
		if err != nil {
			return nil, fmt.Errorf("failed to sample blinding scalar: %w", err)
		}
	}

	// 2. Sample bivariate polynomials
	F, err := SampleRandomBivariatePolynomial(deg, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sample bivariate polynomial F: %w", err)
	}

	FPrime, err := SampleRandomBivariatePolynomial(deg, blindSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sample blinding polynomial F': %w", err)
	}

	// 3. Compute commitment matrix
	commitMatrix, err := ComputeCommitmentMatrix(F, FPrime)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment matrix: %w", err)
	}
	commitHex := commitMatrix.ToHexMatrix()

	// 4. Generate polynomial evaluations for each participant
	sendMessages := make(map[string]*SendMessage)
	now := time.Now().UnixMilli()

	for idx, nodeID := range committee {
		// Participant index is 1-based: j = 1, 2, ..., n
		jFE := cryptography.NewFieldElement(int64(idx + 1))

		rowPoly := F.RowPolynomial(jFE)
		rowBlindPoly := FPrime.RowPolynomial(jFE)
		colPoly := F.ColPolynomial(jFE)
		colBlindPoly := FPrime.ColPolynomial(jFE)

		rowHex := make([]string, len(rowPoly.Coeffs))
		rowBlindHex := make([]string, len(rowBlindPoly.Coeffs))
		colHex := make([]string, len(colPoly.Coeffs))
		colBlindHex := make([]string, len(colBlindPoly.Coeffs))

		for cIdx := range rowPoly.Coeffs {
			rowHex[cIdx] = rowPoly.Coeffs[cIdx].Hex()
			rowBlindHex[cIdx] = rowBlindPoly.Coeffs[cIdx].Hex()
		}
		for cIdx := range colPoly.Coeffs {
			colHex[cIdx] = colPoly.Coeffs[cIdx].Hex()
			colBlindHex[cIdx] = colBlindPoly.Coeffs[cIdx].Hex()
		}

		sendMessages[nodeID] = &SendMessage{
			SessionID:    sessionID,
			CommitteeID:  committeeID,
			DealerID:     dealerID,
			RecipientID:  nodeID,
			Epoch:        epoch,
			Commitments:  commitHex,
			RowPoly:      rowHex,
			RowBlindPoly: rowBlindHex,
			ColPoly:      colHex,
			ColBlindPoly: colBlindHex,
			Timestamp:    now,
		}
	}

	return &DealerPackage{
		SessionID:        sessionID,
		Secret:           secret,
		BlindSecret:      blindSecret,
		F:                F,
		FPrime:           FPrime,
		CommitmentMatrix: commitMatrix,
		SendMessages:     sendMessages,
	}, nil
}
