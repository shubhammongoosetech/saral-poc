package proactive

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

var (
	ErrRefreshMismatchSecret = errors.New("underlying secret verification mismatch across refresh")
	ErrOldShareNotErased     = errors.New("failed to securely erase old epoch share")
)

// RefreshSession manages the complete research-grounded proactive share refresh protocol (Section 11)
type RefreshSession struct {
	CommitteeID string
	OldEpoch    uint64
	NewEpoch    uint64
	SelfID      string
	SelfIndex   int
	Committee   []string
	N           int
	K           int
	T           int

	OldShare      *cryptography.FieldElement
	OldBlindShare *cryptography.FieldElement

	// Peer public share commitments from previous epoch: NodeID -> Q_j = s_j*G + s'_j*H
	PeerShareCommitments map[string]*cryptography.CurvePoint
	MasterCommitment     *cryptography.CurvePoint

	// Subprotocol AVSS instances: DealerNodeID -> completed Session
	CompletedSharings map[string]*avss.Session
	Agreement         *ValidatedAgreementInstance

	// Resulting refreshed share material
	NewShare              *cryptography.FieldElement
	NewBlindShare         *cryptography.FieldElement
	NewShareCommitment    *cryptography.CurvePoint
	NewSecretCommitment   *cryptography.CurvePoint

	State     RefreshState
	CreatedAt time.Time
	UpdatedAt time.Time
	Error     string

	mu sync.RWMutex
}

// NewRefreshSession initializes a new proactive refresh session
func NewRefreshSession(
	committeeID string,
	oldEpoch uint64,
	selfID string,
	selfIndex int,
	committee []string,
	k, t int,
	oldShare, oldBlindShare *cryptography.FieldElement,
	peerCommitments map[string]*cryptography.CurvePoint,
	masterCommitment *cryptography.CurvePoint,
) (*RefreshSession, error) {
	n := len(committee)
	if k != t+1 {
		return nil, fmt.Errorf("proactive refresh requires ordinary sharing k = t + 1 (got k=%d, t=%d)", k, t)
	}
	if n <= 3*t {
		return nil, fmt.Errorf("proactive refresh requires n > 3t (got n=%d, t=%d)", n, t)
	}

	rs := &RefreshSession{
		CommitteeID:          committeeID,
		OldEpoch:             oldEpoch,
		NewEpoch:             oldEpoch + 1,
		SelfID:               selfID,
		SelfIndex:            selfIndex,
		Committee:            committee,
		N:                    n,
		K:                    k,
		T:                    t,
		OldShare:             oldShare,
		OldBlindShare:        oldBlindShare,
		PeerShareCommitments: peerCommitments,
		MasterCommitment:     masterCommitment,
		CompletedSharings:    make(map[string]*avss.Session),
		State:                RefreshStateIdle,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Define external validity predicate for Validated Agreement:
	// A candidate set S of dealers is valid iff |S| >= 2t+1 and for each dealer d, C^{(d)}_{0,0} == Q^{(\tau)}_d
	predicate := func(candidateSet []string) bool {
		if len(candidateSet) < 2*t+1 {
			return false
		}
		for _, dealerID := range candidateSet {
			sess, exists := rs.CompletedSharings[dealerID]
			if !exists || sess.Commitments == nil {
				return false
			}
			expectedQ, hasQ := rs.PeerShareCommitments[dealerID]
			if !hasQ {
				return false
			}
			// C^{(dealer)}_{0, 0} must match Q_dealer from previous epoch
			if !sess.Commitments.SecretCommitment().Equal(expectedQ) {
				return false
			}
		}
		return true
	}

	rs.Agreement = NewValidatedAgreementInstance(committeeID, oldEpoch+1, selfID, committee, n, t, 2*t+1, predicate)
	return rs, nil
}

// RecordCompletedSharing registers a successfully completed AVSS subprotocol where a peer shared its share
func (rs *RefreshSession) RecordCompletedSharing(dealerID string, sess *avss.Session) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.CompletedSharings[dealerID] = sess
}

// CanProposeAgreement checks if we have accumulated >= 2t + 1 verified completed AVSS instances
func (rs *RefreshSession) CanProposeAgreement() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	validCount := 0
	for dealerID, sess := range rs.CompletedSharings {
		expectedQ, hasQ := rs.PeerShareCommitments[dealerID]
		if hasQ && sess.Commitments != nil && sess.Commitments.SecretCommitment().Equal(expectedQ) {
			validCount++
		}
	}
	return validCount >= 2*rs.T+1
}

// GetCandidateSet returns the list of dealer IDs whose sharings are verified
func (rs *RefreshSession) GetCandidateSet() []string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	candidates := make([]string, 0, len(rs.CompletedSharings))
	for dealerID, sess := range rs.CompletedSharings {
		expectedQ, hasQ := rs.PeerShareCommitments[dealerID]
		if hasQ && sess.Commitments != nil && sess.Commitments.SecretCommitment().Equal(expectedQ) {
			candidates = append(candidates, dealerID)
		}
	}
	return candidates
}

// ComputeNewShare computes the refreshed share from the agreed candidate set S* via Lagrange interpolation
func (rs *RefreshSession) ComputeNewShare(agreedSet []string, shareStore *vault.ShareStore) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if len(agreedSet) < rs.K {
		return fmt.Errorf("agreed set size %d < threshold k=%d", len(agreedSet), rs.K)
	}

	// 1. Select the canonical first k dealers from the agreed set
	subset := agreedSet[:rs.K]
	xCoords := make([]*cryptography.FieldElement, rs.K)
	for idx, dealerID := range subset {
		dealerIndex := avss.NodeIndexInCommittee(rs.Committee, dealerID)
		if dealerIndex == -1 {
			return fmt.Errorf("dealer %s not in committee", dealerID)
		}
		xCoords[idx] = cryptography.NewFieldElement(int64(dealerIndex))
	}

	// 2. Compute Lagrange coefficients at x = 0 for the subset
	xTarget := cryptography.NewFieldElement(0)
	lambdas := make([]*cryptography.FieldElement, rs.K)
	for i := 0; i < rs.K; i++ {
		l, err := cryptography.LagrangeCoefficient(xTarget, xCoords[i], xCoords)
		if err != nil {
			return fmt.Errorf("failed computing lagrange coefficient for dealer %s: %w", subset[i], err)
		}
		lambdas[i] = l
	}

	// 3. Compute new share s^{(\tau+1)}_j = \sum_{i \in subset} \lambda_i * s_{i, j} \pmod q
	newShare := cryptography.NewFieldElement(0)
	newBlindShare := cryptography.NewFieldElement(0)

	for i := 0; i < rs.K; i++ {
		dealerID := subset[i]
		subSess, exists := rs.CompletedSharings[dealerID]
		if !exists || subSess.Share == nil || subSess.BlindShare == nil {
			return fmt.Errorf("missing completed sub-share for dealer %s", dealerID)
		}

		termShare := lambdas[i].Mul(subSess.Share)
		termBlind := lambdas[i].Mul(subSess.BlindShare)

		newShare = newShare.Add(termShare)
		newBlindShare = newBlindShare.Add(termBlind)
	}

	// 4. Verify that the new secret commitment matches the master commitment
	// \sum \lambda_i * Q_i == C_{0, 0}
	computedMasterCommit := &cryptography.CurvePoint{X: cryptography.Zero, Y: cryptography.Zero}
	for i := 0; i < rs.K; i++ {
		dealerID := subset[i]
		qI := rs.PeerShareCommitments[dealerID]
		termPt := qI.ScalarMult(lambdas[i])
		computedMasterCommit = computedMasterCommit.Add(termPt)
	}

	if rs.MasterCommitment != nil && !computedMasterCommit.Equal(rs.MasterCommitment) {
		rs.State = RefreshStateFailed
		rs.Error = ErrRefreshMismatchSecret.Error()
		return ErrRefreshMismatchSecret
	}

	// 5. Compute new public share commitment Q^{(\tau+1)}_j = newShare*G + newBlindShare*H
	newShareCommit := cryptography.PedersenCommitment(newShare, newBlindShare)

	rs.NewShare = newShare
	rs.NewBlindShare = newBlindShare
	rs.NewShareCommitment = newShareCommit
	rs.NewSecretCommitment = computedMasterCommit
	rs.State = RefreshStateCompleted
	rs.UpdatedAt = time.Now()

	// 6. Secure Erasure of old epoch share from vault and disk (Section 10 & 11)
	if shareStore != nil {
		if err := shareStore.SecureEraseEpoch(rs.CommitteeID, rs.OldEpoch); err != nil {
			return fmt.Errorf("%w: %v", ErrOldShareNotErased, err)
		}

		// Persist new refreshed share
		newMeta := vault.ShareRecordMetadata{
			CommitteeID:            rs.CommitteeID,
			SessionID:              fmt.Sprintf("refresh-epoch-%d", rs.NewEpoch),
			NodeID:                 rs.SelfID,
			NodeIndex:              rs.SelfIndex,
			Epoch:                  rs.NewEpoch,
			ShareVersion:           rs.NewEpoch,
			State:                  "ACTIVE",
			PublicShareCommitment:  newShareCommit.Hex(),
			PublicSecretCommitment: computedMasterCommit.Hex(),
			CreatedAt:              time.Now().UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
		}
		if err := shareStore.SaveShare(newMeta, newShare, newBlindShare); err != nil {
			return fmt.Errorf("failed saving refreshed share to vault: %w", err)
		}
	}

	// Zero out old share in memory
	rs.OldShare = nil
	rs.OldBlindShare = nil

	return nil
}

