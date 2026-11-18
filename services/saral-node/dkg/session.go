package dkg

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// Session manages a single Dealerless DKG session on a local node
type Session struct {
	SessionID   string
	CommitteeID string
	Epoch       uint64
	SelfID      string
	SelfIndex   int
	Committee   []string
	N           int
	K           int
	T           int
	State       DKGState

	// Local random secret contribution material
	LocalSecret        *cryptography.FieldElement
	LocalBlind         *cryptography.FieldElement
	LocalDealerPkg     *avss.DealerPackage
	ContributionDealt  bool

	// Completed AVSS instances from peer dealers: DealerID -> Session
	CompletedSharings      map[string]*avss.Session
	PeerCommitments        map[string]*cryptography.CurvePoint
	PeerCommitmentMatrices map[string]*avss.CommitmentMatrix

	// Agreement instance for negotiating the Qualified Set QUAL
	Agreement *proactive.ValidatedAgreementInstance

	// Final derived DKG key material
	QualifiedSet        []string
	AgreedHash          string
	FinalShare          *cryptography.FieldElement
	FinalBlindShare     *cryptography.FieldElement
	FinalShareCommit    *cryptography.CurvePoint
	MasterPublicKey     *cryptography.CurvePoint

	ShareStore *vault.ShareStore
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Error      string

	mu sync.RWMutex
}

// NewSession initializes a new node DKG session
func NewSession(
	sessionID, committeeID, selfID string,
	selfIndex int,
	committee []string,
	n, k, t int,
	shareStore *vault.ShareStore,
) (*Session, error) {
	if err := ValidateDKGParameters(n, k, t); err != nil {
		return nil, err
	}

	normalizedCommittee := make([]string, len(committee))
	copy(normalizedCommittee, committee)

	sess := &Session{
		SessionID:              sessionID,
		CommitteeID:            committeeID,
		Epoch:                  1, // Initial DKG generates Epoch 1 shares
		SelfID:                 selfID,
		SelfIndex:              selfIndex,
		Committee:              normalizedCommittee,
		N:                      n,
		K:                      k,
		T:                      t,
		State:                  StateCreated,
		CompletedSharings:      make(map[string]*avss.Session),
		PeerCommitments:        make(map[string]*cryptography.CurvePoint),
		PeerCommitmentMatrices: make(map[string]*avss.CommitmentMatrix),
		ShareStore:             shareStore,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}

	// Define external validity predicate for Agreement on QUAL:
	// A candidate set S of dealers is valid iff |S| >= n - t and each dealer d in S
	// has a completed, verified AVSS sharing whose commitment matrix is registered.
	predicate := func(candidateSet []string) bool {
		sess.mu.RLock()
		defer sess.mu.RUnlock()

		if len(candidateSet) < sess.N-sess.T {
			return false
		}
		for _, dealerID := range candidateSet {
			subSess, exists := sess.CompletedSharings[dealerID]
			if !exists || subSess.Commitments == nil || subSess.Share == nil {
				return false
			}
			expectedQ, hasQ := sess.PeerCommitments[dealerID]
			if !hasQ || !subSess.Commitments.SecretCommitment().Equal(expectedQ) {
				return false
			}
		}
		return true
	}

	sess.Agreement = proactive.NewValidatedAgreementInstance(
		committeeID, 1, selfID, normalizedCommittee, n, t, n-t, predicate,
	)

	sess.State = StateParticipantsRegistered
	return sess, nil
}

// StartContribution generates a fresh random secret contribution and deals its AVSS sharing
func (s *Session) StartContribution() (*avss.DealerPackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ContributionDealt {
		return s.LocalDealerPkg, nil
	}

	// 1. Independently generate a fresh random secret contribution z_i in [1, q-1]
	zi, err := cryptography.RandScalar()
	if err != nil {
		s.State = StateFailed
		s.Error = fmt.Sprintf("failed to generate random secret contribution: %v", err)
		return nil, err
	}

	// 2. Independently generate a random blinding contribution z'_i in [1, q-1]
	zPrimeI, err := cryptography.RandScalar()
	if err != nil {
		s.State = StateFailed
		s.Error = fmt.Sprintf("failed to generate random blinding contribution: %v", err)
		return nil, err
	}

	subSessionID := fmt.Sprintf("dkg-%s-contrib-%s", s.SessionID, s.SelfID)

	// 3. Generate verifiable bivariate polynomial sharing of (zi, zPrimeI) via AVSS
	dealerPkg, err := avss.GenerateDealerSharing(
		subSessionID, s.CommitteeID, s.SelfID, s.Epoch, s.Committee, s.K, zi, zPrimeI,
	)
	if err != nil {
		s.State = StateFailed
		s.Error = fmt.Sprintf("failed to generate AVSS contribution package: %v", err)
		return nil, err
	}

	s.LocalSecret = zi
	s.LocalBlind = zPrimeI
	s.LocalDealerPkg = dealerPkg
	s.ContributionDealt = true
	s.PeerCommitments[s.SelfID] = dealerPkg.CommitmentMatrix.SecretCommitment()
	s.PeerCommitmentMatrices[s.SelfID] = dealerPkg.CommitmentMatrix
	s.State = StateAVSSSharing
	s.UpdatedAt = time.Now()

	return dealerPkg, nil
}

// RecordPeerCommitment registers a peer dealer's public commitment matrix
func (s *Session) RecordPeerCommitment(dealerID string, cm *avss.CommitmentMatrix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cm != nil {
		s.PeerCommitmentMatrices[dealerID] = cm
		s.PeerCommitments[dealerID] = cm.SecretCommitment()
	}
}

// RecordCompletedSharing registers a verified, finalized AVSS sub-sharing received from a dealer
func (s *Session) RecordCompletedSharing(dealerID string, sess *avss.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.CompletedSharings[dealerID] = sess
	if sess.Commitments != nil {
		s.PeerCommitmentMatrices[dealerID] = sess.Commitments
		s.PeerCommitments[dealerID] = sess.Commitments.SecretCommitment()
	}

	// Once >= n - t completed contributions are accumulated, advance state
	if s.State == StateAVSSSharing && len(s.CompletedSharings) >= s.N-s.T {
		s.State = StateContributionsVerified
		s.UpdatedAt = time.Now()
	}
}

// CanProposeQualifiedSet checks if the local node has verified >= n - t dealer sharings
func (s *Session) CanProposeQualifiedSet() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.CompletedSharings) >= s.N-s.T
}

// GetCandidateQualifiedSet returns the list of dealer IDs whose sharings are verified
func (s *Session) GetCandidateQualifiedSet() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	candidates := make([]string, 0, len(s.CompletedSharings))
	for dealerID := range s.CompletedSharings {
		candidates = append(candidates, dealerID)
	}
	sort.Strings(candidates)
	return candidates
}

// AggregateShares aggregates the verified AVSS shares from the agreed Qualified Set QUAL*
// Computes local private key share x_j = \sum_{i \in QUAL} s_{i, j} mod N,
// public key Y = \sum_{i \in QUAL} C^{(i)}_{0, 0}, and saves to vault.
func (s *Session) AggregateShares(agreedQUAL []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(agreedQUAL) < s.N-s.T {
		return fmt.Errorf("%w: agreed set size %d < required quorum %d",
			ErrInsufficientDealers, len(agreedQUAL), s.N-s.T)
	}

	sortedQUAL := make([]string, len(agreedQUAL))
	copy(sortedQUAL, agreedQUAL)
	sort.Strings(sortedQUAL)

	// 1. Verify every dealer in QUAL has a completed sharing
	for _, dealerID := range sortedQUAL {
		subSess, exists := s.CompletedSharings[dealerID]
		if !exists || subSess.Share == nil || subSess.BlindShare == nil {
			return fmt.Errorf("missing verified AVSS share from qualified contributor: %s", dealerID)
		}
	}

	// 2. Aggregate local private key share and blinding factor:
	// x_j = \sum_{i \in QUAL} s_{i, j} \pmod N
	// x'_j = \sum_{i \in QUAL} s'_{i, j} \pmod N
	combinedShare := cryptography.NewFieldElement(0)
	combinedBlind := cryptography.NewFieldElement(0)

	for _, dealerID := range sortedQUAL {
		subSess := s.CompletedSharings[dealerID]
		combinedShare = combinedShare.Add(subSess.Share)
		combinedBlind = combinedBlind.Add(subSess.BlindShare)
	}

	// 3. Derive group master public key / secret commitment:
	// Y = \sum_{i \in QUAL} C^{(i)}_{0, 0}
	masterPubKey := &cryptography.CurvePoint{X: cryptography.Zero, Y: cryptography.Zero}
	for _, dealerID := range sortedQUAL {
		subCommit, exists := s.PeerCommitments[dealerID]
		if !exists || subCommit == nil {
			return fmt.Errorf("missing secret commitment for qualified dealer: %s", dealerID)
		}
		masterPubKey = masterPubKey.Add(subCommit)
	}

	// 4. Derive local public share verification commitment:
	// Q_j = x_j * G + x'_j * H
	shareCommitment := cryptography.PedersenCommitment(combinedShare, combinedBlind)

	// Mathematical consistency check:
	// Verify that Q_j matches the sum of the dealers' individual share commitments at x = selfIndex
	selfIdxFE := cryptography.NewFieldElement(int64(s.SelfIndex))
	expectedShareCommit := &cryptography.CurvePoint{X: cryptography.Zero, Y: cryptography.Zero}
	for _, dealerID := range sortedQUAL {
		cm := s.PeerCommitmentMatrices[dealerID]
		if cm == nil {
			return fmt.Errorf("missing commitment matrix for dealer %s", dealerID)
		}
		expectedShareCommit = expectedShareCommit.Add(cm.ComputeShareCommitment(selfIdxFE))
	}

	if !shareCommitment.Equal(expectedShareCommit) {
		s.State = StateFailed
		s.Error = ErrPublicKeyMismatch.Error()
		return fmt.Errorf("%w: derived share commitment does not match aggregated matrix commitments", ErrPublicKeyMismatch)
	}

	s.State = StateSharesAggregated
	s.QualifiedSet = sortedQUAL
	s.AgreedHash = proactive.HashCandidateSet(sortedQUAL)
	s.FinalShare = combinedShare
	s.FinalBlindShare = combinedBlind
	s.FinalShareCommit = shareCommitment
	s.MasterPublicKey = masterPubKey
	s.State = StatePublicKeyVerified
	s.UpdatedAt = time.Now()

	// 5. Secure Persistence in Node Vault
	if s.ShareStore != nil {
		meta := vault.ShareRecordMetadata{
			CommitteeID:            s.CommitteeID,
			SessionID:              s.SessionID,
			NodeID:                 s.SelfID,
			NodeIndex:              s.SelfIndex,
			Epoch:                  s.Epoch,
			ShareVersion:           s.Epoch,
			State:                  "ACTIVE",
			PublicShareCommitment:  shareCommitment.Hex(),
			PublicSecretCommitment: masterPubKey.Hex(),
			CreatedAt:              time.Now().UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
		}
		if err := s.ShareStore.SaveShare(meta, combinedShare, combinedBlind); err != nil {
			s.State = StateFailed
			s.Error = fmt.Sprintf("failed saving final DKG share to encrypted vault: %v", err)
			return err
		}
	}

	// Zero out ephemeral contribution secrets
	s.LocalSecret = nil
	s.LocalBlind = nil

	s.State = StateCompleted
	s.UpdatedAt = time.Now()
	return nil
}

// GetPublicView returns a safe, unprivileged public status view of the DKG session.
// STRICT PRIVACY GUARANTEE: Private shares are NEVER exposed in the public view.
func (s *Session) GetPublicView() *DKGSessionPublicView {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parts := make(map[string]*DKGParticipantStatus, s.N)
	for idx, id := range s.Committee {
		statusStr := "PENDING"
		_, completed := s.CompletedSharings[id]
		inQual := false
		for _, q := range s.QualifiedSet {
			if q == id {
				inQual = true
				break
			}
		}

		if inQual {
			statusStr = "QUALIFIED"
		} else if completed {
			statusStr = "CONTRIBUTED"
		}

		secCommitHex := ""
		if c, exists := s.PeerCommitments[id]; exists && c != nil {
			secCommitHex = c.Hex()
		}

		parts[id] = &DKGParticipantStatus{
			NodeID:            id,
			NodeIndex:         idx + 1,
			ContributionDealt: s.SelfID == id && s.ContributionDealt,
			SecretCommitment:  secCommitHex,
			CompletedSharings: len(s.CompletedSharings),
			InQualifiedSet:    inQual,
			ShareAggregated:   s.State == StateCompleted,
			Status:            statusStr,
		}
	}

	var masterPubHex string
	if s.MasterPublicKey != nil {
		masterPubHex = s.MasterPublicKey.Hex()
	}

	return &DKGSessionPublicView{
		SessionID:       s.SessionID,
		CommitteeID:     s.CommitteeID,
		Epoch:           s.Epoch,
		N:               s.N,
		K:               s.K,
		T:               s.T,
		State:           s.State,
		Committee:       s.Committee,
		QualifiedSet:    s.QualifiedSet,
		MasterPublicKey: masterPubHex,
		Curve:           "NIST P-256",
		Participants:    parts,
		CreatedAt:       s.CreatedAt.UnixMilli(),
		UpdatedAt:       s.UpdatedAt.UnixMilli(),
		Error:           s.Error,
	}
}
