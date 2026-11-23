package dkg

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
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

	// Authenticated User & Key Binding
	WalletID      string
	KeyID         string
	UserBindingID string
	ChainFamily   string
	Curve         string

	// Local random secret contribution material
	LocalSecret        *cryptography.FieldElement
	LocalBlind         *cryptography.FieldElement
	LocalDealerPkg     *avss.DealerPackage
	ContributionDealt  bool
	proposed           bool

	// Completed AVSS instances from peer dealers: DealerID -> Session
	CompletedSharings      map[string]*avss.Session
	PeerCommitments        map[string]*cryptography.CurvePoint // C^{(i)}_{0,0} = z_i*G + z'_i*H
	PeerPublicKeys         map[string]*cryptography.CurvePoint // V_i = z_i*G (unblinded signing public key share)
	PeerCommitmentMatrices map[string]*avss.CommitmentMatrix

	// Leader-based HybridDKG instance for negotiating Qualified Set QUAL
	HybridDKG *HybridDKGInstance

	// Final derived DKG key material
	QualifiedSet           []string
	AgreedHash             string
	FinalShare             *cryptography.FieldElement
	FinalBlindShare        *cryptography.FieldElement
	FinalShareCommit       *cryptography.CurvePoint
	MasterSigningPublicKey *cryptography.CurvePoint // Y = x * G (Genuine unblinded signing public key)
	MasterSecretCommitment *cryptography.CurvePoint // C = x * G + x' * H (Pedersen commitment)
	MasterPublicKey        *cryptography.CurvePoint // Signing public key point

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
		PeerPublicKeys:         make(map[string]*cryptography.CurvePoint),
		PeerCommitmentMatrices: make(map[string]*avss.CommitmentMatrix),
		ShareStore:             shareStore,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	sess.HybridDKG = NewHybridDKGInstance(
		sessionID, committeeID, selfID, selfIndex,
		normalizedCommittee, n, k, t, 0, priv, make(map[string]string),
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
	zi, err := cryptography.RandScalarForCurve(s.Curve)
	if err != nil {
		s.State = StateFailed
		s.Error = fmt.Sprintf("failed to generate random secret contribution: %v", err)
		return nil, err
	}

	// 2. Independently generate a random blinding contribution z'_i in [1, q-1]
	zPrimeI, err := cryptography.RandScalarForCurve(s.Curve)
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
	s.PeerPublicKeys[s.SelfID] = cryptography.GetGeneratorG(s.Curve).ScalarMult(zi)
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

// RecordPeerPublicKey registers a peer dealer's unblinded public key commitment V_i = z_i * G
func (s *Session) RecordPeerPublicKey(dealerID string, pk *cryptography.CurvePoint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pk != nil && pk.IsOnCurve() {
		s.PeerPublicKeys[dealerID] = pk
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

// ensureHybridDKG ensures HybridDKG instance is initialized and synchronized with session curve
func (s *Session) ensureHybridDKG() {
	if s.HybridDKG == nil {
		_, priv, _ := ed25519.GenerateKey(nil)
		s.HybridDKG = NewHybridDKGInstance(
			s.SessionID, s.CommitteeID, s.SelfID, s.SelfIndex,
			s.Committee, s.N, s.K, s.T, 0, priv, make(map[string]string),
		)
	}
	s.HybridDKG.Curve = s.Curve
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

	s.ensureHybridDKG()

	// Call Kate-Huang-Goldberg Section 5.3 CombineDKGShares
	result, err := s.HybridDKG.CombineDKGShares(
		agreedQUAL,
		s.CompletedSharings,
		s.PeerCommitments,
		s.PeerCommitmentMatrices,
		s.PeerPublicKeys,
	)
	if err != nil {
		s.State = StateFailed
		s.Error = err.Error()
		return fmt.Errorf("CombineDKGShares failed: %w", err)
	}

	s.State = StateSharesAggregated
	s.QualifiedSet = result.AgreedQUAL
	s.AgreedHash = result.ProposalHash
	s.FinalShare = result.CombinedShare
	s.FinalBlindShare = result.CombinedBlindShare
	s.FinalShareCommit = result.LocalShareCommitment
	s.MasterSecretCommitment = result.MasterSecretCommitment
	s.MasterSigningPublicKey = result.MasterSigningPublicKey
	s.MasterPublicKey = result.MasterSigningPublicKey
	s.State = StatePublicKeyVerified
	s.UpdatedAt = time.Now()

	// 5. Secure Persistence in Node Vault
	if s.ShareStore != nil {
		meta := vault.ShareRecordMetadata{
			WalletID:               s.WalletID,
			KeyID:                  s.KeyID,
			UserBindingID:          s.UserBindingID,
			DKGSessionID:           s.SessionID,
			SessionID:              s.SessionID,
			CommitteeID:            s.CommitteeID,
			ParticipantID:          s.SelfID,
			NodeID:                 s.SelfID,
			NodeIndex:              s.SelfIndex,
			ChainFamily:            s.ChainFamily,
			Curve:                  s.Curve,
			Threshold:              s.K,
			ShareEpoch:             s.Epoch,
			Epoch:                  s.Epoch,
			ShareVersion:           s.Epoch,
			State:                  "ACTIVE",
			PublicShareCommitment:  result.LocalShareCommitment.Hex(),
			PublicSecretCommitment: result.MasterSecretCommitment.Hex(),
			CreationTimestamp:      time.Now().UnixMilli(),
			CreatedAt:              time.Now().UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
			RecordVersion:          1,
		}
		if err := s.ShareStore.SaveShare(meta, result.CombinedShare, result.CombinedBlindShare); err != nil {
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
	var signingPubHex string
	if s.MasterSigningPublicKey != nil {
		signingPubHex = s.MasterSigningPublicKey.Hex()
	} else {
		signingPubHex = masterPubHex
	}
	var secretCommitHex string
	if s.MasterSecretCommitment != nil {
		secretCommitHex = s.MasterSecretCommitment.Hex()
	} else {
		secretCommitHex = masterPubHex
	}

	return &DKGSessionPublicView{
		SessionID:              s.SessionID,
		CommitteeID:            s.CommitteeID,
		Epoch:                  s.Epoch,
		N:                      s.N,
		K:                      s.K,
		T:                      s.T,
		State:                  s.State,
		Committee:              s.Committee,
		QualifiedSet:           s.QualifiedSet,
		MasterSigningPublicKey: signingPubHex,
		MasterSecretCommitment: secretCommitHex,
		MasterPublicKey:        masterPubHex,
		Curve:                  "NIST P-256",
		Participants:           parts,
		CreatedAt:              s.CreatedAt.UnixMilli(),
		UpdatedAt:              s.UpdatedAt.UnixMilli(),
		Error:                  s.Error,
	}
}
