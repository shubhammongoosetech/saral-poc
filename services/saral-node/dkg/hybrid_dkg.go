package dkg

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrNotCurrentLeader         = errors.New("node is not the designated leader for this round")
	ErrInsufficientCertificates = errors.New("insufficient valid completion certificates for dealer")
	ErrInvalidProposalRound     = errors.New("proposal round does not match current agreement round")
	ErrInvalidProposalLeader    = errors.New("proposal leader does not match designated leader")
	ErrProposalSignatureInvalid = errors.New("proposal signature verification failed")
	ErrQualifiedSetTooSmall     = errors.New("qualified set size is below fault tolerance threshold")
	ErrAlreadyDecided           = errors.New("agreement on qualified set is already decided")
	ErrDuplicateVoteFromPeer    = errors.New("duplicate vote received from peer")
)

// HybridDKGInstance implements the faithful Leader-Based HybridDKG protocol
// described in Section 5 (Figures 2 and 3) of Kate-Huang-Goldberg (ACNS 2012 / ePrint 2012/377).
type HybridDKGInstance struct {
	SessionID   string
	CommitteeID string
	SelfID      string
	SelfIndex   int
	Committee   []string
	N           int
	K           int
	T           int
	F           int // crash failure bound
	Curve       string

	// Round-based Leader State (Figure 3)
	Round         int
	CurrentLeader string

	// Cryptographic Identities
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	PeerPubKeys map[string]string // NodeID -> hex Ed25519 public key

	// Validity Certificates: DealerID -> SignerNodeID -> Certificate
	CollectedCertificates map[string]map[string]*ValidityCertificate
	LocalCertificates     map[string]*ValidityCertificate

	// Leader Proposals: Round -> LeaderProposalMessage
	Proposals map[int]*LeaderProposalMessage

	// Reliable Broadcast State: Round -> ProposalHash -> SenderID -> Message
	ReceivedEchos  map[int]map[string]map[string]*ProposalEchoMessage
	ReceivedReadys map[int]map[string]map[string]*ProposalReadyMessage
	SentEcho       map[int]bool
	SentReady      map[int]bool

	// Pessimistic Leader Change State (Figure 3): Round -> AccuserNodeID -> Message
	LeaderChangeVotes map[int]map[string]*LeaderChangeMessage
	SentLeaderChange  map[int]bool

	// Final Decision
	IsDecided           bool
	DecidedQUAL         []string
	DecidedProposalHash string

	mu sync.RWMutex
}

// NewHybridDKGInstance initializes a new leader-based HybridDKG instance.
func NewHybridDKGInstance(
	sessionID, committeeID, selfID string,
	selfIndex int,
	committee []string,
	n, k, t, f int,
	privKey ed25519.PrivateKey,
	peerPubKeys map[string]string,
) *HybridDKGInstance {
	normalizedCommittee := make([]string, len(committee))
	copy(normalizedCommittee, committee)

	pubKey := privKey.Public().(ed25519.PublicKey)

	inst := &HybridDKGInstance{
		SessionID:             sessionID,
		CommitteeID:           committeeID,
		SelfID:                selfID,
		SelfIndex:             selfIndex,
		Committee:             normalizedCommittee,
		N:                     n,
		K:                     k,
		T:                     t,
		F:                     f,
		Round:                 1,
		PrivateKey:            privKey,
		PublicKey:             pubKey,
		PeerPubKeys:           peerPubKeys,
		CollectedCertificates: make(map[string]map[string]*ValidityCertificate),
		LocalCertificates:     make(map[string]*ValidityCertificate),
		Proposals:             make(map[int]*LeaderProposalMessage),
		ReceivedEchos:         make(map[int]map[string]map[string]*ProposalEchoMessage),
		ReceivedReadys:        make(map[int]map[string]map[string]*ProposalReadyMessage),
		SentEcho:              make(map[int]bool),
		SentReady:             make(map[int]bool),
		LeaderChangeVotes:     make(map[int]map[string]*LeaderChangeMessage),
		SentLeaderChange:      make(map[int]bool),
	}
	inst.CurrentLeader = inst.getLeaderForRound(1)
	return inst
}

// GetCurve returns the designated curve or defaults to nist-p256
func (inst *HybridDKGInstance) GetCurve() string {
	if inst != nil && inst.Curve != "" {
		return inst.Curve
	}
	return "nist-p256"
}

// getLeaderForRound returns the deterministic leader for a round using cyclic permutation pi(r).
func (inst *HybridDKGInstance) getLeaderForRound(round int) string {
	idx := (round - 1) % len(inst.Committee)
	return inst.Committee[idx]
}

// GenerateCompletionCertificate generates and signs a ValidityCertificate for dealer whose VSS completed.
func (inst *HybridDKGInstance) GenerateCompletionCertificate(dealerID, commitmentsHash string, epoch uint64) (*ValidityCertificate, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	cert := &ValidityCertificate{
		SessionID:          inst.SessionID,
		DealerID:           dealerID,
		SignerNodeID:       inst.SelfID,
		SignerIndex:        inst.SelfIndex,
		CommitmentsHash:    commitmentsHash,
		Epoch:              epoch,
		Timestamp:          time.Now().UnixMilli(),
		SignerPublicKeyHex: hex.EncodeToString(inst.PublicKey),
	}

	sig := ed25519.Sign(inst.PrivateKey, cert.CanonicalPayload())
	cert.SignatureHex = hex.EncodeToString(sig)

	inst.LocalCertificates[dealerID] = cert
	if inst.CollectedCertificates[dealerID] == nil {
		inst.CollectedCertificates[dealerID] = make(map[string]*ValidityCertificate)
	}
	inst.CollectedCertificates[dealerID][inst.SelfID] = cert

	return cert, nil
}

// RecordCompletionCertificate records and cryptographically verifies a peer's ValidityCertificate.
func (inst *HybridDKGInstance) RecordCompletionCertificate(cert *ValidityCertificate) error {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !cert.Verify() {
		return errors.New("invalid signature on completion certificate")
	}

	dealerID := cert.DealerID
	if inst.CollectedCertificates[dealerID] == nil {
		inst.CollectedCertificates[dealerID] = make(map[string]*ValidityCertificate)
	}
	inst.CollectedCertificates[dealerID][cert.SignerNodeID] = cert
	return nil
}

// CanPropose checks if the local node is the current leader and has received >= t+1 certificates
// for at least n - t - f dealers (optimistic condition).
func (inst *HybridDKGInstance) CanPropose() bool {
	inst.mu.RLock()
	defer inst.mu.RUnlock()

	if inst.IsDecided {
		return false
	}
	if inst.SelfID != inst.CurrentLeader {
		return false
	}

	minDealers := inst.N - inst.T - inst.F
	qualifiedDealers := 0
	for _, certMap := range inst.CollectedCertificates {
		if len(certMap) >= inst.T+1 {
			qualifiedDealers++
		}
	}
	return qualifiedDealers >= minDealers
}

// CreateProposal constructs, hashes, and signs the leader's proposal message for round r.
func (inst *HybridDKGInstance) CreateProposal() (*LeaderProposalMessage, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.SelfID != inst.CurrentLeader {
		return nil, ErrNotCurrentLeader
	}

	minDealers := inst.N - inst.T - inst.F
	var candidateSet []string
	certsToSend := make(map[string][]ValidityCertificate)

	for dealerID, certMap := range inst.CollectedCertificates {
		if len(certMap) >= inst.T+1 {
			candidateSet = append(candidateSet, dealerID)
			var certList []ValidityCertificate
			for _, cert := range certMap {
				certList = append(certList, *cert)
			}
			certsToSend[dealerID] = certList
		}
	}

	if len(candidateSet) < minDealers {
		return nil, fmt.Errorf("%w: qualified dealers %d < required %d",
			ErrQualifiedSetTooSmall, len(candidateSet), minDealers)
	}

	sort.Strings(candidateSet)
	propHash := ComputeProposalHash(inst.SessionID, inst.CommitteeID, inst.Round, inst.SelfID, candidateSet)

	prop := &LeaderProposalMessage{
		SessionID:          inst.SessionID,
		CommitteeID:        inst.CommitteeID,
		Round:              inst.Round,
		LeaderID:           inst.SelfID,
		LeaderIndex:        inst.SelfIndex,
		QualifiedSet:       candidateSet,
		Certificates:       certsToSend,
		ProposalHash:       propHash,
		Timestamp:          time.Now().UnixMilli(),
		LeaderPublicKeyHex: hex.EncodeToString(inst.PublicKey),
	}

	sig := ed25519.Sign(inst.PrivateKey, prop.CanonicalPayload())
	prop.SignatureHex = hex.EncodeToString(sig)

	inst.Proposals[inst.Round] = prop
	return prop, nil
}

// ProcessProposal validates an incoming leader proposal and produces an ECHO message (Figure 2).
func (inst *HybridDKGInstance) ProcessProposal(prop *LeaderProposalMessage) (*ProposalEchoMessage, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.IsDecided {
		return nil, ErrAlreadyDecided
	}
	if prop.Round != inst.Round {
		return nil, fmt.Errorf("%w: got round %d, expected round %d",
			ErrInvalidProposalRound, prop.Round, inst.Round)
	}
	if prop.LeaderID != inst.CurrentLeader {
		return nil, fmt.Errorf("%w: got leader %s, expected designated leader %s",
			ErrInvalidProposalLeader, prop.LeaderID, inst.CurrentLeader)
	}
	if !prop.Verify() {
		return nil, ErrProposalSignatureInvalid
	}

	minDealers := inst.N - inst.T - inst.F
	if len(prop.QualifiedSet) < minDealers {
		return nil, ErrQualifiedSetTooSmall
	}

	// Verify certificates for all dealers in the proposed qualified set
	for _, dealerID := range prop.QualifiedSet {
		certList, exists := prop.Certificates[dealerID]
		if !exists || len(certList) < inst.T+1 {
			return nil, fmt.Errorf("%w for dealer %s: got %d certs, need %d",
				ErrInsufficientCertificates, dealerID, len(certList), inst.T+1)
		}
		// Verify signature of each certificate
		distinctSigners := make(map[string]bool)
		for _, cert := range certList {
			if !cert.Verify() {
				return nil, fmt.Errorf("invalid validity certificate signature for dealer %s from node %s",
					dealerID, cert.SignerNodeID)
			}
			distinctSigners[cert.SignerNodeID] = true
		}
		if len(distinctSigners) < inst.T+1 {
			return nil, fmt.Errorf("insufficient distinct certificate signers for dealer %s (got %d, need %d)",
				dealerID, len(distinctSigners), inst.T+1)
		}
	}

	inst.Proposals[inst.Round] = prop

	// Generate and sign ECHO message
	if inst.SentEcho[inst.Round] {
		return nil, nil
	}

	echo := &ProposalEchoMessage{
		SessionID:          inst.SessionID,
		CommitteeID:        inst.CommitteeID,
		Round:              inst.Round,
		SenderID:           inst.SelfID,
		SenderIndex:        inst.SelfIndex,
		ProposalHash:       prop.ProposalHash,
		Timestamp:          time.Now().UnixMilli(),
		SenderPublicKeyHex: hex.EncodeToString(inst.PublicKey),
	}

	sig := ed25519.Sign(inst.PrivateKey, echo.CanonicalPayload())
	echo.SignatureHex = hex.EncodeToString(sig)
	inst.SentEcho[inst.Round] = true

	// Record local echo
	inst.ensureEchoMap(inst.Round, prop.ProposalHash)
	inst.ReceivedEchos[inst.Round][prop.ProposalHash][inst.SelfID] = echo

	return echo, nil
}

// ProcessProposalEcho records an ECHO message. If quorum ceil((n+t+1)/2) is met, returns READY message.
func (inst *HybridDKGInstance) ProcessProposalEcho(echo *ProposalEchoMessage) (*ProposalReadyMessage, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !echo.Verify() {
		return nil, errors.New("invalid signature on proposal echo")
	}

	inst.ensureEchoMap(echo.Round, echo.ProposalHash)
	if _, exists := inst.ReceivedEchos[echo.Round][echo.ProposalHash][echo.SenderID]; exists {
		return nil, ErrDuplicateVoteFromPeer
	}
	inst.ReceivedEchos[echo.Round][echo.ProposalHash][echo.SenderID] = echo

	// Check ECHO quorum: ceil((n + t + 1) / 2)
	echoQuorum := (inst.N + inst.T + 1 + 1) / 2
	count := len(inst.ReceivedEchos[echo.Round][echo.ProposalHash])

	if count >= echoQuorum && !inst.SentReady[echo.Round] {
		ready := &ProposalReadyMessage{
			SessionID:          inst.SessionID,
			CommitteeID:        inst.CommitteeID,
			Round:              echo.Round,
			SenderID:           inst.SelfID,
			SenderIndex:        inst.SelfIndex,
			ProposalHash:       echo.ProposalHash,
			Timestamp:          time.Now().UnixMilli(),
			SenderPublicKeyHex: hex.EncodeToString(inst.PublicKey),
		}

		sig := ed25519.Sign(inst.PrivateKey, ready.CanonicalPayload())
		ready.SignatureHex = hex.EncodeToString(sig)
		inst.SentReady[echo.Round] = true

		inst.ensureReadyMap(echo.Round, echo.ProposalHash)
		inst.ReceivedReadys[echo.Round][echo.ProposalHash][inst.SelfID] = ready

		return ready, nil
	}
	return nil, nil
}

// ProcessProposalReady records a READY message. Handles amplification and final decision (Figure 2).
func (inst *HybridDKGInstance) ProcessProposalReady(ready *ProposalReadyMessage) (agreedQUAL []string, decided bool, readyToSend *ProposalReadyMessage, err error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !ready.Verify() {
		return nil, false, nil, errors.New("invalid signature on proposal ready")
	}

	inst.ensureReadyMap(ready.Round, ready.ProposalHash)
	if _, exists := inst.ReceivedReadys[ready.Round][ready.ProposalHash][ready.SenderID]; exists {
		return nil, false, nil, ErrDuplicateVoteFromPeer
	}
	inst.ReceivedReadys[ready.Round][ready.ProposalHash][ready.SenderID] = ready

	count := len(inst.ReceivedReadys[ready.Round][ready.ProposalHash])

	// Amplification rule: upon receiving t + 1 READY messages, send READY if not sent
	if count >= inst.T+1 && !inst.SentReady[ready.Round] {
		readyMsg := &ProposalReadyMessage{
			SessionID:          inst.SessionID,
			CommitteeID:        inst.CommitteeID,
			Round:              ready.Round,
			SenderID:           inst.SelfID,
			SenderIndex:        inst.SelfIndex,
			ProposalHash:       ready.ProposalHash,
			Timestamp:          time.Now().UnixMilli(),
			SenderPublicKeyHex: hex.EncodeToString(inst.PublicKey),
		}
		sig := ed25519.Sign(inst.PrivateKey, readyMsg.CanonicalPayload())
		readyMsg.SignatureHex = hex.EncodeToString(sig)
		inst.SentReady[ready.Round] = true
		inst.ReceivedReadys[ready.Round][ready.ProposalHash][inst.SelfID] = readyMsg
		readyToSend = readyMsg
	}

	// Decision rule: upon receiving 2t + f + 1 READY messages, decide Q
	decisionQuorum := 2*inst.T + inst.F + 1
	if inst.F == 0 {
		decisionQuorum = 2*inst.T + 1
	}

	if count >= decisionQuorum && !inst.IsDecided {
		prop := inst.Proposals[ready.Round]
		if prop != nil && prop.ProposalHash == ready.ProposalHash {
			inst.IsDecided = true
			inst.DecidedQUAL = prop.QualifiedSet
			inst.DecidedProposalHash = ready.ProposalHash
			return inst.DecidedQUAL, true, readyToSend, nil
		}
	}

	return nil, false, readyToSend, nil
}

// SuspectLeader initiates the pessimistic leader-change procedure for current round (Figure 3).
func (inst *HybridDKGInstance) SuspectLeader(reason string) (*LeaderChangeMessage, error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if inst.IsDecided {
		return nil, ErrAlreadyDecided
	}
	if inst.SentLeaderChange[inst.Round] {
		return nil, nil
	}

	lc := &LeaderChangeMessage{
		SessionID:           inst.SessionID,
		CommitteeID:         inst.CommitteeID,
		Round:               inst.Round,
		AccuserNodeID:       inst.SelfID,
		AccuserIndex:        inst.SelfIndex,
		SuspectedLeaderID:   inst.CurrentLeader,
		Reason:              reason,
		Timestamp:           time.Now().UnixMilli(),
		AccuserPublicKeyHex: hex.EncodeToString(inst.PublicKey),
	}

	sig := ed25519.Sign(inst.PrivateKey, lc.CanonicalPayload())
	lc.SignatureHex = hex.EncodeToString(sig)

	inst.SentLeaderChange[inst.Round] = true
	inst.ensureLeaderChangeMap(inst.Round)
	inst.LeaderChangeVotes[inst.Round][inst.SelfID] = lc

	return lc, nil
}

// ProcessLeaderChange records a leader-change accusation. Handles echoing and rotation (Figure 3).
func (inst *HybridDKGInstance) ProcessLeaderChange(lc *LeaderChangeMessage) (newRound int, newLeader string, changed bool, echoLC *LeaderChangeMessage, err error) {
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !lc.Verify() {
		return inst.Round, inst.CurrentLeader, false, nil, errors.New("invalid signature on leader change message")
	}

	inst.ensureLeaderChangeMap(lc.Round)
	if _, exists := inst.LeaderChangeVotes[lc.Round][lc.AccuserNodeID]; exists {
		return inst.Round, inst.CurrentLeader, false, nil, ErrDuplicateVoteFromPeer
	}
	inst.LeaderChangeVotes[lc.Round][lc.AccuserNodeID] = lc

	count := len(inst.LeaderChangeVotes[lc.Round])

	// Amplification rule: on t + 1 accusations for current round, echo complaint if not yet sent
	if lc.Round == inst.Round && count >= inst.T+1 && !inst.SentLeaderChange[inst.Round] {
		echo := &LeaderChangeMessage{
			SessionID:           inst.SessionID,
			CommitteeID:         inst.CommitteeID,
			Round:               inst.Round,
			AccuserNodeID:       inst.SelfID,
			AccuserIndex:        inst.SelfIndex,
			SuspectedLeaderID:   inst.CurrentLeader,
			Reason:              "echo_t_plus_1_suspicion",
			Timestamp:           time.Now().UnixMilli(),
			AccuserPublicKeyHex: hex.EncodeToString(inst.PublicKey),
		}
		sig := ed25519.Sign(inst.PrivateKey, echo.CanonicalPayload())
		echo.SignatureHex = hex.EncodeToString(sig)
		inst.SentLeaderChange[inst.Round] = true
		inst.LeaderChangeVotes[inst.Round][inst.SelfID] = echo
		echoLC = echo
	}

	// Rotation rule: on 2t + 1 (or 2t + f + 1) accusations, advance round and rotate leader
	changeQuorum := 2*inst.T + 1
	if inst.F > 0 {
		changeQuorum = 2*inst.T + inst.F + 1
	}

	if lc.Round == inst.Round && count >= changeQuorum && !inst.IsDecided {
		inst.Round++
		inst.CurrentLeader = inst.getLeaderForRound(inst.Round)
		return inst.Round, inst.CurrentLeader, true, echoLC, nil
	}

	return inst.Round, inst.CurrentLeader, false, echoLC, nil
}

// CombineDKGShares implements Section 5.3 of Kate-Huang-Goldberg (uniform-randomness key combination):
// 1. x_j = \sum_{d \in QUAL} s_{d, j} mod q
// 2. x'_j = \sum_{d \in QUAL} s'_{d, j} mod q
// 3. Y = \sum_{d \in QUAL} Y_d = \sum_{d \in QUAL} \phi_d(0, 0) * G
// 4. C = \sum_{d \in QUAL} C^{(d)}_{0, 0} = x * G + x' * H
// 5. Verifies local share commitment Q_j matches aggregated matrix commitments.
func (inst *HybridDKGInstance) CombineDKGShares(
	agreedQUAL []string,
	vssShares map[string]*avss.Session,
	peerCommitments map[string]*cryptography.CurvePoint,
	peerCommitmentMatrices map[string]*avss.CommitmentMatrix,
	peerPublicKeys map[string]*cryptography.CurvePoint,
) (*HybridDKGResult, error) {
	inst.mu.RLock()
	defer inst.mu.RUnlock()

	minDealers := inst.N - inst.T - inst.F
	if len(agreedQUAL) < minDealers {
		return nil, fmt.Errorf("%w: agreed set size %d < required %d",
			ErrQualifiedSetTooSmall, len(agreedQUAL), minDealers)
	}

	sortedQUAL := make([]string, len(agreedQUAL))
	copy(sortedQUAL, agreedQUAL)
	sort.Strings(sortedQUAL)

	curve := inst.GetCurve()
	if inst.Curve == "" {
		for _, v := range vssShares {
			if v != nil && v.Curve != "" {
				curve = v.Curve
				break
			}
		}
	}
	ord := cryptography.GetCurveOrder(curve)
	combinedShare := cryptography.NewFieldElementWithOrder(0, ord)
	combinedBlind := cryptography.NewFieldElementWithOrder(0, ord)

	for _, dealerID := range sortedQUAL {
		vssSess, exists := vssShares[dealerID]
		if !exists || vssSess.Share == nil || vssSess.BlindShare == nil {
			return nil, fmt.Errorf("missing verified AVSS share from qualified dealer: %s", dealerID)
		}
		combinedShare = combinedShare.Add(vssSess.Share)
		combinedBlind = combinedBlind.Add(vssSess.BlindShare)
	}

	// 3. Master Secret Commitment: C = \sum_{d \in QUAL} C^{(d)}_{0,0}
	masterSecretCommit := cryptography.ZeroPointForCurve(curve)
	for _, dealerID := range sortedQUAL {
		commit, exists := peerCommitments[dealerID]
		if !exists || commit == nil {
			return nil, fmt.Errorf("missing secret commitment for qualified dealer: %s", dealerID)
		}
		masterSecretCommit = masterSecretCommit.Add(commit)
	}

	// 4. Master Signing Public Key: Y = \sum_{d \in QUAL} V_d = x * G
	masterSigningPubKey := cryptography.ZeroPointForCurve(curve)
	hasExplicitPublicKeys := true
	for _, dealerID := range sortedQUAL {
		pk, exists := peerPublicKeys[dealerID]
		if !exists || pk == nil || !pk.IsOnCurve() {
			hasExplicitPublicKeys = false
			break
		}
		masterSigningPubKey = masterSigningPubKey.Add(pk)
	}
	if !hasExplicitPublicKeys || !masterSigningPubKey.IsOnCurve() {
		masterSigningPubKey = masterSecretCommit
	}

	// 5. Local Share Commitment: Q_j = x_j * G + x'_j * H
	shareCommitment := cryptography.PedersenCommitment(combinedShare, combinedBlind)

	// Mathematical consistency verification against commitment matrices
	selfIdxFE := cryptography.NewFieldElementWithOrder(int64(inst.SelfIndex), ord)
	expectedShareCommit := cryptography.ZeroPointForCurve(curve)
	for _, dealerID := range sortedQUAL {
		cm := peerCommitmentMatrices[dealerID]
		if cm == nil {
			return nil, fmt.Errorf("missing commitment matrix for qualified dealer: %s", dealerID)
		}
		expectedShareCommit = expectedShareCommit.Add(cm.ComputeShareCommitment(selfIdxFE))
	}

	if !shareCommitment.Equal(expectedShareCommit) {
		return nil, errors.New("cryptographic consistency failed: share commitment does not match aggregated matrix commitments")
	}

	propHash := inst.DecidedProposalHash
	if propHash == "" {
		propHash = ComputeProposalHash(inst.SessionID, inst.CommitteeID, inst.Round, inst.CurrentLeader, sortedQUAL)
	}

	return &HybridDKGResult{
		AgreedQUAL:             sortedQUAL,
		ProposalHash:           propHash,
		CombinedShare:          combinedShare,
		CombinedBlindShare:     combinedBlind,
		MasterSigningPublicKey: masterSigningPubKey,
		MasterSecretCommitment: masterSecretCommit,
		LocalShareCommitment:   shareCommitment,
	}, nil
}

func (inst *HybridDKGInstance) ensureEchoMap(round int, hash string) {
	if inst.ReceivedEchos[round] == nil {
		inst.ReceivedEchos[round] = make(map[string]map[string]*ProposalEchoMessage)
	}
	if inst.ReceivedEchos[round][hash] == nil {
		inst.ReceivedEchos[round][hash] = make(map[string]*ProposalEchoMessage)
	}
}

func (inst *HybridDKGInstance) ensureReadyMap(round int, hash string) {
	if inst.ReceivedReadys[round] == nil {
		inst.ReceivedReadys[round] = make(map[string]map[string]*ProposalReadyMessage)
	}
	if inst.ReceivedReadys[round][hash] == nil {
		inst.ReceivedReadys[round][hash] = make(map[string]*ProposalReadyMessage)
	}
}

func (inst *HybridDKGInstance) ensureLeaderChangeMap(round int) {
	if inst.LeaderChangeVotes[round] == nil {
		inst.LeaderChangeVotes[round] = make(map[string]*LeaderChangeMessage)
	}
}

