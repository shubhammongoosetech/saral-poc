package dkg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

const (
	MessageTypeHybridDKGProposal     = "HYBRID_DKG_PROPOSAL"
	MessageTypeHybridDKGEcho         = "HYBRID_DKG_ECHO"
	MessageTypeHybridDKGReady        = "HYBRID_DKG_READY"
	MessageTypeHybridDKGLeaderChange = "HYBRID_DKG_LEADER_CHANGE"
	MessageTypeHybridDKGRecovery     = "HYBRID_DKG_RECOVERY"
)

// ValidityCertificate is issued by a participant when a dealer's HybridVSS instance completes.
// Under Section 5.1 of Kate-Huang-Goldberg (ACNS 2012):
// The leader collects validity certificates from at least t+1 nodes for each dealer in the qualified set.
type ValidityCertificate struct {
	SessionID          string `json:"sessionId"`
	DealerID           string `json:"dealerId"`
	SignerNodeID       string `json:"signerNodeId"`
	SignerIndex        int    `json:"signerIndex"`
	CommitmentsHash    string `json:"commitmentsHash"`
	Epoch              uint64 `json:"epoch"`
	Timestamp          int64  `json:"timestamp"`
	SignatureHex       string `json:"signatureHex"`
	SignerPublicKeyHex string `json:"signerPublicKeyHex"`
}

// CanonicalPayload returns the canonical byte representation of the certificate for Ed25519 signing.
func (vc *ValidityCertificate) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("%s:%s:%s:%s:%d",
		vc.SessionID, vc.DealerID, vc.SignerNodeID, vc.CommitmentsHash, vc.Epoch))
}

// Verify checks the validity certificate's cryptographic Ed25519 signature.
func (vc *ValidityCertificate) Verify() bool {
	if vc.SignatureHex == "" || vc.SignerPublicKeyHex == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(vc.SignerPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(vc.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubBytes, vc.CanonicalPayload(), sigBytes)
}

// LeaderProposalMessage represents the leader's proposal of the Qualified Set QUAL
// in the optimistic phase (Figure 2 of Kate-Huang-Goldberg).
type LeaderProposalMessage struct {
	SessionID          string                           `json:"sessionId"`
	CommitteeID        string                           `json:"committeeId"`
	Round              int                              `json:"round"`
	LeaderID           string                           `json:"leaderId"`
	LeaderIndex        int                              `json:"leaderIndex"`
	QualifiedSet       []string                         `json:"qualifiedSet"` // Set Q of dealers
	Certificates       map[string][]ValidityCertificate `json:"certificates"` // DealerID -> certs
	ProposalHash       string                           `json:"proposalHash"`
	Timestamp          int64                            `json:"timestamp"`
	SignatureHex       string                           `json:"signatureHex"`
	LeaderPublicKeyHex string                           `json:"leaderPublicKeyHex"`
}

// ComputeProposalHash computes deterministic SHA-256 hash of the leader's proposal.
func ComputeProposalHash(sessionID, committeeID string, round int, leaderID string, qualifiedSet []string) string {
	sorted := make([]string, len(qualifiedSet))
	copy(sorted, qualifiedSet)
	sort.Strings(sorted)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%d:%s:%s", sessionID, committeeID, round, leaderID, strings.Join(sorted, ","))))
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalPayload returns the canonical bytes for the proposal signature.
func (lp *LeaderProposalMessage) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("PROPOSAL:%s:%s:%d:%s:%s",
		lp.SessionID, lp.CommitteeID, lp.Round, lp.LeaderID, lp.ProposalHash))
}

// Verify checks the leader's Ed25519 signature on the proposal.
func (lp *LeaderProposalMessage) Verify() bool {
	if lp.SignatureHex == "" || lp.LeaderPublicKeyHex == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(lp.LeaderPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(lp.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	expectedHash := ComputeProposalHash(lp.SessionID, lp.CommitteeID, lp.Round, lp.LeaderID, lp.QualifiedSet)
	if lp.ProposalHash != expectedHash {
		return false
	}
	return ed25519.Verify(pubBytes, lp.CanonicalPayload(), sigBytes)
}

// ProposalEchoMessage is broadcast by nodes upon validating the leader's proposal (Figure 2).
type ProposalEchoMessage struct {
	SessionID          string `json:"sessionId"`
	CommitteeID        string `json:"committeeId"`
	Round              int    `json:"round"`
	SenderID           string `json:"senderId"`
	SenderIndex        int    `json:"senderIndex"`
	ProposalHash       string `json:"proposalHash"`
	Timestamp          int64  `json:"timestamp"`
	SignatureHex       string `json:"signatureHex"`
	SenderPublicKeyHex string `json:"senderPublicKeyHex"`
}

func (pe *ProposalEchoMessage) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("ECHO:%s:%s:%d:%s:%s",
		pe.SessionID, pe.CommitteeID, pe.Round, pe.SenderID, pe.ProposalHash))
}

func (pe *ProposalEchoMessage) Verify() bool {
	if pe.SignatureHex == "" || pe.SenderPublicKeyHex == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(pe.SenderPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(pe.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubBytes, pe.CanonicalPayload(), sigBytes)
}

// ProposalReadyMessage is broadcast by nodes when enough ECHOs/READYs are gathered (Figure 2).
type ProposalReadyMessage struct {
	SessionID          string `json:"sessionId"`
	CommitteeID        string `json:"committeeId"`
	Round              int    `json:"round"`
	SenderID           string `json:"senderId"`
	SenderIndex        int    `json:"senderIndex"`
	ProposalHash       string `json:"proposalHash"`
	Timestamp          int64  `json:"timestamp"`
	SignatureHex       string `json:"signatureHex"`
	SenderPublicKeyHex string `json:"senderPublicKeyHex"`
}

func (pr *ProposalReadyMessage) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("READY:%s:%s:%d:%s:%s",
		pr.SessionID, pr.CommitteeID, pr.Round, pr.SenderID, pr.ProposalHash))
}

func (pr *ProposalReadyMessage) Verify() bool {
	if pr.SignatureHex == "" || pr.SenderPublicKeyHex == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(pr.SenderPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(pr.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubBytes, pr.CanonicalPayload(), sigBytes)
}

// LeaderChangeMessage is broadcast during the pessimistic phase when the leader fails (Figure 3).
type LeaderChangeMessage struct {
	SessionID          string `json:"sessionId"`
	CommitteeID        string `json:"committeeId"`
	Round              int    `json:"round"`
	AccuserNodeID      string `json:"accuserNodeId"`
	AccuserIndex       int    `json:"accuserIndex"`
	SuspectedLeaderID  string `json:"suspectedLeaderId"`
	Reason             string `json:"reason"`
	Timestamp          int64  `json:"timestamp"`
	SignatureHex       string `json:"signatureHex"`
	AccuserPublicKeyHex string `json:"accuserPublicKeyHex"`
}

func (lc *LeaderChangeMessage) CanonicalPayload() []byte {
	return []byte(fmt.Sprintf("LEADER_CHANGE:%s:%s:%d:%s:%s:%s",
		lc.SessionID, lc.CommitteeID, lc.Round, lc.AccuserNodeID, lc.SuspectedLeaderID, lc.Reason))
}

func (lc *LeaderChangeMessage) Verify() bool {
	if lc.SignatureHex == "" || lc.AccuserPublicKeyHex == "" {
		return false
	}
	pubBytes, err := hex.DecodeString(lc.AccuserPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(lc.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubBytes, lc.CanonicalPayload(), sigBytes)
}

// HybridDKGResult encapsulates the output of Section 5.3 key combination.
type HybridDKGResult struct {
	AgreedQUAL             []string
	ProposalHash           string
	CombinedShare          *cryptography.FieldElement
	CombinedBlindShare     *cryptography.FieldElement
	MasterSigningPublicKey *cryptography.CurvePoint // Y = x * G (Genuine unblinded signing public key)
	MasterSecretCommitment *cryptography.CurvePoint // C = x * G + x' * H (Pedersen commitment)
	LocalShareCommitment   *cryptography.CurvePoint // Q_j = x_j * G + x'_j * H
}

