package dkg

import (
	"errors"
	"fmt"
)

// DKGState represents the lifecycle phase of a Dealerless DKG session
type DKGState string

const (
	StateCreated                 DKGState = "CREATED"
	StateParticipantsRegistered  DKGState = "PARTICIPANTS_REGISTERED"
	StateContributionsStarted    DKGState = "CONTRIBUTIONS_STARTED"
	StateAVSSSharing             DKGState = "AVSS_SHARING"
	StateContributionsVerified   DKGState = "CONTRIBUTIONS_VERIFIED"
	StateQualifiedSetAgreement   DKGState = "QUALIFIED_SET_AGREEMENT"
	StateSharesAggregated        DKGState = "SHARES_AGGREGATED"
	StatePublicKeyVerified       DKGState = "PUBLIC_KEY_VERIFIED"
	StateCompleted               DKGState = "COMPLETED"
	StateFailed                  DKGState = "FAILED"
)

// DKG Protocol Relay Message Types
const (
	MessageTypeDKGInit           = "DKG_INIT"
	MessageTypeDKGContribution   = "DKG_CONTRIBUTION"
	MessageTypeDKGAVSSComplete   = "DKG_AVSS_COMPLETE"
	MessageTypeDKGQualifiedSet   = "DKG_QUALIFIED_SET"
	MessageTypeDKGAgreement      = "DKG_AGREEMENT"
	MessageTypeDKGPublicKey      = "DKG_PUBLIC_KEY"
	MessageTypeDKGComplete       = "DKG_COMPLETE"
	MessageTypeDKGAbort          = "DKG_ABORT"
)

var (
	ErrDKGAlreadyRunning       = errors.New("dkg session already running")
	ErrDKGSessionNotFound      = errors.New("dkg session not found")
	ErrInvalidDKGParameters    = errors.New("invalid dkg parameters")
	ErrInsufficientDealers     = errors.New("insufficient valid dealers for qualified set")
	ErrDKGPredicateFailed      = errors.New("dkg qualified set agreement predicate failed")
	ErrPublicKeyMismatch       = errors.New("aggregated public key verification mismatch")
	ErrUnauthorizedDKGRequest  = errors.New("unauthorized dkg operation")
)

// ValidateDKGParameters validates the cryptographic parameter constraints for DKG:
// 1. n > 3*t (Asynchronous Byzantine Consensus bound)
// 2. n - 2*t >= k (AVSS reconstruction bound)
// 3. k >= t + 1 (Fault tolerance: reconstruction threshold requires at least one honest participant)
func ValidateDKGParameters(n, k, t int) error {
	if n <= 0 || k <= 0 || t <= 0 {
		return fmt.Errorf("%w: n, k, and t must be positive integers (got n=%d, k=%d, t=%d)",
			ErrInvalidDKGParameters, n, k, t)
	}
	if n <= 3*t {
		return fmt.Errorf("%w: asynchronous consensus requires n > 3t (got n=%d, t=%d, 3t=%d)",
			ErrInvalidDKGParameters, n, t, 3*t)
	}
	if n-2*t < k {
		return fmt.Errorf("%w: dual-threshold AVSS requires n - 2t >= k (got %d - 2*%d = %d < %d)",
			ErrInvalidDKGParameters, n, t, n-2*t, k)
	}
	if k < t+1 {
		return fmt.Errorf("%w: threshold k must be at least t + 1 (got k=%d, t=%d)",
			ErrInvalidDKGParameters, k, t)
	}
	return nil
}

// DKGInitMessage initializes a DKG session across the committee
type DKGInitMessage struct {
	SessionID   string   `json:"sessionId"`
	CommitteeID string   `json:"committeeId"`
	Epoch       uint64   `json:"epoch"`
	N           int      `json:"n"`
	K           int      `json:"k"`
	T           int      `json:"t"`
	Committee   []string `json:"committee"`
	Timestamp   int64    `json:"timestamp"`
}

// DKGContributionMessage announces a node's AVSS contribution commitment matrix
type DKGContributionMessage struct {
	SessionID           string     `json:"sessionId"`
	CommitteeID         string     `json:"committeeId"`
	DealerID            string     `json:"dealerId"`
	DealerIndex         int        `json:"dealerIndex"`
	SecretCommitment    string     `json:"secretCommitment"`    // C_{0,0} hex (Pedersen: z_i*G + z'_i*H)
	PublicKeyCommitment string     `json:"publicKeyCommitment"` // V_i hex (Feldman/signing: z_i*G)
	CommitmentMatrix    [][]string `json:"commitmentMatrix"`    // hex matrix
	Timestamp           int64      `json:"timestamp"`
}

// DKGAVSSCompleteMessage signals that a node has completed verification of a peer's AVSS sharing
type DKGAVSSCompleteMessage struct {
	SessionID   string `json:"sessionId"`
	CommitteeID string `json:"committeeId"`
	NodeID      string `json:"nodeId"`
	DealerID    string `json:"dealerId"`
	Timestamp   int64  `json:"timestamp"`
}

// DKGQualifiedSetMessage proposes or announces an agreed qualified contributor set
type DKGQualifiedSetMessage struct {
	SessionID    string   `json:"sessionId"`
	CommitteeID  string   `json:"committeeId"`
	ProposerID   string   `json:"proposerId"`
	QualifiedSet []string `json:"qualifiedSet"`
	Timestamp    int64    `json:"timestamp"`
}

// DKGPublicKeyMessage broadcasts a node's derived public share commitment and master public key
type DKGPublicKeyMessage struct {
	SessionID        string `json:"sessionId"`
	CommitteeID      string `json:"committeeId"`
	NodeID           string `json:"nodeId"`
	NodeIndex        int    `json:"nodeIndex"`
	PublicShareCommit string `json:"publicShareCommit"`
	MasterPublicKey  string `json:"masterPublicKey"`
	Timestamp        int64  `json:"timestamp"`
}

// DKGCompleteNotification notifies coordinators that a node has successfully finalized DKG
type DKGCompleteNotification struct {
	SessionID       string   `json:"sessionId"`
	CommitteeID     string   `json:"committeeId"`
	NodeID          string   `json:"nodeId"`
	QualifiedSet    []string `json:"qualifiedSet"`
	MasterPublicKey string   `json:"masterPublicKey"`
	Timestamp       int64    `json:"timestamp"`
}

// DKGParticipantStatus records public participant progress
type DKGParticipantStatus struct {
	NodeID             string `json:"nodeId"`
	NodeIndex          int    `json:"nodeIndex"`
	ContributionDealt  bool   `json:"contributionDealt"`
	SecretCommitment   string `json:"secretCommitment,omitempty"`
	CompletedSharings  int    `json:"completedSharings"`
	InQualifiedSet     bool   `json:"inQualifiedSet"`
	ShareAggregated    bool   `json:"shareAggregated"`
	PublicShareCommit  string `json:"publicShareCommit,omitempty"`
	Status             string `json:"status"` // PENDING | CONTRIBUTED | QUALIFIED | FINALIZED | FAILED
}

// DKGSessionPublicView represents public session metadata exposed over RPC / SDK
type DKGSessionPublicView struct {
	SessionID              string                           `json:"sessionId"`
	CommitteeID            string                           `json:"committeeId"`
	Epoch                  uint64                           `json:"epoch"`
	N                      int                              `json:"n"`
	K                      int                              `json:"k"`
	T                      int                              `json:"t"`
	State                  DKGState                         `json:"state"`
	Committee              []string                         `json:"committee"`
	QualifiedSet           []string                         `json:"qualifiedSet,omitempty"`
	MasterSigningPublicKey string                           `json:"masterSigningPublicKey,omitempty"` // Y = x * G (real signing key)
	MasterSecretCommitment string                           `json:"masterSecretCommitment,omitempty"` // C = x * G + x' * H (Pedersen commitment)
	MasterPublicKey        string                           `json:"masterPublicKey,omitempty"`        // signing key
	Curve                  string                           `json:"curve"`
	Participants           map[string]*DKGParticipantStatus `json:"participants"`
	CreatedAt              int64                            `json:"createdAt"`
	UpdatedAt              int64                            `json:"updatedAt"`
	Error                  string                           `json:"error,omitempty"`
}
