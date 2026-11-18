package avss

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

type SessionState string

const (
	StateCreated                 SessionState = "CREATED"
	StateInitialized             SessionState = "INITIALIZED"
	StateDealerDistributing      SessionState = "DEALER_DISTRIBUTING"
	StateVerifyingShares         SessionState = "VERIFYING_SHARES"
	StateEchoCollecting          SessionState = "ECHO_COLLECTING"
	StateReadyCollecting         SessionState = "READY_COLLECTING"
	StateSharingCompleted        SessionState = "SHARING_COMPLETED"
	StateSharingFailed           SessionState = "SHARING_FAILED"
	StateReconstructionRequested SessionState = "RECONSTRUCTION_REQUESTED"
	StateReconstructionCompleted SessionState = "RECONSTRUCTION_COMPLETED"
)

var (
	ErrInvalidSecurityParameters = errors.New("invalid AVSS security parameters: must satisfy n - 2t >= k and k > t")
	ErrSessionAlreadyCompleted   = errors.New("AVSS session already completed")
	ErrSessionFailed             = errors.New("AVSS session failed")
)

// ValidateSecurityParameters validates the Cachin et al. 2002 dual-threshold AVSS bounds:
// n - 2*t >= k and k > t
func ValidateSecurityParameters(n, k, t int) error {
	if t < 0 {
		return fmt.Errorf("%w: t must be >= 0 (got %d)", ErrInvalidSecurityParameters, t)
	}
	if k <= t {
		return fmt.Errorf("%w: k must be strictly greater than t (got k=%d, t=%d)", ErrInvalidSecurityParameters, k, t)
	}
	if n-2*t < k {
		return fmt.Errorf("%w: n - 2t must be >= k (got n=%d, t=%d, k=%d, n-2t=%d)", ErrInvalidSecurityParameters, n, t, k, n-2*t)
	}
	return nil
}

// Session tracks the local node's cryptographic state for a single AVSS instance
type Session struct {
	SessionID   string
	CommitteeID string
	DealerID    string
	SelfID      string
	SelfIndex   int // 1-based index in committee
	Epoch       uint64
	N           int
	K           int
	T           int
	Committee   []string // List of NodeIDs in canonical order

	State     SessionState
	CreatedAt time.Time
	UpdatedAt time.Time
	Error     string

	Commitments     *CommitmentMatrix
	CommitmentsHash string // SHA-256 hash of canonical commitment hex matrix

	RowPoly      *Polynomial
	RowBlindPoly *Polynomial
	ColPoly      *Polynomial
	ColBlindPoly *Polynomial

	// Grid points collected from ECHOs: map[senderID]point
	ReceivedEchos  map[string]*EchoMessage
	ReceivedReadys map[string]*ReadyMessage

	SentEcho  bool
	SentReady bool

	Share                  *cryptography.FieldElement
	BlindShare             *cryptography.FieldElement
	PublicShareCommitment  *cryptography.CurvePoint
	PublicSecretCommitment *cryptography.CurvePoint

	mu sync.RWMutex
}

// NewSession initializes a new AVSS session state machine
func NewSession(
	sessionID, committeeID, dealerID, selfID string,
	selfIndex int,
	epoch uint64,
	n, k, t int,
	committee []string,
) (*Session, error) {
	if err := ValidateSecurityParameters(n, k, t); err != nil {
		return nil, err
	}

	now := time.Now()
	return &Session{
		SessionID:      sessionID,
		CommitteeID:    committeeID,
		DealerID:       dealerID,
		SelfID:         selfID,
		SelfIndex:      selfIndex,
		Epoch:          epoch,
		N:              n,
		K:              k,
		T:              t,
		Committee:      committee,
		State:          StateCreated,
		CreatedAt:      now,
		UpdatedAt:      now,
		ReceivedEchos:  make(map[string]*EchoMessage),
		ReceivedReadys: make(map[string]*ReadyMessage),
	}, nil
}

// HashCommitments computes SHA-256 hash of the commitment matrix for agreement cross-checks
func HashCommitments(hexMatrix [][]string) string {
	h := sha256.New()
	for _, row := range hexMatrix {
		for _, pt := range row {
			h.Write([]byte(pt))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanSendReady checks if the node has gathered enough evidence to broadcast READY:
// (a) Gathered >= n - t valid ECHOs with identical commitments, OR
// (b) Gathered >= t + 1 valid READYs with identical commitments
func (s *Session) CanSendReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.SentReady || (s.RowPoly == nil && len(s.ReceivedEchos) < s.K) {
		return false
	}

	// Count matching ECHOs
	echoCount := 0
	for _, echo := range s.ReceivedEchos {
		if HashCommitments(echo.Commitments) == s.CommitmentsHash {
			echoCount++
		}
	}
	if echoCount >= s.N-s.T {
		return true
	}

	// Count matching READYs
	readyCount := 0
	for _, ready := range s.ReceivedReadys {
		if HashCommitments(ready.Commitments) == s.CommitmentsHash {
			readyCount++
		}
	}
	if readyCount >= s.T+1 {
		return true
	}

	return false
}

// CanComplete checks if the node has received >= k + t valid READYs agreeing on commitments
func (s *Session) CanComplete() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.State == StateSharingCompleted {
		return false
	}
	if s.RowPoly == nil {
		return false
	}

	readyCount := 0
	for _, ready := range s.ReceivedReadys {
		if HashCommitments(ready.Commitments) == s.CommitmentsHash {
			readyCount++
		}
	}

	// Completion predicate: >= k + t READY messages
	return readyCount >= s.K+s.T
}

// FinalizeShare derives and locks in the final secret share S_i = a_i(0)
func (s *Session) FinalizeShare() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.RowPoly == nil || s.RowBlindPoly == nil || s.Commitments == nil {
		return errors.New("cannot finalize share: missing verified polynomial slices")
	}

	// S_i = a_i(0) = RowPoly.Coeffs[0]
	// S'_i = a'_i(0) = RowBlindPoly.Coeffs[0]
	s.Share = s.RowPoly.Coeffs[0]
	s.BlindShare = s.RowBlindPoly.Coeffs[0]

	selfIndexFE := cryptography.NewFieldElement(int64(s.SelfIndex))
	s.PublicShareCommitment = s.Commitments.ComputeShareCommitment(selfIndexFE)
	s.PublicSecretCommitment = s.Commitments.SecretCommitment()

	s.State = StateSharingCompleted
	s.UpdatedAt = time.Now()
	return nil
}

