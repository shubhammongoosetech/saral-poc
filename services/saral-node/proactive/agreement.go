package proactive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	ErrPredicateFailed     = errors.New("validated agreement predicate failed")
	ErrAgreementAlreadyDone = errors.New("agreement already decided")
)

// HashCandidateSet computes deterministic SHA-256 hash of a candidate set
func HashCandidateSet(set []string) string {
	sorted := make([]string, len(set))
	copy(sorted, set)
	sort.Strings(sorted)

	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
		h.Write([]byte{':'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ValidityPredicate checks if candidate set S satisfies the research predicate:
// |S| >= requiredQuorum and all dealers in S are in the authorized committee
type ValidityPredicate func(candidateSet []string) bool

// ValidatedAgreementInstance executes one instance of Asynchronous Validated Byzantine Agreement
type ValidatedAgreementInstance struct {
	CommitteeID    string
	Epoch          uint64
	SelfID         string
	Committee      []string
	N              int
	T              int
	RequiredQuorum int // typically 2t+1 or k
	Predicate      ValidityPredicate

	proposals map[string][]string        // hash -> candidate set
	echos     map[string]map[string]bool // hash -> set of senderIDs
	readys    map[string]map[string]bool // hash -> set of senderIDs

	sentEcho  bool
	sentReady bool

	DecidedSet  []string
	DecidedHash string
	IsDecided   bool

	mu sync.RWMutex
}

// NewValidatedAgreementInstance creates an agreement instance
func NewValidatedAgreementInstance(
	committeeID string,
	epoch uint64,
	selfID string,
	committee []string,
	n, t, requiredQuorum int,
	predicate ValidityPredicate,
) *ValidatedAgreementInstance {
	return &ValidatedAgreementInstance{
		CommitteeID:    committeeID,
		Epoch:          epoch,
		SelfID:         selfID,
		Committee:      committee,
		N:              n,
		T:              t,
		RequiredQuorum: requiredQuorum,
		Predicate:      predicate,
		proposals:      make(map[string][]string),
		echos:          make(map[string]map[string]bool),
		readys:         make(map[string]map[string]bool),
	}
}

// ProcessProposal evaluates a proposal against the validity predicate and produces an ECHO if valid
func (v *ValidatedAgreementInstance) ProcessProposal(msg *AgreementProposeMessage) (*AgreementEchoMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.IsDecided {
		return nil, ErrAgreementAlreadyDone
	}

	// 1. Quorum size check
	if len(msg.CandidateSet) < v.RequiredQuorum {
		return nil, fmt.Errorf("%w: candidate set size %d < required quorum %d",
			ErrPredicateFailed, len(msg.CandidateSet), v.RequiredQuorum)
	}

	// 2. Validate against external predicate (verifying AVSS commitments match previous shares)
	if v.Predicate != nil && !v.Predicate(msg.CandidateSet) {
		return nil, fmt.Errorf("%w: candidate set failed AVSS commitment verification", ErrPredicateFailed)
	}

	propHash := HashCandidateSet(msg.CandidateSet)
	v.proposals[propHash] = msg.CandidateSet

	// Generate ECHO if not yet sent
	if !v.sentEcho {
		v.sentEcho = true
		return &AgreementEchoMessage{
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: propHash,
		}, nil
	}

	return nil, nil
}

// ProcessEcho processes an ECHO message. Returns READY message if quorum of ECHOs (>= n - t) is reached.
func (v *ValidatedAgreementInstance) ProcessEcho(echo *AgreementEchoMessage) (*AgreementReadyMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.echos[echo.ProposalHash] == nil {
		v.echos[echo.ProposalHash] = make(map[string]bool)
	}
	v.echos[echo.ProposalHash][echo.SenderID] = true

	// Check if >= n - t ECHOs received for this proposal
	if !v.sentReady && len(v.echos[echo.ProposalHash]) >= v.N-v.T {
		v.sentReady = true
		return &AgreementReadyMessage{
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: echo.ProposalHash,
		}, nil
	}

	return nil, nil
}

// ProcessReady processes a READY message. Decides if quorum of READYs (>= 2t + 1) is reached.
func (v *ValidatedAgreementInstance) ProcessReady(ready *AgreementReadyMessage) ([]string, bool, *AgreementReadyMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.readys[ready.ProposalHash] == nil {
		v.readys[ready.ProposalHash] = make(map[string]bool)
	}
	v.readys[ready.ProposalHash][ready.SenderID] = true

	var readyToSend *AgreementReadyMessage
	// Amplification rule: if >= t + 1 READYs received and not yet sent READY
	if !v.sentReady && len(v.readys[ready.ProposalHash]) >= v.T+1 {
		v.sentReady = true
		readyToSend = &AgreementReadyMessage{
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: ready.ProposalHash,
		}
	}

	// Decision rule: if >= 2t + 1 READYs received
	if !v.IsDecided && len(v.readys[ready.ProposalHash]) >= 2*v.T+1 {
		candidateSet, exists := v.proposals[ready.ProposalHash]
		if exists {
			v.DecidedSet = candidateSet
			v.DecidedHash = ready.ProposalHash
			v.IsDecided = true
			return v.DecidedSet, true, readyToSend, nil
		}
	}

	return nil, false, readyToSend, nil
}

