package proactive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

var (
	ErrPredicateFailed     = errors.New("validated agreement predicate failed")
	ErrAgreementAlreadyDone = errors.New("agreement already decided")
	ErrInvalidSender        = errors.New("sender not in authorized committee")
	ErrDuplicateVote        = errors.New("duplicate vote from participant")
	ErrInvalidCoinShare     = errors.New("invalid common coin share")
	ErrUnknownProposal      = errors.New("proposal hash unknown")
)

const (
	StepPreVote  = 1
	StepMainVote = 2

	VoteReject  = 0
	VoteAccept  = 1
	VoteAbstain = -1
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

// ValidatedAgreementInstance executes an instance of Asynchronous Validated Byzantine Agreement
// implementing randomized Asynchronous Binary Byzantine Agreement (ABBA / CKS00 / CKS05)
// with a threshold common coin over NIST P-256.
type ValidatedAgreementInstance struct {
	SessionID      string
	CommitteeID    string
	Epoch          uint64
	SelfID         string
	Committee      []string
	N              int
	T              int
	RequiredQuorum int // typically 2t+1
	Predicate      ValidityPredicate

	// Threshold Common Coin cryptographic state
	CoinKeyShare *cryptography.CoinKeyShare
	CoinPeerPKs  map[string]*cryptography.CurvePoint
	SessionTag   string

	// Proposal registry: Hash -> CandidateSet, and ProposerID -> Hash
	proposals       map[string][]string
	proposerHashMap map[string]string

	// Fast-path / Reliable Broadcast dispersal state
	echos     map[string]map[string]bool // hash -> senderID -> bool
	readys    map[string]map[string]bool // hash -> senderID -> bool
	sentEcho  bool
	sentReady bool

	// ABBA Consensus State
	CurrentRound int
	// prevotes: round -> candidateHash -> senderID -> voteValue
	prevotes map[int]map[string]map[string]int
	// mainvotes: round -> candidateHash -> senderID -> voteValue
	mainvotes map[int]map[string]map[string]int
	// coinShares: round -> senderID -> CoinShare
	coinShares map[int]map[string]*cryptography.CoinShare

	sentPrevote   map[int]bool
	sentMainvote  map[int]bool
	sentCoinShare map[int]bool

	// Preferred candidate hash locked for future rounds if common coin outputs 1
	lockedCandidate string

	// Agreement Result
	DecidedSet  []string
	DecidedHash string
	IsDecided   bool

	mu sync.RWMutex
}

// NewValidatedAgreementInstance creates an agreement instance with threshold common coin
func NewValidatedAgreementInstance(
	committeeID string,
	epoch uint64,
	selfID string,
	committee []string,
	n, t, requiredQuorum int,
	predicate ValidityPredicate,
) *ValidatedAgreementInstance {
	inst := &ValidatedAgreementInstance{
		CommitteeID:     committeeID,
		Epoch:           epoch,
		SelfID:          selfID,
		Committee:       committee,
		N:               n,
		T:               t,
		RequiredQuorum:  requiredQuorum,
		Predicate:       predicate,
		SessionTag:      fmt.Sprintf("saral-agreement:%s:epoch:%d", committeeID, epoch),
		proposals:       make(map[string][]string),
		proposerHashMap: make(map[string]string),
		echos:           make(map[string]map[string]bool),
		readys:          make(map[string]map[string]bool),
		CurrentRound:    1,
		prevotes:        make(map[int]map[string]map[string]int),
		mainvotes:       make(map[int]map[string]map[string]int),
		coinShares:      make(map[int]map[string]*cryptography.CoinShare),
		sentPrevote:     make(map[int]bool),
		sentMainvote:    make(map[int]bool),
		sentCoinShare:   make(map[int]bool),
	}

	// Auto-initialize threshold common coin keys for committee
	coinSeed := fmt.Sprintf("saral-proactive-coin-%s-epoch-%d", committeeID, epoch)
	shares, _, err := cryptography.SetupThresholdCoinKeys(committeeID, committee, t, coinSeed)
	if err == nil {
		inst.CoinKeyShare = shares[selfID]
		inst.CoinPeerPKs = make(map[string]*cryptography.CurvePoint, n)
		for id, s := range shares {
			inst.CoinPeerPKs[id] = s.PublicKeyShare
		}
	}

	return inst
}

// SetCoinKeys explicitly configures external threshold coin keys
func (v *ValidatedAgreementInstance) SetCoinKeys(keyShare *cryptography.CoinKeyShare, peerPKs map[string]*cryptography.CurvePoint) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.CoinKeyShare = keyShare
	v.CoinPeerPKs = peerPKs
}

// IsMember returns true if nodeID is in the committee
func (v *ValidatedAgreementInstance) isMember(nodeID string) bool {
	for _, m := range v.Committee {
		if m == nodeID {
			return true
		}
	}
	return false
}

// ProcessProposal evaluates a proposal against the validity predicate and produces an ECHO if valid
func (v *ValidatedAgreementInstance) ProcessProposal(msg *AgreementProposeMessage) (*AgreementEchoMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.IsDecided {
		return nil, ErrAgreementAlreadyDone
	}
	if !v.isMember(msg.ProposerID) {
		return nil, ErrInvalidSender
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
	v.proposerHashMap[msg.ProposerID] = propHash

	// Decision rule: if >= 2t + 1 READYs were already received while proposal was in flight
	if !v.IsDecided && len(v.readys[propHash]) >= 2*v.T+1 {
		v.DecidedSet = msg.CandidateSet
		v.DecidedHash = propHash
		v.IsDecided = true
	}

	// Generate ECHO if not yet sent
	if !v.sentEcho {
		v.sentEcho = true
		return &AgreementEchoMessage{
			SessionID:    v.SessionID,
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: propHash,
			Timestamp:    time.Now().UnixMilli(),
		}, nil
	}

	return nil, nil
}

// ProcessEcho processes an ECHO message. Returns READY message if quorum of ECHOs (>= n - t) is reached.
func (v *ValidatedAgreementInstance) ProcessEcho(echo *AgreementEchoMessage) (*AgreementReadyMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isMember(echo.SenderID) {
		return nil, ErrInvalidSender
	}

	if v.echos[echo.ProposalHash] == nil {
		v.echos[echo.ProposalHash] = make(map[string]bool)
	}
	v.echos[echo.ProposalHash][echo.SenderID] = true

	// Check if >= n - t ECHOs received for this proposal
	if !v.sentReady && len(v.echos[echo.ProposalHash]) >= v.N-v.T {
		v.sentReady = true
		return &AgreementReadyMessage{
			SessionID:    v.SessionID,
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: echo.ProposalHash,
			Timestamp:    time.Now().UnixMilli(),
		}, nil
	}

	return nil, nil
}

// ProcessReady processes a READY message. Decides if quorum of READYs (>= 2t + 1) is reached.
func (v *ValidatedAgreementInstance) ProcessReady(ready *AgreementReadyMessage) ([]string, bool, *AgreementReadyMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.isMember(ready.SenderID) {
		return nil, false, nil, ErrInvalidSender
	}

	if v.readys[ready.ProposalHash] == nil {
		v.readys[ready.ProposalHash] = make(map[string]bool)
	}
	v.readys[ready.ProposalHash][ready.SenderID] = true

	var readyToSend *AgreementReadyMessage
	// Amplification rule: if >= t + 1 READYs received and not yet sent READY
	if !v.sentReady && len(v.readys[ready.ProposalHash]) >= v.T+1 {
		v.sentReady = true
		readyToSend = &AgreementReadyMessage{
			SessionID:    v.SessionID,
			CommitteeID:  v.CommitteeID,
			Epoch:        v.Epoch,
			SenderID:     v.SelfID,
			ProposalHash: ready.ProposalHash,
			Timestamp:    time.Now().UnixMilli(),
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

// StartRound begins an ABBA round r with a PRE-VOTE based on designated round leader L_r
func (v *ValidatedAgreementInstance) StartRound(round int) (*AgreementVoteMessage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.IsDecided {
		return nil, ErrAgreementAlreadyDone
	}
	if v.sentPrevote[round] {
		return nil, nil
	}

	// 1. Determine candidate for round r:
	// If a candidate was locked by previous round common coin, continue with locked candidate
	candHash := v.lockedCandidate
	voteVal := VoteAccept

	if candHash == "" {
		// Elect round leader deterministically: L_r = Committee[(round-1) mod n]
		leaderIndex := (round - 1) % v.N
		leaderID := v.Committee[leaderIndex]
		leaderHash, hasLeaderProp := v.proposerHashMap[leaderID]

		if hasLeaderProp {
			candHash = leaderHash
			voteVal = VoteAccept
		} else {
			// If leader has not proposed, deterministically select the first canonical proposal
			if len(v.proposals) > 0 {
				keys := make([]string, 0, len(v.proposals))
				for h := range v.proposals {
					keys = append(keys, h)
				}
				sort.Strings(keys)
				candHash = keys[0]
				voteVal = VoteAccept
			} else {
				voteVal = VoteReject
			}
		}
	}

	v.sentPrevote[round] = true
	msg := &AgreementVoteMessage{
		CommitteeID:   v.CommitteeID,
		Epoch:         v.Epoch,
		Round:         round,
		Step:          StepPreVote,
		SenderID:      v.SelfID,
		CandidateHash: candHash,
		VoteValue:     voteVal,
		Timestamp:     time.Now().UnixMilli(),
	}

	v.recordVote(round, StepPreVote, candHash, v.SelfID, voteVal)
	return msg, nil
}

func (v *ValidatedAgreementInstance) recordVote(round, step int, candHash, senderID string, voteVal int) {
	var targetMap map[int]map[string]map[string]int
	if step == StepPreVote {
		targetMap = v.prevotes
	} else {
		targetMap = v.mainvotes
	}

	if targetMap[round] == nil {
		targetMap[round] = make(map[string]map[string]int)
	}
	if targetMap[round][candHash] == nil {
		targetMap[round][candHash] = make(map[string]int)
	}
	targetMap[round][candHash][senderID] = voteVal
}

// ProcessVote processes incoming PRE-VOTE or MAIN-VOTE messages in randomized ABBA consensus
func (v *ValidatedAgreementInstance) ProcessVote(msg *AgreementVoteMessage) (
	nextVote *AgreementVoteMessage,
	coinShareMsg *AgreementCoinShareMessage,
	decided bool,
	decidedSet []string,
	err error,
) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.IsDecided {
		return nil, nil, true, v.DecidedSet, nil
	}
	if !v.isMember(msg.SenderID) {
		return nil, nil, false, nil, ErrInvalidSender
	}

	round := msg.Round
	step := msg.Step

	var currentVotes map[int]map[string]map[string]int
	if step == StepPreVote {
		currentVotes = v.prevotes
	} else {
		currentVotes = v.mainvotes
	}

	// Duplicate & Byzantine equivocation check
	if currentVotes[round] != nil {
		for h, senderMap := range currentVotes[round] {
			if _, exists := senderMap[msg.SenderID]; exists {
				if h != msg.CandidateHash || senderMap[msg.SenderID] != msg.VoteValue {
					return nil, nil, false, nil, fmt.Errorf("byzantine equivocation detected from %s", msg.SenderID)
				}
				// Duplicate identical vote: silently ignore
				return nil, nil, false, nil, nil
			}
		}
	}

	v.recordVote(round, step, msg.CandidateHash, msg.SenderID, msg.VoteValue)

	// Evaluate Step 1: PRE-VOTE completion -> produce MAIN-VOTE
	if step == StepPreVote && !v.sentMainvote[round] {
		totalPrevotes := 0
		acceptCounts := make(map[string]int)

		for h, senders := range v.prevotes[round] {
			for _, val := range senders {
				totalPrevotes++
				if val == VoteAccept {
					acceptCounts[h]++
				}
			}
		}

		if totalPrevotes >= v.N-v.T {
			v.sentMainvote[round] = true

			selectedHash := ""
			mainVoteVal := VoteReject

			// Check for unanimous accept: >= n - t
			for h, cnt := range acceptCounts {
				if cnt >= v.N-v.T {
					selectedHash = h
					mainVoteVal = VoteAccept
					break
				}
			}

			// If no unanimous candidate, select candidate with plurality and vote Abstain
			if mainVoteVal != VoteAccept {
				maxCnt := 0
				for h, cnt := range acceptCounts {
					if cnt > maxCnt {
						maxCnt = cnt
						selectedHash = h
					}
				}
				mainVoteVal = VoteAbstain
			}

			v.recordVote(round, StepMainVote, selectedHash, v.SelfID, mainVoteVal)
			nextVote = &AgreementVoteMessage{
				CommitteeID:   v.CommitteeID,
				Epoch:         v.Epoch,
				Round:         round,
				Step:          StepMainVote,
				SenderID:      v.SelfID,
				CandidateHash: selectedHash,
				VoteValue:     mainVoteVal,
				Timestamp:     time.Now().UnixMilli(),
			}
			return nextVote, nil, false, nil, nil
		}
	}

	// Evaluate Step 2: MAIN-VOTE completion & Decision / Coin step
	if step == StepMainVote {
		acceptCounts := make(map[string]int)
		totalMainvotes := 0

		for h, senders := range v.mainvotes[round] {
			for _, val := range senders {
				totalMainvotes++
				if val == VoteAccept {
					acceptCounts[h]++
				}
			}
		}

		// Decision Rule: if >= 2t + 1 MAIN-VOTEs for (h, VoteAccept)
		for h, cnt := range acceptCounts {
			if cnt >= 2*v.T+1 {
				candidateSet, exists := v.proposals[h]
				if exists {
					v.DecidedSet = candidateSet
					v.DecidedHash = h
					v.IsDecided = true
					return nil, nil, true, v.DecidedSet, nil
				}
			}
		}

		// If >= n - t MAIN-VOTEs collected and not decided yet: trigger threshold common coin
		if totalMainvotes >= v.N-v.T && !v.sentCoinShare[round] && v.CoinKeyShare != nil {
			v.sentCoinShare[round] = true
			cs, err := v.CoinKeyShare.GenerateShare(round, v.SessionTag)
			if err == nil {
				if v.coinShares[round] == nil {
					v.coinShares[round] = make(map[string]*cryptography.CoinShare)
				}
				v.coinShares[round][v.SelfID] = cs

				coinShareMsg = &AgreementCoinShareMessage{
					CommitteeID: v.CommitteeID,
					Epoch:       v.Epoch,
					Round:       round,
					SenderID:    v.SelfID,
					CoinShare:   cs,
					Timestamp:   time.Now().UnixMilli(),
				}
				return nil, coinShareMsg, false, nil, nil
			}
		}
	}

	return nil, nil, false, nil, nil
}

// ProcessCoinShare processes an incoming threshold common-coin share for round r
func (v *ValidatedAgreementInstance) ProcessCoinShare(msg *AgreementCoinShareMessage) (
	nextVote *AgreementVoteMessage,
	decided bool,
	decidedSet []string,
	err error,
) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.IsDecided {
		return nil, true, v.DecidedSet, nil
	}
	if !v.isMember(msg.SenderID) {
		return nil, false, nil, ErrInvalidSender
	}

	round := msg.Round

	var cs *cryptography.CoinShare
	switch share := msg.CoinShare.(type) {
	case *cryptography.CoinShare:
		cs = share
	default:
		data, marshalErr := json.Marshal(msg.CoinShare)
		if marshalErr != nil {
			return nil, false, nil, ErrInvalidCoinShare
		}
		cs = &cryptography.CoinShare{}
		if unmarshalErr := json.Unmarshal(data, cs); unmarshalErr != nil {
			return nil, false, nil, ErrInvalidCoinShare
		}
	}

	pkShare, exists := v.CoinPeerPKs[msg.SenderID]
	if !exists || !cryptography.VerifyCoinShare(cs, pkShare, v.SessionTag) {
		return nil, false, nil, ErrInvalidCoinShare
	}

	if v.coinShares[round] == nil {
		v.coinShares[round] = make(map[string]*cryptography.CoinShare)
	}
	v.coinShares[round][msg.SenderID] = cs

	// If >= t + 1 valid coin shares collected, combine to obtain round common coin bit
	if len(v.coinShares[round]) >= v.T+1 {
		sharesList := make([]*cryptography.CoinShare, 0, len(v.coinShares[round]))
		for _, s := range v.coinShares[round] {
			sharesList = append(sharesList, s)
		}

		coinBit, combineErr := cryptography.CombineCoinShares(sharesList, v.T)
		if combineErr != nil {
			return nil, false, nil, combineErr
		}

		nextRound := round + 1
		if nextRound > v.CurrentRound {
			v.CurrentRound = nextRound
		}

		if !v.sentPrevote[nextRound] {
			v.sentPrevote[nextRound] = true

			// If coinBit == 1, all nodes lock on the leading plurality candidate!
			// If coinBit == 0, nodes unlock and rotate to the next round leader!
			candHash := ""
			voteVal := VoteAccept

			if coinBit == 1 {
				// Find candidate with plurality of mainvotes from round r
				maxCnt := 0
				for h, senders := range v.mainvotes[round] {
					cnt := len(senders)
					if cnt > maxCnt {
						maxCnt = cnt
						candHash = h
					}
				}
				if candHash == "" {
					keys := make([]string, 0, len(v.proposals))
					for h := range v.proposals {
						keys = append(keys, h)
					}
					sort.Strings(keys)
					if len(keys) > 0 {
						candHash = keys[0]
					}
				}
				v.lockedCandidate = candHash
				voteVal = VoteAccept
			} else {
				v.lockedCandidate = ""
				leaderIndex := (nextRound - 1) % v.N
				leaderID := v.Committee[leaderIndex]
				if lHash, has := v.proposerHashMap[leaderID]; has {
					candHash = lHash
					voteVal = VoteAccept
				} else {
					keys := make([]string, 0, len(v.proposals))
					for h := range v.proposals {
						keys = append(keys, h)
					}
					sort.Strings(keys)
					if len(keys) > 0 {
						candHash = keys[0]
						voteVal = VoteAccept
					}
				}
			}

			v.recordVote(nextRound, StepPreVote, candHash, v.SelfID, voteVal)
			nextVote = &AgreementVoteMessage{
				CommitteeID:   v.CommitteeID,
				Epoch:         v.Epoch,
				Round:         nextRound,
				Step:          StepPreVote,
				SenderID:      v.SelfID,
				CandidateHash: candHash,
				VoteValue:     voteVal,
				Timestamp:     time.Now().UnixMilli(),
			}
			return nextVote, false, nil, nil
		}
	}

	return nil, false, nil, nil
}
