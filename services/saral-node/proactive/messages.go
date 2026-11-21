package proactive

const (
	MessageTypeEpochStart       = "PROACTIVE_EPOCH_START"
	MessageTypeRefreshShare     = "PROACTIVE_REFRESH_SHARE"
	MessageTypeAgreementPropose = "PROACTIVE_AGREEMENT_PROPOSE"
	MessageTypeAgreementEcho    = "PROACTIVE_AGREEMENT_ECHO"
	MessageTypeAgreementReady   = "PROACTIVE_AGREEMENT_READY"
	MessageTypeAgreementVote    = "PROACTIVE_AGREEMENT_VOTE"
	MessageTypeAgreementCoinShare = "PROACTIVE_AGREEMENT_COIN_SHARE"
	MessageTypeRefreshComplete  = "PROACTIVE_REFRESH_COMPLETE"
	MessageTypeEpochAbort       = "PROACTIVE_EPOCH_ABORT"
)

// EpochStartMessage signals the start of a proactive refresh epoch
type EpochStartMessage struct {
	CommitteeID string   `json:"committeeId"`
	NewEpoch    uint64   `json:"newEpoch"`
	InitiatorID string   `json:"initiatorId"`
	Timestamp   int64    `json:"timestamp"`
}

// AgreementProposeMessage proposes an accepted set of completed AVSS sharings
type AgreementProposeMessage struct {
	SessionID    string   `json:"sessionId,omitempty"`
	CommitteeID  string   `json:"committeeId"`
	Epoch        uint64   `json:"epoch"`
	ProposerID   string   `json:"proposerId"`
	CandidateSet []string `json:"candidateSet"` // NodeIDs of dealers whose AVSS completed
	Timestamp    int64    `json:"timestamp"`
}

// AgreementEchoMessage echoes validation of a candidate set proposal
type AgreementEchoMessage struct {
	SessionID    string `json:"sessionId,omitempty"`
	CommitteeID  string `json:"committeeId"`
	Epoch        uint64 `json:"epoch"`
	SenderID     string `json:"senderId"`
	ProposalHash string `json:"proposalHash"`
	Timestamp    int64  `json:"timestamp"`
}

// AgreementReadyMessage broadcasts readiness on an agreed proposal
type AgreementReadyMessage struct {
	SessionID    string `json:"sessionId,omitempty"`
	CommitteeID  string `json:"committeeId"`
	Epoch        uint64 `json:"epoch"`
	SenderID     string `json:"senderId"`
	ProposalHash string `json:"proposalHash"`
	Timestamp    int64  `json:"timestamp"`
}

// AgreementVoteMessage exchanges binary agreement votes (Step 1: PRE-VOTE, Step 2: MAIN-VOTE)
// in the randomized Asynchronous Byzantine Agreement (ABBA) protocol (CKS00 / CKS05).
type AgreementVoteMessage struct {
	SessionID     string `json:"sessionId,omitempty"`
	CommitteeID   string `json:"committeeId"`
	Epoch         uint64 `json:"epoch"`
	Round         int    `json:"round"`
	Step          int    `json:"step"` // 1: PRE_VOTE, 2: MAIN_VOTE
	SenderID      string `json:"senderId"`
	CandidateHash string `json:"candidateHash"`
	VoteValue     int    `json:"voteValue"` // 0: Reject/Skip, 1: Accept Candidate, -1: Abstain/Split
	Timestamp     int64  `json:"timestamp"`
}

// AgreementCoinShareMessage broadcasts a participant's verifiable common-coin share for round r.
type AgreementCoinShareMessage struct {
	SessionID   string                  `json:"sessionId,omitempty"`
	CommitteeID string                  `json:"committeeId"`
	Epoch       uint64                  `json:"epoch"`
	Round       int                     `json:"round"`
	SenderID    string                  `json:"senderId"`
	CoinShare   interface{}             `json:"coinShare"`
	Timestamp   int64                   `json:"timestamp"`
}

// RefreshCompleteNotification notifies peers that the local node finalized the refresh
type RefreshCompleteNotification struct {
	CommitteeID string `json:"committeeId"`
	Epoch       uint64 `json:"epoch"`
	NodeID      string `json:"nodeId"`
	Status      string `json:"status"`
	Timestamp   int64  `json:"timestamp"`
}

