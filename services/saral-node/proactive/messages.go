package proactive

const (
	MessageTypeEpochStart       = "PROACTIVE_EPOCH_START"
	MessageTypeRefreshShare     = "PROACTIVE_REFRESH_SHARE"
	MessageTypeAgreementPropose = "PROACTIVE_AGREEMENT_PROPOSE"
	MessageTypeAgreementEcho    = "PROACTIVE_AGREEMENT_ECHO"
	MessageTypeAgreementReady   = "PROACTIVE_AGREEMENT_READY"
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
	CommitteeID  string   `json:"committeeId"`
	Epoch        uint64   `json:"epoch"`
	ProposerID   string   `json:"proposerId"`
	CandidateSet []string `json:"candidateSet"` // NodeIDs of dealers whose AVSS completed
	Timestamp    int64    `json:"timestamp"`
}

// AgreementEchoMessage echoes validation of a candidate set proposal
type AgreementEchoMessage struct {
	CommitteeID  string `json:"committeeId"`
	Epoch        uint64 `json:"epoch"`
	SenderID     string `json:"senderId"`
	ProposalHash string `json:"proposalHash"`
	Timestamp    int64  `json:"timestamp"`
}

// AgreementReadyMessage broadcasts readiness on an agreed proposal
type AgreementReadyMessage struct {
	CommitteeID  string `json:"committeeId"`
	Epoch        uint64 `json:"epoch"`
	SenderID     string `json:"senderId"`
	ProposalHash string `json:"proposalHash"`
	Timestamp    int64  `json:"timestamp"`
}

// RefreshCompleteNotification notifies peers that the local node finalized the refresh
type RefreshCompleteNotification struct {
	CommitteeID string `json:"committeeId"`
	Epoch       uint64 `json:"epoch"`
	NodeID      string `json:"nodeId"`
	Status      string `json:"status"`
	Timestamp   int64  `json:"timestamp"`
}

