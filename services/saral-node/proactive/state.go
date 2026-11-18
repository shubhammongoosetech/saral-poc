package proactive

type EpochState string

const (
	EpochStateActive        EpochState = "ACTIVE"
	EpochStateRefreshing    EpochState = "REFRESHING"
	EpochStateTransitioning EpochState = "TRANSITIONING"
	EpochStateAborted       EpochState = "ABORTED"
)

type RefreshState string

const (
	RefreshStateIdle          RefreshState = "IDLE"
	RefreshStateSharingShares RefreshState = "SHARING_SHARES"
	RefreshStateAgreement     RefreshState = "AGREEMENT"
	RefreshStateComputing     RefreshState = "COMPUTING_NEW_SHARES"
	RefreshStateCompleted     RefreshState = "COMPLETED"
	RefreshStateFailed        RefreshState = "FAILED"
)

// NodeProactiveState tracks the node's epoch and proactive parameters (Section 10)
type NodeProactiveState struct {
	CommitteeID       string       `json:"committeeId"`
	SessionID         string       `json:"sessionId"`
	EpochNumber       uint64       `json:"epochNumber"`
	EpochState        EpochState   `json:"epochState"`
	ShareVersion      uint64       `json:"shareVersion"`
	CommitmentVersion uint64       `json:"commitmentVersion"`
	RefreshState      RefreshState `json:"refreshState"`
	ParticipantSet    []string     `json:"participantSet"`
	ActiveSecretHex   string       `json:"activeSecretCommitment,omitempty"` // C_{0,0} public commitment
}

