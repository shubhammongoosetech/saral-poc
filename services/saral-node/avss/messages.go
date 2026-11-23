package avss

const (
	MessageTypeInit             = "AVSS_INIT"
	MessageTypeSend             = "AVSS_SEND"
	MessageTypeEcho             = "AVSS_ECHO"
	MessageTypeReady            = "AVSS_READY"
	MessageTypeShared           = "AVSS_SHARED"
	MessageTypeReconstruct      = "AVSS_RECONSTRUCT"
	MessageTypeReconstructShare = "AVSS_RECONSTRUCT_SHARE"
	MessageTypeRecoveryRequest  = "AVSS_RECOVERY_REQ"
	MessageTypeRecoveryResponse = "AVSS_RECOVERY_RESP"
)

// InitMessage initiates an AVSS session
type InitMessage struct {
	SessionID   string   `json:"sessionId"`
	CommitteeID string   `json:"committeeId"`
	DealerID    string   `json:"dealerId"`
	Epoch       uint64   `json:"epoch"`
	N           int      `json:"n"`
	K           int      `json:"k"`
	T           int      `json:"t"`
	Nodes       []string `json:"nodes"`
	Timestamp   int64    `json:"timestamp"`
}

// SendMessage represents the dealer's private distribution to a participant
type SendMessage struct {
	SessionID    string     `json:"sessionId"`
	CommitteeID  string     `json:"committeeId"`
	DealerID     string     `json:"dealerId"`
	RecipientID  string     `json:"recipientId"`
	Epoch        uint64     `json:"epoch"`
	Commitments  [][]string `json:"commitments"`  // k x k hex points
	RowPoly      []string   `json:"rowPoly"`      // a_i(y) coefficients in hex
	RowBlindPoly []string   `json:"rowBlindPoly"` // a'_i(y) coefficients in hex
	ColPoly      []string   `json:"colPoly"`      // b_i(x) coefficients in hex
	ColBlindPoly []string   `json:"colBlindPoly"` // b'_i(x) coefficients in hex
	Curve        string     `json:"curve,omitempty"`
	Timestamp    int64      `json:"timestamp"`
}

// EchoMessage is sent by participants to all peers upon validating SEND
type EchoMessage struct {
	SessionID   string     `json:"sessionId"`
	CommitteeID string     `json:"committeeId"`
	SenderID    string     `json:"senderId"`
	RecipientID string     `json:"recipientId"`
	Epoch       uint64     `json:"epoch"`
	Commitments [][]string `json:"commitments"`
	Point       string     `json:"point"`      // p_{sender, recipient} = a_{sender}(recipient)
	BlindPoint  string     `json:"blindPoint"` // p'_{sender, recipient} = a'_{sender}(recipient)
	Curve       string     `json:"curve,omitempty"`
	Timestamp   int64      `json:"timestamp"`
}

// ReadyMessage is sent by participants upon collecting sufficient ECHOs or READYs
type ReadyMessage struct {
	SessionID   string     `json:"sessionId"`
	CommitteeID string     `json:"committeeId"`
	SenderID    string     `json:"senderId"`
	RecipientID string     `json:"recipientId"`
	Epoch       uint64     `json:"epoch"`
	Commitments [][]string `json:"commitments"`
	Point       string     `json:"point,omitempty"`
	BlindPoint  string     `json:"blindPoint,omitempty"`
	Curve       string     `json:"curve,omitempty"`
	Timestamp   int64      `json:"timestamp"`
}

// ReconstructRequest requests test reconstruction of the shared secret
type ReconstructRequest struct {
	SessionID   string `json:"sessionId"`
	CommitteeID string `json:"committeeId"`
	RequesterID string `json:"requesterId"`
	Timestamp   int64  `json:"timestamp"`
}

// ReconstructShareMessage delivers a verified share to the reconstruction tester
type ReconstructShareMessage struct {
	SessionID   string `json:"sessionId"`
	CommitteeID string `json:"committeeId"`
	SenderID    string `json:"senderId"`
	NodeIndex   int    `json:"nodeIndex"` // 1-based index in committee
	Share       string `json:"share"`
	BlindShare  string `json:"blindShare"`
	Timestamp   int64  `json:"timestamp"`
}

// RecoveryRequestMessage allows a crashed or recovering node to request its missing slice or verified commitments
type RecoveryRequestMessage struct {
	SessionID   string `json:"sessionId"`
	CommitteeID string `json:"committeeId"`
	RequesterID string `json:"requesterId"`
	Epoch       uint64 `json:"epoch"`
	Timestamp   int64  `json:"timestamp"`
}

// RecoveryResponseMessage delivers the buffered valid slice or public evaluation to the recovering node
type RecoveryResponseMessage struct {
	SessionID    string     `json:"sessionId"`
	CommitteeID  string     `json:"committeeId"`
	ResponderID  string     `json:"responderId"`
	RecipientID  string     `json:"recipientId"`
	Epoch        uint64     `json:"epoch"`
	Commitments  [][]string `json:"commitments"`
	Point        string     `json:"point,omitempty"`
	BlindPoint   string     `json:"blindPoint,omitempty"`
	RowPolySlice []string   `json:"rowPolySlice,omitempty"`
	Curve        string     `json:"curve,omitempty"`
	Timestamp    int64      `json:"timestamp"`
}

