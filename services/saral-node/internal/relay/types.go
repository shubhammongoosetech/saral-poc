package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type DeliveryState string

const (
	StateCreated      DeliveryState = "CREATED"
	StateQueued       DeliveryState = "QUEUED"
	StateSent         DeliveryState = "SENT"
	StateForwarded    DeliveryState = "FORWARDED"
	StateDelivered    DeliveryState = "DELIVERED"
	StateAcknowledged DeliveryState = "ACKNOWLEDGED"
	StateFailed       DeliveryState = "FAILED"
	StateExpired      DeliveryState = "EXPIRED"
)

type HopTraceRecord struct {
	HopID     string `json:"hopId"`
	Domain    string `json:"domain"`
	Timestamp int64  `json:"timestamp"`
	Action    string `json:"action"` // FORWARD | DELIVER
	Signature string `json:"signature,omitempty"`
}

type ParticipantEntry struct {
	NodeID       string `json:"nodeId"`
	Domain       string `json:"domain"`
	PublicKeyHex string `json:"publicKeyHex"`
	Endpoint     string `json:"endpoint,omitempty"`
}

type RelayMessage struct {
	MessageID        string                 `json:"messageId"`
	SourceNode       string                 `json:"sourceNode"`
	SourceDomain     string                 `json:"sourceDomain"`
	TargetNode       string                 `json:"targetNode"`
	TargetDomain     string                 `json:"targetDomain"`
	Type             string                 `json:"type"`
	Payload          map[string]interface{} `json:"payload,omitempty"`
	EncryptedPayload string                 `json:"encryptedPayload,omitempty"`
	Timestamp        int64                  `json:"timestamp"`
	TimestampISO     string                 `json:"timestampIso,omitempty"`
	ExpiresAt        int64                  `json:"expiresAt"`
	HopLimit         int                    `json:"hopLimit"`
	Hops             []string               `json:"hops,omitempty"`
	RoutingTrace     []HopTraceRecord       `json:"routingTrace,omitempty"`
	SignatureHex     string                 `json:"signatureHex"`
	PublicKeyHex     string                 `json:"publicKeyHex"`
}

type RelayAck struct {
	MessageID       string           `json:"messageId"`
	TargetNode      string           `json:"targetNode"`
	TargetDomain    string           `json:"targetDomain"`
	SourceNode      string           `json:"sourceNode"`
	SourceDomain    string           `json:"sourceDomain"`
	Status          DeliveryState    `json:"status"`
	Timestamp       int64            `json:"timestamp"`
	TimestampISO    string           `json:"timestampIso,omitempty"`
	LatencyMs       int64            `json:"latencyMs"`
	RecipientSigHex string           `json:"recipientSigHex"`
	RecipientPubKey string           `json:"recipientPubKey"`
	ForwardedBy     []string         `json:"forwardedBy,omitempty"`
	RoutingTrace    []HopTraceRecord `json:"routingTrace,omitempty"`
	Error           string           `json:"error,omitempty"`
}

type DeliveryRecord struct {
	MessageID    string           `json:"messageId"`
	SourceNode   string           `json:"sourceNode"`
	SourceDomain string           `json:"sourceDomain"`
	TargetNode   string           `json:"targetNode"`
	TargetDomain string           `json:"targetDomain"`
	State        DeliveryState    `json:"state"`
	CreatedAt    int64            `json:"createdAt"`
	UpdatedAt    int64            `json:"updatedAt"`
	Hops         []string         `json:"hops"`
	RoutingTrace []HopTraceRecord `json:"routingTrace,omitempty"`
	Ack          *RelayAck        `json:"ack,omitempty"`
	Error        string           `json:"error,omitempty"`
	RetryCount   int              `json:"retryCount"`
}

type RelaySendRequest struct {
	TargetNode   string                 `json:"targetNode"`
	TargetDomain string                 `json:"targetDomain,omitempty"`
	SourceNode   string                 `json:"sourceNode,omitempty"`
	SourceDomain string                 `json:"sourceDomain,omitempty"`
	Type         string                 `json:"type,omitempty"`
	Payload      map[string]interface{} `json:"payload"`
	TimeoutMs    int                    `json:"timeoutMs,omitempty"`
	MessageID    string                 `json:"messageId,omitempty"`
}

// CanonicalMessagePayload creates canonical bytes for signing and verification of immutable fields
func CanonicalMessagePayload(msg *RelayMessage) []byte {
	var payloadData []byte
	if msg.EncryptedPayload != "" {
		payloadData = []byte(msg.EncryptedPayload)
	} else if msg.Payload != nil {
		payloadData, _ = json.Marshal(msg.Payload)
	}
	hash := sha256.Sum256(payloadData)
	return []byte(fmt.Sprintf("SARAL-MSG:v3:%s:%s:%s:%s:%s:%s:%s:%d:%d",
		msg.MessageID,
		msg.SourceNode,
		msg.SourceDomain,
		msg.TargetNode,
		msg.TargetDomain,
		msg.Type,
		hex.EncodeToString(hash[:]),
		msg.Timestamp,
		msg.ExpiresAt,
	))
}

// CanonicalAckPayload creates canonical bytes for ACK signature and verification
func CanonicalAckPayload(ack *RelayAck) []byte {
	return []byte(fmt.Sprintf("SARAL-ACK:v3:%s:%s:%s:%s:%s:%s:%d",
		ack.MessageID,
		ack.TargetNode,
		ack.TargetDomain,
		ack.SourceNode,
		ack.SourceDomain,
		string(ack.Status),
		ack.Timestamp,
	))
}

// NormalizeNodeID converts user/test aliases into canonical "saral-foundation-1"
func NormalizeNodeID(raw string) (string, string) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "saral-")
	s = strings.TrimPrefix(s, "node-")

	var domain, numStr string
	if strings.HasPrefix(s, "foundation") {
		domain = "FOUNDATION"
		numStr = strings.TrimPrefix(s, "foundation")
	} else if strings.HasPrefix(s, "public") {
		domain = "PUBLIC"
		numStr = strings.TrimPrefix(s, "public")
	} else if strings.HasPrefix(s, "private") {
		domain = "PRIVATE"
		numStr = strings.TrimPrefix(s, "private")
	} else if strings.HasPrefix(s, "f") {
		domain = "FOUNDATION"
		numStr = strings.TrimPrefix(s, "f")
	} else if strings.HasPrefix(s, "p") {
		domain = "PUBLIC"
		numStr = strings.TrimPrefix(s, "p")
	} else if strings.HasPrefix(s, "r") {
		domain = "PRIVATE"
		numStr = strings.TrimPrefix(s, "r")
	}

	numStr = strings.Trim(numStr, "-_")
	num, err := strconv.Atoi(numStr)
	if err == nil && domain != "" {
		return fmt.Sprintf("saral-%s-%d", strings.ToLower(domain), num), domain
	}

	if strings.Contains(s, "foundation") {
		return raw, "FOUNDATION"
	} else if strings.Contains(s, "public") {
		return raw, "PUBLIC"
	} else if strings.Contains(s, "private") {
		return raw, "PRIVATE"
	}
	return raw, "UNKNOWN"
}
