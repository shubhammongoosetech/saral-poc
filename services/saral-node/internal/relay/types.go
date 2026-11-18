package relay

import (
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

type RelayMessage struct {
	MessageID    string                 `json:"messageId"`
	SourceNode   string                 `json:"sourceNode"`
	SourceDomain string                 `json:"sourceDomain"`
	TargetNode   string                 `json:"targetNode"`
	TargetDomain string                 `json:"targetDomain"`
	Type         string                 `json:"type"`
	Payload      map[string]interface{} `json:"payload"`
	Timestamp    int64                  `json:"timestamp"`
	TimestampISO string                 `json:"timestampIso,omitempty"`
	ExpiresAt    int64                  `json:"expiresAt"`
	HopLimit     int                    `json:"hopLimit"`
	Hops         []string               `json:"hops,omitempty"`
	SignatureHex string                 `json:"signatureHex"`
	PublicKeyHex string                 `json:"publicKeyHex"`
}

type RelayAck struct {
	MessageID       string        `json:"messageId"`
	TargetNode      string        `json:"targetNode"`
	TargetDomain    string        `json:"targetDomain"`
	SourceNode      string        `json:"sourceNode"`
	SourceDomain    string        `json:"sourceDomain"`
	Status          DeliveryState `json:"status"`
	Timestamp       int64         `json:"timestamp"`
	TimestampISO    string        `json:"timestampIso,omitempty"`
	LatencyMs       int64         `json:"latencyMs"`
	RecipientSigHex string        `json:"recipientSigHex"`
	RecipientPubKey string        `json:"recipientPubKey"`
	ForwardedBy     []string      `json:"forwardedBy,omitempty"`
	Error           string        `json:"error,omitempty"`
}

type DeliveryRecord struct {
	MessageID    string        `json:"messageId"`
	SourceNode   string        `json:"sourceNode"`
	SourceDomain string        `json:"sourceDomain"`
	TargetNode   string        `json:"targetNode"`
	TargetDomain string        `json:"targetDomain"`
	State        DeliveryState `json:"state"`
	CreatedAt    int64         `json:"createdAt"`
	UpdatedAt    int64         `json:"updatedAt"`
	Hops         []string      `json:"hops"`
	Ack          *RelayAck     `json:"ack,omitempty"`
	Error        string        `json:"error,omitempty"`
	RetryCount   int           `json:"retryCount"`
}

type RelaySendRequest struct {
	TargetNode   string                 `json:"targetNode"`
	TargetDomain string                 `json:"targetDomain,omitempty"`
	Type         string                 `json:"type,omitempty"`
	Payload      map[string]interface{} `json:"payload"`
	TimeoutMs    int                    `json:"timeoutMs,omitempty"`
	MessageID    string                 `json:"messageId,omitempty"`
}

// CanonicalMessagePayload creates canonical bytes for signing and verification
func CanonicalMessagePayload(msg *RelayMessage) []byte {
	payloadBytes, _ := json.Marshal(msg.Payload)
	return []byte(fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%d:%d",
		msg.MessageID,
		msg.SourceNode,
		msg.SourceDomain,
		msg.TargetNode,
		msg.TargetDomain,
		msg.Type,
		string(payloadBytes),
		msg.Timestamp,
		msg.ExpiresAt,
	))
}

// CanonicalAckPayload creates canonical bytes for ACK signature and verification
func CanonicalAckPayload(ack *RelayAck) []byte {
	return []byte(fmt.Sprintf("ACK:%s:%s:%s:%s:%s:%s:%d",
		ack.MessageID,
		ack.TargetNode,
		ack.TargetDomain,
		ack.SourceNode,
		ack.SourceDomain,
		string(ack.Status),
		ack.Timestamp,
	))
}

// NormalizeNodeID converts user/test aliases (e.g. "foundation-01", "node-f2") into canonical "saral-foundation-1"
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

