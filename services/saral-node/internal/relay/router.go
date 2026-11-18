package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
)

const (
	MaxPayloadBytes = 1024 * 1024 // 1 MB
	MaxHistoryItems = 500
	DefaultTimeout  = 10000       // 10 seconds
)

type RelayRouter struct {
	idMgr               *identity.IdentityManager
	domain              string
	p2pMgr              *p2p.P2PManager
	coordinatorURL      string
	trustedParticipants map[string]string // NodeID -> PublicKeyHex
	seenMessages        map[string]*RelayAck
	history             []*DeliveryRecord
	mu                  sync.RWMutex
	httpClient          *http.Client
	stopChan            chan struct{}
}

func NewRelayRouter(
	idMgr *identity.IdentityManager,
	domain string,
	p2pMgr *p2p.P2PManager,
	coordinatorURL string,
) *RelayRouter {
	r := &RelayRouter{
		idMgr:               idMgr,
		domain:              strings.ToUpper(domain),
		p2pMgr:              p2pMgr,
		coordinatorURL:      coordinatorURL,
		trustedParticipants: make(map[string]string),
		seenMessages:        make(map[string]*RelayAck),
		history:             make([]*DeliveryRecord, 0, MaxHistoryItems),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	go r.cleanupLoop()
	return r
}

func (r *RelayRouter) Stop() {
	close(r.stopChan)
}

func (r *RelayRouter) RegisterTrustedParticipant(nodeID, pubKeyHex string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	canonicalID, _ := NormalizeNodeID(nodeID)
	r.trustedParticipants[canonicalID] = pubKeyHex
}

func (r *RelayRouter) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now().UnixMilli()
			for k, ack := range r.seenMessages {
				if now-ack.Timestamp > 300000 { // 5 minutes retention
					delete(r.seenMessages, k)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *RelayRouter) Send(req RelaySendRequest) (*DeliveryRecord, error) {
	if req.MessageID == "" {
		req.MessageID = "msg-" + randomHex(8)
	}
	if req.Type == "" {
		req.Type = "RELAY_MESSAGE"
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = DefaultTimeout
	}

	targetNode, targetDomain := NormalizeNodeID(req.TargetNode)
	if req.TargetDomain != "" {
		targetDomain = strings.ToUpper(req.TargetDomain)
	}

	now := time.Now().UnixMilli()
	msg := &RelayMessage{
		MessageID:    req.MessageID,
		SourceNode:   r.idMgr.Identity.NodeID,
		SourceDomain: r.domain,
		TargetNode:   targetNode,
		TargetDomain: targetDomain,
		Type:         req.Type,
		Payload:      req.Payload,
		Timestamp:    now,
		TimestampISO: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    now + int64(req.TimeoutMs),
		HopLimit:     5,
		Hops:         []string{r.idMgr.Identity.NodeID},
		PublicKeyHex: r.idMgr.Identity.PublicKeyHex,
	}

	// Sign canonical representation
	canonicalPayload := CanonicalMessagePayload(msg)
	msg.SignatureHex = r.idMgr.Sign(canonicalPayload)

	record := &DeliveryRecord{
		MessageID:    msg.MessageID,
		SourceNode:   msg.SourceNode,
		SourceDomain: msg.SourceDomain,
		TargetNode:   msg.TargetNode,
		TargetDomain: msg.TargetDomain,
		State:        StateCreated,
		CreatedAt:    now,
		UpdatedAt:    now,
		Hops:         msg.Hops,
	}

	r.appendHistory(record)

	// Routing Decision:
	// 1. Direct P2P if target is a known connected peer
	var destURL string
	isDirectP2P := false

	if r.p2pMgr != nil {
		for _, peer := range r.p2pMgr.GetPeers() {
			normPeer, _ := NormalizeNodeID(peer.NodeID)
			if normPeer == targetNode && peer.Connected {
				destURL = peer.Endpoint + "/p2p/relay"
				isDirectP2P = true
				break
			}
		}
	}

	// 2. If not direct P2P, forward through Coordinator
	if !isDirectP2P {
		if r.coordinatorURL == "" {
			record.State = StateFailed
			record.Error = "no route to destination: peer not directly connected and coordinatorURL not configured"
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}
		destURL = strings.TrimRight(r.coordinatorURL, "/") + "/relay/forward"
	}

	if isDirectP2P {
		record.State = StateSent
	} else {
		record.State = StateForwarded
	}
	record.UpdatedAt = time.Now().UnixMilli()

	// Safe dispatch with retries and exponential backoff
	ack, err := r.dispatchWithRetry(destURL, msg, 3)
	if err != nil {
		record.State = StateFailed
		record.Error = err.Error()
		record.UpdatedAt = time.Now().UnixMilli()
		return record, err
	}

	// Verify recipient signature on ACK
	if ack.Status == StateAcknowledged || ack.Status == StateDelivered {
		canonicalAck := CanonicalAckPayload(ack)
		if !identity.VerifySignature(ack.RecipientPubKey, canonicalAck, ack.RecipientSigHex) {
			record.State = StateFailed
			record.Error = "recipient ACK signature verification failed (forged or corrupted ACK)"
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}

		// Verify that the ACK was indeed signed by the intended recipient
		normAckTarget, _ := NormalizeNodeID(ack.TargetNode)
		if normAckTarget != targetNode {
			record.State = StateFailed
			record.Error = fmt.Sprintf("ACK recipient mismatch: expected %s, got %s", targetNode, ack.TargetNode)
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}

		record.State = StateAcknowledged
		record.Ack = ack
		record.Hops = ack.ForwardedBy
		record.UpdatedAt = time.Now().UnixMilli()
		return record, nil
	}

	record.State = ack.Status
	record.Error = ack.Error
	record.Ack = ack
	record.UpdatedAt = time.Now().UnixMilli()
	return record, nil
}

func (r *RelayRouter) dispatchWithRetry(url string, msg *RelayMessage, maxRetries int) (*RelayAck, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var lastErr error
	backoff := 100 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Saral-Internal-Token", "saral-internal-coordinator-secret")

		resp, err := r.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var ack RelayAck
			if decodeErr := json.NewDecoder(resp.Body).Decode(&ack); decodeErr == nil {
				return &ack, nil
			} else {
				lastErr = decodeErr
			}
		} else {
			lastErr = err
		}

		if attempt < maxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	return nil, fmt.Errorf("delivery failed after %d attempts to %s: %w", maxRetries, url, lastErr)
}

func (r *RelayRouter) HandleIncomingRelay(msg RelayMessage) (*RelayAck, error) {
	now := time.Now().UnixMilli()

	// 1. Expiration check
	if msg.ExpiresAt > 0 && now > msg.ExpiresAt {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateExpired,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        "message expired before delivery",
		}, nil
	}

	// 2. Hop limit & loop check
	if msg.HopLimit <= 0 {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        "hop limit exceeded - loop detected",
		}, nil
	}

	for _, hop := range msg.Hops {
		if hop == r.idMgr.Identity.NodeID {
			return &RelayAck{
				MessageID:    msg.MessageID,
				TargetNode:   r.idMgr.Identity.NodeID,
				TargetDomain: r.domain,
				SourceNode:   msg.SourceNode,
				SourceDomain: msg.SourceDomain,
				Status:       StateFailed,
				Timestamp:    now,
				TimestampISO: time.Now().UTC().Format(time.RFC3339),
				Error:        "routing loop detected in hops",
			}, nil
		}
	}

	// 3. Sender signature verification
	canonicalPayload := CanonicalMessagePayload(&msg)
	if !identity.VerifySignature(msg.PublicKeyHex, canonicalPayload, msg.SignatureHex) {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        "invalid message signature from sender",
		}, nil
	}

	// 4. Trusted participant verification
	r.mu.Lock()
	canonicalSender, _ := NormalizeNodeID(msg.SourceNode)
	if expectedKey, exists := r.trustedParticipants[canonicalSender]; exists {
		if expectedKey != msg.PublicKeyHex {
			r.mu.Unlock()
			return &RelayAck{
				MessageID:    msg.MessageID,
				TargetNode:   r.idMgr.Identity.NodeID,
				TargetDomain: r.domain,
				SourceNode:   msg.SourceNode,
				SourceDomain: msg.SourceDomain,
				Status:       StateFailed,
				Timestamp:    now,
				TimestampISO: time.Now().UTC().Format(time.RFC3339),
				Error:        fmt.Sprintf("sender public key mismatch: registered %s, received %s", expectedKey, msg.PublicKeyHex),
			}, nil
		}
	} else {
		// Auto-enroll validly signed peer
		r.trustedParticipants[canonicalSender] = msg.PublicKeyHex
	}

	// 5. Deduplication check
	if prevAck, exists := r.seenMessages[msg.MessageID]; exists {
		r.mu.Unlock()
		return prevAck, nil // Idempotent response
	}
	r.mu.Unlock()

	// 6. Target Node Verification
	normTarget, _ := NormalizeNodeID(msg.TargetNode)
	normSelf, _ := NormalizeNodeID(r.idMgr.Identity.NodeID)

	if normTarget != normSelf {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("wrong target node: intended for %s, received by %s", msg.TargetNode, r.idMgr.Identity.NodeID),
		}, nil
	}

	// 7. Successfully delivered to destination! Create and sign ACK
	hops := append(msg.Hops, r.idMgr.Identity.NodeID)
	latency := now - msg.Timestamp
	if latency < 0 {
		latency = 0
	}

	ack := &RelayAck{
		MessageID:       msg.MessageID,
		TargetNode:      r.idMgr.Identity.NodeID,
		TargetDomain:    r.domain,
		SourceNode:      msg.SourceNode,
		SourceDomain:    msg.SourceDomain,
		Status:          StateAcknowledged,
		Timestamp:       now,
		TimestampISO:    time.Now().UTC().Format(time.RFC3339),
		LatencyMs:       latency,
		RecipientPubKey: r.idMgr.Identity.PublicKeyHex,
		ForwardedBy:     hops,
	}

	canonicalAck := CanonicalAckPayload(ack)
	ack.RecipientSigHex = r.idMgr.Sign(canonicalAck)

	r.mu.Lock()
	r.seenMessages[msg.MessageID] = ack
	r.mu.Unlock()

	r.appendHistory(&DeliveryRecord{
		MessageID:    msg.MessageID,
		SourceNode:   msg.SourceNode,
		SourceDomain: msg.SourceDomain,
		TargetNode:   r.idMgr.Identity.NodeID,
		TargetDomain: r.domain,
		State:        StateDelivered,
		CreatedAt:    now,
		UpdatedAt:    now,
		Hops:         hops,
		Ack:          ack,
	})

	log.Printf("[SARAL Node - %s] Delivered relay %s from %s (Latency: %d ms, Hops: %v)",
		r.domain, msg.MessageID, msg.SourceNode, latency, hops)

	return ack, nil
}

func (r *RelayRouter) appendHistory(record *DeliveryRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.history) >= MaxHistoryItems {
		r.history = r.history[1:]
	}
	r.history = append(r.history, record)
}

func (r *RelayRouter) GetHistory() []*DeliveryRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]*DeliveryRecord, len(r.history))
	copy(res, r.history)
	return res
}

func (r *RelayRouter) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ackCount := 0
	failedCount := 0
	for _, rec := range r.history {
		if rec.State == StateAcknowledged || rec.State == StateDelivered {
			ackCount++
		} else if rec.State == StateFailed || rec.State == StateExpired {
			failedCount++
		}
	}

	return map[string]interface{}{
		"nodeId":        r.idMgr.Identity.NodeID,
		"domain":        r.domain,
		"totalMessages": len(r.history),
		"acknowledged":  ackCount,
		"failed":        failedCount,
		"seenCacheSize": len(r.seenMessages),
	}
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
