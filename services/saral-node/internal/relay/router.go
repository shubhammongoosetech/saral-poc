package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/crypto"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/membership"
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
	vaultDir            string
	trustedParticipants map[string]membership.ParticipantEntry // Canonical NodeID -> ParticipantEntry
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
	vaultDir string,
) *RelayRouter {
	r := &RelayRouter{
		idMgr:               idMgr,
		domain:              strings.ToUpper(domain),
		p2pMgr:              p2pMgr,
		coordinatorURL:      coordinatorURL,
		vaultDir:            vaultDir,
		trustedParticipants: make(map[string]membership.ParticipantEntry),
		seenMessages:        make(map[string]*RelayAck),
		history:             make([]*DeliveryRecord, 0, MaxHistoryItems),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	// Restore persistent deduplication cache across process restarts
	r.loadSeenMessagesFromDisk()
	r.loadGenesisParticipants()

	go r.cleanupLoop()
	go r.syncParticipantsLoop()

	return r
}

func (r *RelayRouter) loadGenesisParticipants() {
	paths := []string{
		os.Getenv("SARAL_GENESIS_REGISTRY_FILE"),
		"/run/secrets/saral_genesis_participants",
		"/run/secrets/saral_genesis_participants.json",
		"infra/config/genesis_participants.json",
		"../../infra/config/genesis_participants.json",
		"../../../infra/config/genesis_participants.json",
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var mapEntries map[string]membership.ParticipantEntry
		if err := json.Unmarshal(data, &mapEntries); err == nil && len(mapEntries) > 0 {
			for _, v := range mapEntries {
				r.RegisterTrustedParticipant(v)
			}
			log.Printf("[Relay Router - %s] Loaded %d genesis participants from %s", r.domain, len(mapEntries), p)
			return
		}
		var listEntries []membership.ParticipantEntry
		if err := json.Unmarshal(data, &listEntries); err == nil && len(listEntries) > 0 {
			for _, v := range listEntries {
				r.RegisterTrustedParticipant(v)
			}
			log.Printf("[Relay Router - %s] Loaded %d genesis participants from %s", r.domain, len(listEntries), p)
			return
		}
	}
}

func (r *RelayRouter) Stop() {
	close(r.stopChan)
}

func (r *RelayRouter) RegisterTrustedParticipant(p membership.ParticipantEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	canonicalID, domain := membership.NormalizeNodeID(p.NodeID)
	if p.Domain == "" {
		p.Domain = domain
	}
	p.NodeID = canonicalID
	r.trustedParticipants[canonicalID] = p
	if r.p2pMgr != nil {
		r.p2pMgr.RegisterTrustedParticipant(p)
	}
}

func (r *RelayRouter) loadSeenMessagesFromDisk() {
	if r.vaultDir == "" {
		return
	}
	cacheFile := filepath.Join(r.vaultDir, "seen_relay_messages.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var loaded map[string]*RelayAck
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		r.seenMessages = loaded
		log.Printf("[SARAL Node - %s] Restored %d deduplication records from persistent vault", r.domain, len(loaded))
	}
}

func (r *RelayRouter) saveSeenMessagesToDisk() {
	if r.vaultDir == "" {
		return
	}
	cacheFile := filepath.Join(r.vaultDir, "seen_relay_messages.json")
	data, err := json.Marshal(r.seenMessages)
	if err == nil {
		_ = os.WriteFile(cacheFile, data, 0600)
	}
}

func (r *RelayRouter) syncParticipantsLoop() {
	if r.coordinatorURL == "" {
		return
	}

	// Initial sync
	r.fetchParticipantsFromCoordinator()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.fetchParticipantsFromCoordinator()
		}
	}
}

func (r *RelayRouter) fetchParticipantsFromCoordinator() {
	if r.coordinatorURL == "" {
		return
	}

	url := strings.TrimRight(r.coordinatorURL, "/") + "/registry/participants"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())

	resp, err := r.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	var partResp struct {
		Participants map[string]membership.ParticipantEntry `json:"participants"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&partResp); err == nil {
		for _, p := range partResp.Participants {
			r.RegisterTrustedParticipant(p)
		}
	}
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
			changed := false
			for k, ack := range r.seenMessages {
				if now-ack.Timestamp > 600000 { // 10 minutes retention
					delete(r.seenMessages, k)
					changed = true
				}
			}
			if changed {
				r.saveSeenMessagesToDisk()
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

	targetNode, targetDomain := membership.NormalizeNodeID(req.TargetNode)
	if req.TargetDomain != "" {
		targetDomain = strings.ToUpper(req.TargetDomain)
	}

	// Payload size validation
	rawPayload, err := json.Marshal(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if len(rawPayload) > MaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds maximum allowed size (%d bytes > %d limit)", len(rawPayload), MaxPayloadBytes)
	}

	// Encrypted wire transport - Destination-specific encryption if target key enrolled
	r.mu.RLock()
	destEntry, hasDest := r.trustedParticipants[targetNode]
	r.mu.RUnlock()

	var encPayload string
	if hasDest && destEntry.EncryptionKeyHex != "" {
		var encErr error
		encPayload, encErr = crypto.EncryptForDestination(destEntry.EncryptionKeyHex, req.Payload)
		if encErr != nil {
			return nil, fmt.Errorf("destination payload encryption failed: %w", encErr)
		}
	} else {
		var encErr error
		encPayload, encErr = crypto.EncryptPayload(req.Payload)
		if encErr != nil {
			return nil, fmt.Errorf("payload encryption failed: %w", encErr)
		}
	}

	now := time.Now().UnixMilli()
	msg := &RelayMessage{
		MessageID:        req.MessageID,
		SourceNode:       r.idMgr.Identity.NodeID,
		SourceDomain:     r.domain,
		TargetNode:       targetNode,
		TargetDomain:     targetDomain,
		Type:             req.Type,
		Payload:          nil, // Strip plaintext from wire transport
		EncryptedPayload: encPayload,
		Timestamp:        now,
		TimestampISO:     time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:        now + int64(req.TimeoutMs),
		HopLimit:         5,
		Hops:             []string{r.idMgr.Identity.NodeID},
		RoutingTrace: []HopTraceRecord{
			{
				HopID:     r.idMgr.Identity.NodeID,
				Domain:    r.domain,
				Timestamp: now,
				Action:    "ORIGIN_SEND",
			},
		},
		PublicKeyHex: r.idMgr.Identity.PublicKeyHex,
	}

	// Sign canonical immutable message fields
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
		RoutingTrace: msg.RoutingTrace,
	}

	r.appendHistory(record)

	// Routing Decision:
	// 1. Direct P2P if target is a known connected peer
	var destURL string
	isDirectP2P := false

	if r.p2pMgr != nil {
		for _, peer := range r.p2pMgr.GetPeers() {
			normPeer, _ := membership.NormalizeNodeID(peer.NodeID)
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
		// Strict Security Rule 5: Bind recipient ACK verification to enrolled destination public key!
		// Never trust a public key solely because it appears inside an ACK.
		r.mu.RLock()
		expectedEntry, hasExpected := r.trustedParticipants[targetNode]
		r.mu.RUnlock()

		if !hasExpected {
			record.State = StateFailed
			record.Error = fmt.Sprintf("untrusted recipient ACK: destination %s not found in participant registry", targetNode)
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}

		if ack.RecipientPubKey != expectedEntry.PublicKeyHex {
			record.State = StateFailed
			record.Error = fmt.Sprintf("forged ACK recipient public key for %s: expected %s, got %s",
				targetNode, expectedEntry.PublicKeyHex, ack.RecipientPubKey)
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}
		verifyKey := expectedEntry.PublicKeyHex

		canonicalAck := CanonicalAckPayload(ack)
		if !identity.VerifySignature(verifyKey, canonicalAck, ack.RecipientSigHex) {
			record.State = StateFailed
			record.Error = "recipient ACK signature verification failed (forged or corrupted ACK)"
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}

		// Verify intended recipient node ID
		normAckTarget, _ := membership.NormalizeNodeID(ack.TargetNode)
		if normAckTarget != targetNode {
			record.State = StateFailed
			record.Error = fmt.Sprintf("ACK recipient mismatch: expected %s, got %s", targetNode, ack.TargetNode)
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}

		record.State = StateAcknowledged
		record.Ack = ack
		record.Hops = ack.ForwardedBy
		record.RoutingTrace = ack.RoutingTrace
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
		req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())

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

	// 1. Freshness check (clock skew / delayed packets)
	diff := now - msg.Timestamp
	if diff < -5000 || diff > 60000 {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("timestamp outside freshness window (diff: %d ms)", diff),
		}, nil
	}

	// 2. Expiration check
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

	// 3. Hop limit & loop check
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

	// 4. Canonical Sender signature verification (validates encrypted wire payload)
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

	// 6. Strict Mandatory Participant Registry Verification (NO empty bypass, NO auto-enrollment!)
	canonicalSender, _ := membership.NormalizeNodeID(msg.SourceNode)
	r.mu.RLock()
	trustedEntry, exists := r.trustedParticipants[canonicalSender]
	r.mu.RUnlock()

	if !exists {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("unknown peer: sender %s is not in trusted participant registry", msg.SourceNode),
		}, nil
	}
	if trustedEntry.PublicKeyHex != msg.PublicKeyHex {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("forged sender public key for %s: registered %s, received %s", msg.SourceNode, trustedEntry.PublicKeyHex, msg.PublicKeyHex),
		}, nil
	}
	if trustedEntry.Domain != "" && msg.SourceDomain != "" && !strings.EqualFold(trustedEntry.Domain, msg.SourceDomain) {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   r.idMgr.Identity.NodeID,
			TargetDomain: r.domain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("sender domain mismatch for %s: registered %s, claimed %s", msg.SourceNode, trustedEntry.Domain, msg.SourceDomain),
		}, nil
	}

	// 7. Deduplication check (Idempotent response)
	r.mu.Lock()
	if prevAck, exists := r.seenMessages[msg.MessageID]; exists {
		r.mu.Unlock()
		return prevAck, nil // Idempotent response
	}
	r.mu.Unlock()

	// 8. Target Node Verification
	normTarget, _ := membership.NormalizeNodeID(msg.TargetNode)
	normSelf, _ := membership.NormalizeNodeID(r.idMgr.Identity.NodeID)

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

	// 8b. Decrypt Destination-Specific Authenticated Payload (Requirement 7)
	if msg.EncryptedPayload != "" {
		if r.idMgr.GetEncryptionPrivateKey() != nil {
			decrypted, decErr := crypto.DecryptForDestination(r.idMgr.GetEncryptionPrivateKey(), msg.EncryptedPayload)
			if decErr == nil {
				msg.Payload = decrypted
			} else {
				// Fallback to legacy cluster decrypt or fail closed
				decryptedLegacy, legErr := crypto.DecryptPayload(msg.EncryptedPayload)
				if legErr == nil {
					msg.Payload = decryptedLegacy
				} else {
					return &RelayAck{
						MessageID:    msg.MessageID,
						TargetNode:   r.idMgr.Identity.NodeID,
						TargetDomain: r.domain,
						SourceNode:   msg.SourceNode,
						SourceDomain: msg.SourceDomain,
						Status:       StateFailed,
						Timestamp:    now,
						TimestampISO: time.Now().UTC().Format(time.RFC3339),
						Error:        fmt.Sprintf("destination payload decryption failed (intermediary or key mismatch): %v", decErr),
					}, nil
				}
			}
		} else {
			decrypted, decErr := crypto.DecryptPayload(msg.EncryptedPayload)
			if decErr != nil {
				return &RelayAck{
					MessageID:    msg.MessageID,
					TargetNode:   r.idMgr.Identity.NodeID,
					TargetDomain: r.domain,
					SourceNode:   msg.SourceNode,
					SourceDomain: msg.SourceDomain,
					Status:       StateFailed,
					Timestamp:    now,
					TimestampISO: time.Now().UTC().Format(time.RFC3339),
					Error:        fmt.Sprintf("payload decryption failed: %v", decErr),
				}, nil
			}
			msg.Payload = decrypted
		}
	}

	// 9. Successfully delivered to destination! Create and sign ACK
	hops := append(msg.Hops, r.idMgr.Identity.NodeID)
	trace := append(msg.RoutingTrace, HopTraceRecord{
		HopID:     r.idMgr.Identity.NodeID,
		Domain:    r.domain,
		Timestamp: now,
		Action:    "DESTINATION_DELIVER",
	})

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
		RoutingTrace:    trace,
	}

	canonicalAck := CanonicalAckPayload(ack)
	ack.RecipientSigHex = r.idMgr.Sign(canonicalAck)

	r.mu.Lock()
	r.seenMessages[msg.MessageID] = ack
	r.saveSeenMessagesToDisk()
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
		RoutingTrace: trace,
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
