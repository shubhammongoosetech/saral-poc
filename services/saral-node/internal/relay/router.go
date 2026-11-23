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
	DefaultTimeout  = 10000 // 10 seconds
)

type RelayRouter struct {
	idMgr               *identity.IdentityManager
	domain              string
	p2pMgr              *p2p.P2PManager
	vaultDir            string
	trustedParticipants map[string]membership.ParticipantEntry // Canonical NodeID -> ParticipantEntry
	seenMessages        map[string]*RelayAck
	acceptedProtocol    map[string]*RelayAck
	history             []*DeliveryRecord
	messageHandlers     map[string]func(msg *RelayMessage) error
	mu                  sync.RWMutex
	httpClient          *http.Client
	mtlsClient          *http.Client
	stopChan            chan struct{}
}

func (r *RelayRouter) SetMTLSClient(client *http.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mtlsClient = client
}

func (r *RelayRouter) RegisterMessageHandler(msgType string, handler func(msg *RelayMessage) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messageHandlers[msgType] = handler
}

func NewRelayRouter(
	idMgr *identity.IdentityManager,
	domain string,
	p2pMgr *p2p.P2PManager,
	vaultDir string,
) *RelayRouter {
	r := &RelayRouter{
		idMgr:               idMgr,
		domain:              strings.ToUpper(domain),
		p2pMgr:              p2pMgr,
		vaultDir:            vaultDir,
		trustedParticipants: make(map[string]membership.ParticipantEntry),
		seenMessages:        make(map[string]*RelayAck),
		acceptedProtocol:    make(map[string]*RelayAck),
		history:             make([]*DeliveryRecord, 0, MaxHistoryItems),
		messageHandlers:     make(map[string]func(msg *RelayMessage) error),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	// Restore persistent deduplication cache across process restarts
	r.loadSeenMessagesFromDisk()
	r.loadGenesisParticipants()

	go r.cleanupLoop()

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

// TrustedSigningKey returns the enrolled signing key for a protocol participant.
func (r *RelayRouter) TrustedSigningKey(nodeID string) string {
	nodeID, _ = membership.NormalizeNodeID(nodeID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.trustedParticipants[nodeID].PublicKeyHex
}

func requiresPrivateChannel(kind string) bool {
	return strings.HasPrefix(kind, "DKG_") || strings.HasPrefix(kind, "AVSS_") ||
		strings.HasPrefix(kind, "PROACTIVE_") || strings.HasPrefix(kind, "HYBRID_DKG_")
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

func (r *RelayRouter) GetParticipantEndpoint(nodeID string) string {
	nodeID, _ = membership.NormalizeNodeID(nodeID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if entry, ok := r.trustedParticipants[nodeID]; ok {
		return entry.Endpoint
	}
	return ""
}

func (r *RelayRouter) GetAllParticipants() map[string]membership.ParticipantEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make(map[string]membership.ParticipantEntry, len(r.trustedParticipants))
	for k, v := range r.trustedParticipants {
		res[k] = v
	}
	return res
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
			for k, ack := range r.acceptedProtocol {
				if now-ack.Timestamp > 60000 {
					delete(r.acceptedProtocol, k)
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
		if requiresPrivateChannel(req.Type) {
			return nil, fmt.Errorf("destination encryption key is required for protocol messages")
		}
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

	if r.p2pMgr != nil {
		for _, peer := range r.p2pMgr.GetPeers() {
			normPeer, _ := membership.NormalizeNodeID(peer.NodeID)
			if normPeer == targetNode && peer.Connected {
				destURL = peer.Endpoint + "/p2p/relay"
				break
			}
		}
	}

	// 2. Direct P2P via registered trusted participants
	if destURL == "" {
		r.mu.RLock()
		entry, found := r.trustedParticipants[targetNode]
		r.mu.RUnlock()
		if found && entry.Endpoint != "" {
			destURL = strings.TrimRight(entry.Endpoint, "/") + "/p2p/relay"
		} else {
			record.State = StateFailed
			record.Error = fmt.Sprintf("no route to destination: peer %s not connected and not found in trusted participants", targetNode)
			record.UpdatedAt = time.Now().UnixMilli()
			return record, fmt.Errorf("%s", record.Error)
		}
	}

	record.State = StateSent
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

	// If mTLS client configured, attempt mTLS URL first
	if r.mtlsClient != nil {
		mtlsURL := url
		if strings.Contains(url, "8001") {
			mtlsURL = strings.Replace(url, "8001", "8443", 1)
			mtlsURL = strings.Replace(mtlsURL, "http://", "https://", 1)
		} else if strings.Contains(url, "9001") || strings.Contains(url, "9002") || strings.Contains(url, "9003") {
			mtlsURL = strings.Replace(url, "9001", "9443", 1)
			mtlsURL = strings.Replace(mtlsURL, "9002", "9443", 1)
			mtlsURL = strings.Replace(mtlsURL, "9003", "9443", 1)
			mtlsURL = strings.Replace(mtlsURL, "http://", "https://", 1)
		}
		if mtlsURL != url {
			mReq, err := http.NewRequest("POST", mtlsURL, bytes.NewReader(data))
			if err == nil {
				mReq.Header.Set("Content-Type", "application/json")
				mReq.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())
				mResp, errDo := r.mtlsClient.Do(mReq)
				if errDo == nil {
					defer mResp.Body.Close()
					var ack RelayAck
					if decodeErr := json.NewDecoder(mResp.Body).Decode(&ack); decodeErr == nil &&
						(!requiresPrivateChannel(msg.Type) || ack.Status == StateAcknowledged || ack.Status == StateDelivered) {
						return &ack, nil
					}
				}
			}
		}
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())

		resp, err := r.httpClient.Do(req)
		if err == nil {
			var ack RelayAck
			decodeErr := json.NewDecoder(resp.Body).Decode(&ack)
			resp.Body.Close()
			if decodeErr != nil {
				lastErr = decodeErr
			} else if !requiresPrivateChannel(msg.Type) || ack.Status == StateAcknowledged || ack.Status == StateDelivered {
				return &ack, nil
			} else {
				lastErr = fmt.Errorf("protocol handler did not accept message: %s", ack.Error)
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

	private := requiresPrivateChannel(msg.Type)
	acceptedKey := canonicalSender + ":" + msg.MessageID + ":" + msg.SignatureHex
	r.mu.RLock()
	prevAck := r.seenMessages[msg.MessageID]
	if private {
		prevAck = r.acceptedProtocol[acceptedKey]
	}
	r.mu.RUnlock()
	if prevAck != nil {
		return prevAck, nil // Idempotent response
	}

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
	if private {
		privateKey := r.idMgr.GetEncryptionPrivateKey()
		if privateKey == nil || msg.EncryptedPayload == "" {
			return r.failedProtocolAck(msg, "destination-encrypted protocol payload required", now), nil
		}
		payload, err := crypto.DecryptForDestination(privateKey, msg.EncryptedPayload)
		if err != nil {
			return r.failedProtocolAck(msg, "protocol payload decryption failed", now), nil
		}
		msg.Payload = payload
	} else if msg.EncryptedPayload != "" {
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

	r.mu.RLock()
	handler := r.messageHandlers[msg.Type]
	r.mu.RUnlock()
	if private {
		if handler == nil {
			return r.failedProtocolAck(msg, "protocol handler is unavailable", now), nil
		}
		if err := handler(&msg); err != nil {
			return r.failedProtocolAck(msg, err.Error(), now), nil
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
	if private {
		// Protocol state is restored independently. Old transport ACKs must
		// never suppress a necessary replay after process restart.
		r.acceptedProtocol[acceptedKey] = ack
	} else {
		r.seenMessages[msg.MessageID] = ack
		r.saveSeenMessagesToDisk()
	}
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

	if !private && handler != nil {
		go func(m RelayMessage) {
			if err := handler(&m); err != nil {
				log.Printf("[SARAL Node - %s] Error in registered handler for message type %s: %v", r.domain, m.Type, err)
			}
		}(msg)
	}

	return ack, nil
}

func (r *RelayRouter) failedProtocolAck(msg RelayMessage, reason string, now int64) *RelayAck {
	return &RelayAck{
		MessageID: msg.MessageID, TargetNode: r.idMgr.Identity.NodeID, TargetDomain: r.domain,
		SourceNode: msg.SourceNode, SourceDomain: msg.SourceDomain, Status: StateFailed,
		Timestamp: now, Error: reason,
	}
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
