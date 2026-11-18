package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/discovery"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

const (
	MaxCoordinatorHistory = 500
)

type RelayCoordinator struct {
	domain     membership.DomainType
	registry   *membership.NodeRegistry
	monitor    *discovery.Monitor
	peerCoords []string
	auditLog   []*DeliveryRecord
	mu         sync.RWMutex
	httpClient *http.Client
}

func NewRelayCoordinator(
	domain membership.DomainType,
	registry *membership.NodeRegistry,
	monitor *discovery.Monitor,
	peerCoordinatorURLs []string,
) *RelayCoordinator {
	return &RelayCoordinator{
		domain:     domain,
		registry:   registry,
		monitor:    monitor,
		peerCoords: peerCoordinatorURLs,
		auditLog:   make([]*DeliveryRecord, 0, MaxCoordinatorHistory),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (rc *RelayCoordinator) ForwardRelay(msg *RelayMessage) (*RelayAck, error) {
	now := time.Now().UnixMilli()
	coordID := fmt.Sprintf("coord-%s", rc.domain)

	// 1. Expiration check
	if msg.ExpiresAt > 0 && now > msg.ExpiresAt {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   msg.TargetNode,
			TargetDomain: msg.TargetDomain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateExpired,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        "message expired before coordinator forward",
		}, nil
	}

	// 2. Hop limit & loop check
	if msg.HopLimit <= 0 {
		return &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   msg.TargetNode,
			TargetDomain: msg.TargetDomain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        "hop limit exceeded - loop detected",
		}, nil
	}

	for _, hop := range msg.Hops {
		if hop == coordID {
			return &RelayAck{
				MessageID:    msg.MessageID,
				TargetNode:   msg.TargetNode,
				TargetDomain: msg.TargetDomain,
				SourceNode:   msg.SourceNode,
				SourceDomain: msg.SourceDomain,
				Status:       StateFailed,
				Timestamp:    now,
				TimestampISO: time.Now().UTC().Format(time.RFC3339),
				Error:        fmt.Sprintf("forwarding loop detected: %s already in hops", coordID),
			}, nil
		}
	}

	msg.HopLimit--
	msg.Hops = append(msg.Hops, coordID)

	// 3. Destination Resolution
	normTarget, deducedDomain := NormalizeNodeID(msg.TargetNode)
	targetDomain := msg.TargetDomain
	if targetDomain == "" || targetDomain == "UNKNOWN" {
		targetDomain = deducedDomain
	}
	targetDomain = strings.ToUpper(targetDomain)

	log.Printf("[Coordinator - %s] Relaying message %s (Source: %s, Target: %s, TargetDomain: %s, Hops: %v)",
		rc.domain, msg.MessageID, msg.SourceNode, normTarget, targetDomain, msg.Hops)

	// CASE A: Destination is in this Coordinator's domain
	if targetDomain == string(rc.domain) {
		return rc.deliverToLocalNode(normTarget, msg)
	}

	// CASE B: Destination is in another domain -> Forward to Peer Coordinator
	return rc.forwardToPeerCoordinator(targetDomain, msg)
}

func (rc *RelayCoordinator) deliverToLocalNode(normTarget string, msg *RelayMessage) (*RelayAck, error) {
	// Find local node endpoint
	var targetNodeInfo *membership.NodeInfo
	for _, n := range rc.registry.GetAllNodes() {
		normNode, _ := NormalizeNodeID(n.NodeID)
		if normNode == normTarget {
			nodeCopy := n
			targetNodeInfo = &nodeCopy
			break
		}
	}

	now := time.Now().UnixMilli()
	if targetNodeInfo == nil {
		errAck := &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   normTarget,
			TargetDomain: string(rc.domain),
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("destination node %s not found in domain %s", normTarget, rc.domain),
		}
		rc.recordAudit(msg, errAck)
		return errAck, nil
	}

	// Dispatch to node's /node/relay endpoint with retry
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var ack RelayAck
	var lastErr error
	backoff := 100 * time.Millisecond

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", targetNodeInfo.Endpoint+"/node/relay", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Saral-Internal-Token", "saral-internal-coordinator-secret")

		resp, err := rc.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if decodeErr := json.NewDecoder(resp.Body).Decode(&ack); decodeErr == nil {
				rc.recordAudit(msg, &ack)
				return &ack, nil
			} else {
				lastErr = decodeErr
			}
		} else {
			lastErr = err
		}

		if attempt < 3 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	errAck := &RelayAck{
		MessageID:    msg.MessageID,
		TargetNode:   normTarget,
		TargetDomain: string(rc.domain),
		SourceNode:   msg.SourceNode,
		SourceDomain: msg.SourceDomain,
		Status:       StateFailed,
		Timestamp:    time.Now().UnixMilli(),
		TimestampISO: time.Now().UTC().Format(time.RFC3339),
		Error:        fmt.Sprintf("target node %s unreachable at %s: %v", normTarget, targetNodeInfo.Endpoint, lastErr),
	}
	rc.recordAudit(msg, errAck)
	return errAck, nil
}

func (rc *RelayCoordinator) resolveCoordinatorURLForDomain(domain string) string {
	targetDomain := strings.ToUpper(domain)

	// 1. Check discovery monitor peer states
	if rc.monitor != nil {
		for _, st := range rc.monitor.GetPeerCoordinatorStates() {
			if strings.EqualFold(st.Domain, targetDomain) {
				return st.Endpoint
			}
		}
	}

	// 2. Check if URL contains domain name (e.g. Docker DNS: coordinator-public:9002)
	for _, pURL := range rc.peerCoords {
		clean := strings.ToLower(pURL)
		if strings.Contains(clean, strings.ToLower(targetDomain)) {
			return pURL
		}
	}

	// 3. Query /health on configured peer coordinates
	for _, pURL := range rc.peerCoords {
		resp, err := rc.httpClient.Get(strings.TrimRight(pURL, "/") + "/health")
		if err == nil {
			var h struct {
				Domain string `json:"domain"`
			}
			if json.NewDecoder(resp.Body).Decode(&h) == nil && strings.EqualFold(h.Domain, targetDomain) {
				resp.Body.Close()
				return pURL
			}
			resp.Body.Close()
		}
	}

	return ""
}

func (rc *RelayCoordinator) forwardToPeerCoordinator(targetDomain string, msg *RelayMessage) (*RelayAck, error) {
	targetCoordURL := rc.resolveCoordinatorURLForDomain(targetDomain)

	now := time.Now().UnixMilli()
	if targetCoordURL == "" {
		errAck := &RelayAck{
			MessageID:    msg.MessageID,
			TargetNode:   msg.TargetNode,
			TargetDomain: targetDomain,
			SourceNode:   msg.SourceNode,
			SourceDomain: msg.SourceDomain,
			Status:       StateFailed,
			Timestamp:    now,
			TimestampISO: time.Now().UTC().Format(time.RFC3339),
			Error:        fmt.Sprintf("no peer coordinator route available for domain %s (configured peers: %v)", targetDomain, rc.peerCoords),
		}
		rc.recordAudit(msg, errAck)
		return errAck, nil
	}

	destURL := strings.TrimRight(targetCoordURL, "/") + "/relay/forward"
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var ack RelayAck
	var lastErr error
	backoff := 100 * time.Millisecond

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", destURL, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Saral-Internal-Token", "saral-internal-coordinator-secret")

		resp, err := rc.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if decodeErr := json.NewDecoder(resp.Body).Decode(&ack); decodeErr == nil {
				rc.recordAudit(msg, &ack)
				return &ack, nil
			} else {
				lastErr = decodeErr
			}
		} else {
			lastErr = err
		}

		if attempt < 3 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	errAck := &RelayAck{
		MessageID:    msg.MessageID,
		TargetNode:   msg.TargetNode,
		TargetDomain: targetDomain,
		SourceNode:   msg.SourceNode,
		SourceDomain: msg.SourceDomain,
		Status:       StateFailed,
		Timestamp:    time.Now().UnixMilli(),
		TimestampISO: time.Now().UTC().Format(time.RFC3339),
		Error:        fmt.Sprintf("peer coordinator at %s unreachable: %v", destURL, lastErr),
	}
	rc.recordAudit(msg, errAck)
	return errAck, nil
}

func (rc *RelayCoordinator) SendRelay(req RelaySendRequest) (*DeliveryRecord, error) {
	normSource, sourceDomain := NormalizeNodeID(req.SourceNode)
	if req.SourceDomain != "" {
		sourceDomain = strings.ToUpper(req.SourceDomain)
	}
	if normSource == "" {
		// Default to first local node
		nodes := rc.registry.GetAllNodes()
		if len(nodes) > 0 {
			normSource = nodes[0].NodeID
			sourceDomain = string(rc.domain)
		}
	}

	normTarget, targetDomain := NormalizeNodeID(req.TargetNode)
	if req.TargetDomain != "" {
		targetDomain = strings.ToUpper(req.TargetDomain)
	}

	now := time.Now().UnixMilli()

	// If source node is in this domain, command source node to sign and send
	if sourceDomain == string(rc.domain) {
		var sourceNodeInfo *membership.NodeInfo
		for _, n := range rc.registry.GetAllNodes() {
			normN, _ := NormalizeNodeID(n.NodeID)
			if normN == normSource {
				nodeCopy := n
				sourceNodeInfo = &nodeCopy
				break
			}
		}

		if sourceNodeInfo == nil {
			return &DeliveryRecord{
				MessageID:    req.MessageID,
				SourceNode:   normSource,
				SourceDomain: sourceDomain,
				TargetNode:   normTarget,
				TargetDomain: targetDomain,
				State:        StateFailed,
				CreatedAt:    now,
				UpdatedAt:    now,
				Error:        fmt.Sprintf("source node %s not found in coordinator domain %s", normSource, rc.domain),
			}, fmt.Errorf("source node %s not found", normSource)
		}

		// Forward send request to source node
		sendData, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}

		httpReq, err := http.NewRequest("POST", sourceNodeInfo.Endpoint+"/node/relay/send", bytes.NewReader(sendData))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-Saral-Internal-Token", "saral-internal-coordinator-secret")

		resp, err := rc.httpClient.Do(httpReq)
		if err != nil {
			return &DeliveryRecord{
				MessageID:    req.MessageID,
				SourceNode:   normSource,
				SourceDomain: sourceDomain,
				TargetNode:   normTarget,
				TargetDomain: targetDomain,
				State:        StateFailed,
				CreatedAt:    now,
				UpdatedAt:    now,
				Error:        fmt.Sprintf("failed to contact source node %s: %v", normSource, err),
			}, err
		}
		defer resp.Body.Close()

		var record DeliveryRecord
		if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
			return nil, err
		}

		rc.mu.Lock()
		if len(rc.auditLog) >= MaxCoordinatorHistory {
			rc.auditLog = rc.auditLog[1:]
		}
		rc.auditLog = append(rc.auditLog, &record)
		rc.mu.Unlock()

		return &record, nil
	}

	// If source node is in another domain, forward send command to that domain's coordinator
	pURL := rc.resolveCoordinatorURLForDomain(sourceDomain)
	if pURL != "" {
		rpcBody := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "saral_sendRelayMessage",
			"params":  req,
		}
		data, _ := json.Marshal(rpcBody)
		reqPost, _ := http.NewRequest("POST", strings.TrimRight(pURL, "/")+"/rpc", bytes.NewReader(data))
		reqPost.Header.Set("Content-Type", "application/json")
		reqPost.Header.Set("X-Saral-Internal-Token", "saral-internal-coordinator-secret")

		resp, err := rc.httpClient.Do(reqPost)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var rpcResp struct {
			Result *DeliveryRecord `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err == nil && rpcResp.Result != nil {
			return rpcResp.Result, nil
		}
	}

	return nil, fmt.Errorf("unable to route send command to source domain %s", sourceDomain)
}

func (rc *RelayCoordinator) recordAudit(msg *RelayMessage, ack *RelayAck) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	now := time.Now().UnixMilli()
	record := &DeliveryRecord{
		MessageID:    msg.MessageID,
		SourceNode:   msg.SourceNode,
		SourceDomain: msg.SourceDomain,
		TargetNode:   msg.TargetNode,
		TargetDomain: msg.TargetDomain,
		State:        ack.Status,
		CreatedAt:    msg.Timestamp,
		UpdatedAt:    now,
		Hops:         ack.ForwardedBy,
		Ack:          ack,
		Error:        ack.Error,
	}

	if len(rc.auditLog) >= MaxCoordinatorHistory {
		rc.auditLog = rc.auditLog[1:]
	}
	rc.auditLog = append(rc.auditLog, record)
}

func (rc *RelayCoordinator) GetAuditLog() []*DeliveryRecord {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	res := make([]*DeliveryRecord, len(rc.auditLog))
	copy(res, rc.auditLog)
	return res
}

func (rc *RelayCoordinator) GetDeliveryStatus(messageID string) *DeliveryRecord {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	for i := len(rc.auditLog) - 1; i >= 0; i-- {
		if rc.auditLog[i].MessageID == messageID {
			return rc.auditLog[i]
		}
	}
	return nil
}
