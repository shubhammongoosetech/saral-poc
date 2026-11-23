package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/auth"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

// AVSSSessionInfo records metadata for an AVSS sharing session.
// Note: Coordinators NEVER store or handle private secret shares.
type AVSSSessionInfo struct {
	SessionID        string   `json:"sessionId"`
	CommitteeID      string   `json:"committeeId"`
	DealerID         string   `json:"dealerId"`
	Epoch            uint64   `json:"epoch"`
	N                int      `json:"n"`
	K                int      `json:"k"`
	T                int      `json:"t"`
	Committee        []string `json:"committee"`
	SecretCommitment string   `json:"secretCommitment,omitempty"`
	CreatedAt        string   `json:"createdAt"`
	Status           string   `json:"status"` // INITIATED | SHARING_COMPLETED | FAILED
}

// ValidateAVSSParameters enforces the Cachin et al. (CCS 2002) dual-threshold AVSS bounds:
// n - 2*t >= k and k > t
func ValidateAVSSParameters(n, k, t int) error {
	if n <= 0 || k <= 0 || t <= 0 {
		return fmt.Errorf("invalid parameters: n, k, and t must be positive integers (got n=%d, k=%d, t=%d)", n, k, t)
	}
	if n-2*t < k {
		return fmt.Errorf("invalid AVSS parameters: requires n - 2*t >= k (got %d - 2*%d = %d < %d)", n, t, n-2*t, k)
	}
	if k <= t {
		return fmt.Errorf("invalid AVSS parameters: requires k > t (got k=%d, t=%d)", k, t)
	}
	return nil
}

// ValidateProactiveParameters enforces the Cachin et al. (CCS 2002) proactive refresh bounds:
// k = t + 1 and n > 3*t
func ValidateProactiveParameters(n, k, t int) error {
	if k != t+1 {
		return fmt.Errorf("proactive refresh rejected: Cachin et al. proactive refresh strictly requires ordinary sharing with k = t + 1 (got k=%d, t=%d). Configuration C (k > t+1) dual-threshold AVSS does not support the research paper's proactive refresh protocol", k, t)
	}
	if n <= 3*t {
		return fmt.Errorf("proactive refresh rejected: Cachin et al. proactive refresh requires n > 3*t (got n=%d, t=%d, 3*t=%d)", n, t, 3*t)
	}
	return nil
}

// ValidateHybridVSSParameters verifies the Kate-Huang-Goldberg bound:
// n >= 3t + 2f + 1
func ValidateHybridVSSParameters(n, t, f int) error {
	required := 3*t + 2*f + 1
	if n < required {
		return fmt.Errorf("HybridVSS bound violated: requires n >= 3t + 2f + 1 (got n=%d, required=%d for t=%d, f=%d)", n, required, t, f)
	}
	return nil
}

// getNodeEndpoint resolves the HTTP endpoint for a given node ID
func (s *Server) getNodeEndpoint(nodeID string) string {
	if n, ok := s.registry.GetNode(nodeID); ok && n.Endpoint != "" {
		return n.Endpoint
	}
	canonicalID, _ := membership.NormalizeNodeID(nodeID)
	if n, ok := s.registry.GetNode(canonicalID); ok && n.Endpoint != "" {
		return n.Endpoint
	}

	approved := s.monitor.GetAuthorizedParticipants()
	if entry, ok := approved[canonicalID]; ok && entry.Endpoint != "" {
		return entry.Endpoint
	}
	if entry, ok := approved[nodeID]; ok && entry.Endpoint != "" {
		return entry.Endpoint
	}

	for _, st := range s.monitor.GetNodeStates() {
		if st.NodeID == canonicalID || st.NodeID == nodeID {
			if st.Endpoint != "" {
				return st.Endpoint
			}
		}
	}

	return ""
}

// postNodeJSON dispatches an authenticated HTTP POST request to a node endpoint
func (s *Server) postNodeJSON(url string, reqBody interface{}, respDest interface{}) error {
	return s.postNodeJSONWithAuth(url, reqBody, respDest, "")
}

// postNodeJSONWithAuth dispatches an authenticated HTTP POST request forwarding a caller Bearer token
func (s *Server) postNodeJSONWithAuth(url string, reqBody interface{}, respDest interface{}, bearerToken string) error {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(bearerToken, "Bearer "))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("node %s returned HTTP %d: %s", url, resp.StatusCode, string(b))
	}

	if respDest != nil {
		if err := json.NewDecoder(resp.Body).Decode(respDest); err != nil {
			return fmt.Errorf("failed to decode response from %s: %w", url, err)
		}
	}
	return nil
}

// getNodeJSON dispatches an authenticated HTTP GET request to a node endpoint
func (s *Server) getNodeJSON(url string, respDest interface{}) error {
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("node %s returned HTTP %d: %s", url, resp.StatusCode, string(b))
	}

	if respDest != nil {
		if err := json.NewDecoder(resp.Body).Decode(respDest); err != nil {
			return fmt.Errorf("failed to decode response from %s: %w", url, err)
		}
	}
	return nil
}

// handleCreateAVSSSession validates parameters, coordinates node session creation, and triggers the dealer.
func (s *Server) handleCreateAVSSSession(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID   string   `json:"sessionId"`
		CommitteeID string   `json:"committeeId"`
		DealerID    string   `json:"dealerId"`
		N           int      `json:"n"`
		K           int      `json:"k"`
		T           int      `json:"t"`
		Committee   []string `json:"committee"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
		}
	}

	if req.DealerID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: "dealerId is required"}
	}
	canonicalDealer, _ := membership.NormalizeNodeID(req.DealerID)
	req.DealerID = canonicalDealer

	// Resolve committee
	committee := req.Committee
	if len(committee) == 0 {
		if req.N == 5 {
			// Default to domain nodes
			for _, n := range s.registry.GetAllNodes() {
				committee = append(committee, n.NodeID)
			}
		} else {
			// Gather all 15 nodes from approved registry or domain
			allParts := s.monitor.GetAuthorizedParticipants()
			for id := range allParts {
				committee = append(committee, id)
			}
			if len(committee) == 0 {
				for _, n := range s.registry.GetAllNodes() {
					committee = append(committee, n.NodeID)
				}
			}
		}
	}

	// Normalize committee members
	normalizedCommittee := make([]string, 0, len(committee))
	dealerInCommittee := false
	for _, member := range committee {
		cID, _ := membership.NormalizeNodeID(member)
		normalizedCommittee = append(normalizedCommittee, cID)
		if cID == req.DealerID {
			dealerInCommittee = true
		}
	}
	sort.Strings(normalizedCommittee)
	if !dealerInCommittee {
		return nil, &JsonRpcErr{Code: -32602, Message: fmt.Sprintf("dealerId %s must be a member of the committee", req.DealerID)}
	}

	n := len(normalizedCommittee)
	if req.N > 0 && req.N != n {
		return nil, &JsonRpcErr{Code: -32602, Message: fmt.Sprintf("specified n=%d does not match committee size %d", req.N, n)}
	}
	req.N = n

	// Validate AVSS dual-threshold parameters: n - 2*t >= k and k > t
	if err := ValidateAVSSParameters(req.N, req.K, req.T); err != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: err.Error()}
	}

	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("avss-%s-%d", strings.ToLower(string(s.domain)), time.Now().UnixNano())
	}
	if req.CommitteeID == "" {
		req.CommitteeID = fmt.Sprintf("comm-%d", req.N)
	}

	// Step 1: Initialize session on all committee nodes
	nodeErrors := make(map[string]string)
	for _, memberID := range normalizedCommittee {
		ep := s.getNodeEndpoint(memberID)
		if ep == "" {
			nodeErrors[memberID] = "endpoint not resolved"
			continue
		}

		sessionPayload := map[string]interface{}{
			"sessionId":   req.SessionID,
			"committeeId": req.CommitteeID,
			"dealerId":    req.DealerID,
			"epoch":       1,
			"n":           req.N,
			"k":           req.K,
			"t":           req.T,
			"committee":   normalizedCommittee,
		}

		var resp map[string]interface{}
		if err := s.postNodeJSON(ep+"/node/avss/session/create", sessionPayload, &resp); err != nil {
			nodeErrors[memberID] = err.Error()
		}
	}

	if len(nodeErrors) > req.T {
		return nil, &JsonRpcErr{
			Code:    -32001,
			Message: fmt.Sprintf("Failed to initialize session on %d nodes (exceeds fault bound t=%d)", len(nodeErrors), req.T),
			Data:    nodeErrors,
		}
	}

	// Step 2: Trigger dealer to generate sharing and distribute slices
	dealerEp := s.getNodeEndpoint(req.DealerID)
	if dealerEp == "" {
		return nil, &JsonRpcErr{Code: -32002, Message: fmt.Sprintf("Dealer endpoint for %s not found", req.DealerID)}
	}

	dealerPayload := map[string]interface{}{
		"sessionId":   req.SessionID,
		"committeeId": req.CommitteeID,
		"committee":   normalizedCommittee,
		"k":           req.K,
	}

	var dealerResp struct {
		Success          bool        `json:"success"`
		SessionID        string      `json:"sessionId"`
		Commitments      [][]string  `json:"commitments"`
		SecretCommitment string      `json:"secretCommitment"`
		Error            string      `json:"error,omitempty"`
	}

	if err := s.postNodeJSON(dealerEp+"/node/avss/dealer/start", dealerPayload, &dealerResp); err != nil {
		return nil, &JsonRpcErr{Code: -32003, Message: fmt.Sprintf("Dealer start failed: %s", err.Error())}
	}

	// Record session metadata in coordinator (zero secret knowledge)
	s.avssMu.Lock()
	if s.avssSessions == nil {
		s.avssSessions = make(map[string]*AVSSSessionInfo)
	}
	s.avssSessions[req.SessionID] = &AVSSSessionInfo{
		SessionID:        req.SessionID,
		CommitteeID:      req.CommitteeID,
		DealerID:         req.DealerID,
		Epoch:            1,
		N:                req.N,
		K:                req.K,
		T:                req.T,
		Committee:        normalizedCommittee,
		SecretCommitment: dealerResp.SecretCommitment,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		Status:           "INITIATED",
	}
	s.avssMu.Unlock()

	log.Printf("[SARAL Coordinator - %s] Successfully started AVSS session %s (n=%d, k=%d, t=%d, dealer=%s)",
		s.domain, req.SessionID, req.N, req.K, req.T, req.DealerID)

	return map[string]interface{}{
		"success":          true,
		"sessionId":        req.SessionID,
		"committeeId":      req.CommitteeID,
		"dealerId":         req.DealerID,
		"n":                req.N,
		"k":                req.K,
		"t":                req.T,
		"committee":        normalizedCommittee,
		"secretCommitment": dealerResp.SecretCommitment,
		"status":           "INITIATED",
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// handleGetAVSSSessionStatus queries committee nodes and returns aggregated session progress
func (s *Server) handleGetAVSSSessionStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(params, &req); err != nil || req.SessionID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: "sessionId required"}
	}

	s.avssMu.RLock()
	sessionInfo, exists := s.avssSessions[req.SessionID]
	s.avssMu.RUnlock()

	var committee []string
	if exists {
		committee = sessionInfo.Committee
	} else {
		for _, n := range s.registry.GetAllNodes() {
			committee = append(committee, n.NodeID)
		}
	}

	type NodeProgress struct {
		NodeID                 string `json:"nodeId"`
		State                  string `json:"state"`
		EchoCount              int    `json:"echoCount"`
		ReadyCount             int    `json:"readyCount"`
		Completed              bool   `json:"completed"`
		PublicShareCommitment  string `json:"publicShareCommitment,omitempty"`
		PublicSecretCommitment string `json:"publicSecretCommitment,omitempty"`
		Error                  string `json:"error,omitempty"`
	}

	nodeResults := make(map[string]NodeProgress)
	completedCount := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, memberID := range committee {
		wg.Add(1)
		go func(mID string) {
			defer wg.Done()
			ep := s.getNodeEndpoint(mID)
			if ep == "" {
				mu.Lock()
				nodeResults[mID] = NodeProgress{NodeID: mID, State: "UNKNOWN", Error: "endpoint unresolved"}
				mu.Unlock()
				return
			}

			var st struct {
				SessionID              string `json:"sessionId"`
				NodeID                 string `json:"nodeId"`
				State                  string `json:"state"`
				EchoCount              int    `json:"echoCount"`
				ReadyCount             int    `json:"readyCount"`
				Completed              bool   `json:"completed"`
				PublicShareCommitment  string `json:"publicShareCommitment"`
				PublicSecretCommitment string `json:"publicSecretCommitment"`
			}

			err := s.getNodeJSON(fmt.Sprintf("%s/node/avss/session/status?sessionId=%s", ep, req.SessionID), &st)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				nodeResults[mID] = NodeProgress{NodeID: mID, State: "UNREACHABLE", Error: err.Error()}
				return
			}

			if st.Completed {
				completedCount++
			}
			nodeResults[mID] = NodeProgress{
				NodeID:                 mID,
				State:                  st.State,
				EchoCount:              st.EchoCount,
				ReadyCount:             st.ReadyCount,
				Completed:              st.Completed,
				PublicShareCommitment:  st.PublicShareCommitment,
				PublicSecretCommitment: st.PublicSecretCommitment,
			}
		}(memberID)
	}

	wg.Wait()

	overallStatus := "IN_PROGRESS"
	if sessionInfo != nil {
		if completedCount >= sessionInfo.K+sessionInfo.T || completedCount == len(committee) {
			overallStatus = "SHARING_COMPLETED"
			s.avssMu.Lock()
			sessionInfo.Status = overallStatus
			s.avssMu.Unlock()
		}
	} else if completedCount > 0 {
		overallStatus = "ACTIVE"
	}

	return map[string]interface{}{
		"sessionId":      req.SessionID,
		"status":         overallStatus,
		"completedNodes": completedCount,
		"totalNodes":     len(committee),
		"nodes":          nodeResults,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// handleGetAVSSParticipants returns active committee membership for a session
func (s *Server) handleGetAVSSParticipants(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID   string `json:"sessionId"`
		CommitteeID string `json:"committeeId"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &req)
	}

	s.avssMu.RLock()
	sess, exists := s.avssSessions[req.SessionID]
	s.avssMu.RUnlock()

	if exists {
		return map[string]interface{}{
			"sessionId":   sess.SessionID,
			"committeeId": sess.CommitteeID,
			"dealerId":    sess.DealerID,
			"n":           sess.N,
			"k":           sess.K,
			"t":           sess.T,
			"committee":   sess.Committee,
		}, nil
	}

	// Default fallback to authorized registry
	return s.monitor.GetAuthorizedParticipants(), nil
}

// handleGetAVSSCommitments fetches the public commitment matrix from dealer or node
func (s *Server) handleGetAVSSCommitments(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(params, &req); err != nil || req.SessionID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: "sessionId required"}
	}

	s.avssMu.RLock()
	sess, exists := s.avssSessions[req.SessionID]
	s.avssMu.RUnlock()

	var targetNode string
	if exists && sess.DealerID != "" {
		targetNode = sess.DealerID
	} else {
		// Pick first available node
		nodes := s.registry.GetAllNodes()
		if len(nodes) > 0 {
			targetNode = nodes[0].NodeID
		}
	}

	ep := s.getNodeEndpoint(targetNode)
	if ep == "" {
		return nil, &JsonRpcErr{Code: -32002, Message: "Could not locate node to query commitments"}
	}

	var resp struct {
		SessionID        string     `json:"sessionId"`
		Commitments      [][]string `json:"commitments"`
		SecretCommitment string     `json:"secretCommitment"`
	}

	if err := s.getNodeJSON(fmt.Sprintf("%s/node/avss/commitments?sessionId=%s", ep, req.SessionID), &resp); err != nil {
		return nil, &JsonRpcErr{Code: -32003, Message: fmt.Sprintf("Failed to fetch commitments: %s", err.Error())}
	}

	return resp, nil
}

// handleGetAVSSVerificationStatus aggregates individual verification statuses across committee
func (s *Server) handleGetAVSSVerificationStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(params, &req); err != nil || req.SessionID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: "sessionId required"}
	}

	s.avssMu.RLock()
	sess, exists := s.avssSessions[req.SessionID]
	s.avssMu.RUnlock()

	var committee []string
	if exists {
		committee = sess.Committee
	} else {
		for _, n := range s.registry.GetAllNodes() {
			committee = append(committee, n.NodeID)
		}
	}

	type VerificationReport struct {
		NodeID         string `json:"nodeId"`
		HasRowPoly     bool   `json:"hasRowPoly"`
		HasColPoly     bool   `json:"hasColPoly"`
		EchoCount      int    `json:"echoCount"`
		ReadyCount     int    `json:"readyCount"`
		RequiredEchos  int    `json:"requiredEchos"`
		RequiredReadys int    `json:"requiredReadys"`
		State          string `json:"state"`
		Error          string `json:"error,omitempty"`
	}

	results := make(map[string]VerificationReport)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, mID := range committee {
		wg.Add(1)
		go func(memberID string) {
			defer wg.Done()
			ep := s.getNodeEndpoint(memberID)
			if ep == "" {
				mu.Lock()
				results[memberID] = VerificationReport{NodeID: memberID, State: "UNKNOWN", Error: "endpoint unresolved"}
				mu.Unlock()
				return
			}

			var v struct {
				SessionID      string `json:"sessionId"`
				NodeID         string `json:"nodeId"`
				HasRowPoly     bool   `json:"hasRowPoly"`
				HasColPoly     bool   `json:"hasColPoly"`
				EchoCount      int    `json:"echoCount"`
				ReadyCount     int    `json:"readyCount"`
				RequiredEchos  int    `json:"requiredEchos"`
				RequiredReadys int    `json:"requiredReadys"`
				State          string `json:"state"`
			}

			err := s.getNodeJSON(fmt.Sprintf("%s/node/avss/verification/status?sessionId=%s", ep, req.SessionID), &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[memberID] = VerificationReport{NodeID: memberID, State: "UNREACHABLE", Error: err.Error()}
				return
			}
			results[memberID] = VerificationReport{
				NodeID:         v.NodeID,
				HasRowPoly:     v.HasRowPoly,
				HasColPoly:     v.HasColPoly,
				EchoCount:      v.EchoCount,
				ReadyCount:     v.ReadyCount,
				RequiredEchos:  v.RequiredEchos,
				RequiredReadys: v.RequiredReadys,
				State:          v.State,
			}
		}(mID)
	}

	wg.Wait()

	return map[string]interface{}{
		"sessionId": req.SessionID,
		"nodes":     results,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// handleGetProactiveEpochStatus returns proactive manager status across domain nodes
func (s *Server) handleGetProactiveEpochStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	nodes := s.registry.GetAllNodes()
	type EpochNodeStatus struct {
		NodeID            string `json:"nodeId"`
		CurrentEpoch      uint64 `json:"currentEpoch"`
		EpochState        string `json:"epochState"`
		ShareVersion      uint64 `json:"shareVersion"`
		CommitmentVersion uint64 `json:"commitmentVersion"`
		IsRefreshing      bool   `json:"isRefreshing"`
		Error             string `json:"error,omitempty"`
	}

	statuses := make(map[string]EpochNodeStatus)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, n := range nodes {
		wg.Add(1)
		go func(node membership.NodeInfo) {
			defer wg.Done()
			var res struct {
				NodeID            string `json:"nodeId"`
				CurrentEpoch      uint64 `json:"currentEpoch"`
				EpochState        string `json:"epochState"`
				ShareVersion      uint64 `json:"shareVersion"`
				CommitmentVersion uint64 `json:"commitmentVersion"`
				IsRefreshing      bool   `json:"isRefreshing"`
			}
			err := s.getNodeJSON(node.Endpoint+"/node/proactive/status", &res)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				statuses[node.NodeID] = EpochNodeStatus{NodeID: node.NodeID, Error: err.Error()}
				return
			}
			statuses[node.NodeID] = EpochNodeStatus{
				NodeID:            res.NodeID,
				CurrentEpoch:      res.CurrentEpoch,
				EpochState:        res.EpochState,
				ShareVersion:      res.ShareVersion,
				CommitmentVersion: res.CommitmentVersion,
				IsRefreshing:      res.IsRefreshing,
			}
		}(n)
	}

	wg.Wait()

	return map[string]interface{}{
		"domain":    s.domain,
		"nodes":     statuses,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// handleRequestProactiveRefresh validates strict Cachin et al. bounds and initiates share refresh across committee
func (s *Server) handleRequestProactiveRefresh(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	var req struct {
		CommitteeID      string            `json:"committeeId"`
		Committee        []string          `json:"committee"`
		K                int               `json:"k"`
		T                int               `json:"t"`
		PeerCommitments  map[string]string `json:"peerCommitments"`
		MasterCommitment string            `json:"masterCommitment"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	committee := req.Committee
	if len(committee) == 0 {
		for _, n := range s.registry.GetAllNodes() {
			committee = append(committee, n.NodeID)
		}
	}
	n := len(committee)

	// Validate strict proactive bounds: k = t + 1 and n > 3*t
	// Rejects Configuration C (k=3, t=1) because dual-threshold AVSS does not inherit Cachin proactive refresh proof
	if err := ValidateProactiveParameters(n, req.K, req.T); err != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: err.Error()}
	}

	if req.CommitteeID == "" {
		req.CommitteeID = fmt.Sprintf("comm-%d", n)
	}

	refreshPayload := map[string]interface{}{
		"committeeId":      req.CommitteeID,
		"committee":        committee,
		"k":                req.K,
		"t":                req.T,
		"peerCommitments":  req.PeerCommitments,
		"masterCommitment": req.MasterCommitment,
	}

	dispatchedCount := 0
	nodeErrors := make(map[string]string)

	for _, memberID := range committee {
		ep := s.getNodeEndpoint(memberID)
		if ep == "" {
			nodeErrors[memberID] = "endpoint unresolved"
			continue
		}

		var resp map[string]interface{}
		if err := s.postNodeJSON(ep+"/node/proactive/refresh", refreshPayload, &resp); err != nil {
			nodeErrors[memberID] = err.Error()
		} else {
			dispatchedCount++
		}
	}

	if dispatchedCount < req.K {
		return nil, &JsonRpcErr{
			Code:    -32001,
			Message: fmt.Sprintf("Failed to initiate proactive refresh on enough nodes: only %d responded (need at least k=%d)", dispatchedCount, req.K),
			Data:    nodeErrors,
		}
	}

	log.Printf("[SARAL Coordinator - %s] Dispatched proactive refresh to %d nodes in committee %s",
		s.domain, dispatchedCount, req.CommitteeID)

	return map[string]interface{}{
		"success":         true,
		"committeeId":     req.CommitteeID,
		"dispatchedNodes": dispatchedCount,
		"totalNodes":      n,
		"k":               req.K,
		"t":               req.T,
		"status":          "REFRESH_DISPATCHED",
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// handleGetRefreshStatus returns proactive refresh state across the committee
func (s *Server) handleGetRefreshStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	return s.handleGetProactiveEpochStatus(params)
}
