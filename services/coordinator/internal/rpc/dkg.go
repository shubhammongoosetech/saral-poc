package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

// DKGSessionMeta stores coordinator-level public tracking for a DKG session.
// STRICT PRIVACY GUARANTEE: Coordinators NEVER receive, handle, or store private secret shares.
type DKGSessionMeta struct {
	SessionID              string                            `json:"sessionId"`
	CommitteeID            string                            `json:"committeeId"`
	WalletID               string                            `json:"walletId,omitempty"`
	UserID                 string                            `json:"userId,omitempty"`
	Epoch                  uint64                            `json:"epoch"`
	N                      int                               `json:"n"`
	K                      int                               `json:"k"`
	T                      int                               `json:"t"`
	State                  string                            `json:"state"`
	Committee              []string                          `json:"committee"`
	QualifiedSet           []string                          `json:"qualifiedSet,omitempty"`
	MasterSigningPublicKey string                            `json:"masterSigningPublicKey,omitempty"` // Y = x*G
	MasterSecretCommitment string                            `json:"masterSecretCommitment,omitempty"` // C = x*G + x'*H
	MasterPublicKey        string                            `json:"masterPublicKey,omitempty"`        // signing key
	Curve                  string                            `json:"curve"`
	Participants           map[string]*DKGParticipantSummary `json:"participants"`
	CreatedAt              string                            `json:"createdAt"`
	UpdatedAt              string                            `json:"updatedAt"`
	Error                  string                            `json:"error,omitempty"`
}

// DKGParticipantSummary stores public participant progress on coordinator
type DKGParticipantSummary struct {
	NodeID            string `json:"nodeId"`
	NodeIndex         int    `json:"nodeIndex"`
	ContributionDealt bool   `json:"contributionDealt"`
	SecretCommitment  string `json:"secretCommitment,omitempty"`
	CompletedSharings int    `json:"completedSharings"`
	InQualifiedSet    bool   `json:"inQualifiedSet"`
	PublicShareCommit string `json:"publicShareCommit,omitempty"`
	Status            string `json:"status"`
}

// ValidateDKGParameters validates DKG fault constraints:
// n > 3*t (Byzantine Consensus), n - 2*t >= k (AVSS reconstruction), k >= t + 1 (Fault tolerance)
func ValidateDKGParameters(n, k, t int) error {
	if n <= 0 || k <= 0 || t <= 0 {
		return fmt.Errorf("invalid DKG parameters: n, k, and t must be positive integers (got n=%d, k=%d, t=%d)", n, k, t)
	}
	if n <= 3*t {
		return fmt.Errorf("invalid DKG parameters: consensus requires n > 3t (got n=%d, t=%d, 3t=%d)", n, t, 3*t)
	}
	if n-2*t < k {
		return fmt.Errorf("invalid DKG parameters: reconstruction requires n - 2t >= k (got %d - 2*%d = %d < %d)", n, t, n-2*t, k)
	}
	if k < t+1 {
		return fmt.Errorf("invalid DKG parameters: threshold k must be at least t + 1 (got k=%d, t=%d)", k, t)
	}
	return nil
}

// handleStartDKG coordinates initialization of a Dealerless DKG across the committee nodes
func (s *Server) handleStartDKG(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	// Verify operator authorization
	if s.verifierClient != nil && token != "" {
		if _, err := s.verifierClient.VerifyTokenWithRole(token, "operator"); err != nil {
			return nil, &JsonRpcErr{Code: -32001, Message: fmt.Sprintf("Authorization rejected: %s", err.Error())}
		}
	}

	var req struct {
		SessionID   string   `json:"sessionId"`
		CommitteeID string   `json:"committeeId"`
		N           int      `json:"n"`
		K           int      `json:"k"`
		T           int      `json:"t"`
		Committee   []string `json:"committee"`
		WalletID    string   `json:"walletId"`
		KeyID       string   `json:"keyId"`
		UserID      string   `json:"userId"`
		Curve       string   `json:"curve"`
		ChainFamily string   `json:"chainFamily"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
		}
	}

	// Resolve committee
	committee := req.Committee
	if len(committee) == 0 {
		if req.N == 5 {
			for _, n := range s.registry.GetAllNodes() {
				committee = append(committee, n.NodeID)
			}
		} else {
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

	normalizedCommittee := make([]string, 0, len(committee))
	for _, m := range committee {
		cID, _ := membership.NormalizeNodeID(m)
		normalizedCommittee = append(normalizedCommittee, cID)
	}
	sort.Strings(normalizedCommittee)

	n := len(normalizedCommittee)
	if req.N > 0 && req.N != n {
		return nil, &JsonRpcErr{Code: -32602, Message: fmt.Sprintf("specified n=%d does not match committee size %d", req.N, n)}
	}
	req.N = n

	// Default threshold parameters:
	// Each coordinator handles only its own domain's nodes (n=5, k=3, t=1)
	if req.K == 0 && req.T == 0 {
		if req.N == 5 {
			req.K = 3
			req.T = 1
		} else {
			req.T = (req.N - 1) / 3
			if req.T < 1 {
				req.T = 1
			}
			req.K = req.N - 2*req.T
		}
	}

	if err := ValidateDKGParameters(req.N, req.K, req.T); err != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: err.Error()}
	}

	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("dkg-%s-%d", strings.ToLower(string(s.domain)), time.Now().UnixNano())
	}
	expectedCommitteeID := fmt.Sprintf("committee-%s", strings.ToLower(string(s.domain)))
	if req.CommitteeID == "" {
		req.CommitteeID = expectedCommitteeID
	} else if req.CommitteeID != expectedCommitteeID {
		return nil, &JsonRpcErr{
			Code:    -32602,
			Message: fmt.Sprintf("invalid committeeId %q for %s coordinator: expected %q", req.CommitteeID, s.domain, expectedCommitteeID),
		}
	}

	// Step 1: Initialize session on each committee node with authenticated bindings
	nodeErrors := make(map[string]string)
	for _, memberID := range normalizedCommittee {
		ep := s.getNodeEndpoint(memberID)
		if ep == "" {
			nodeErrors[memberID] = "endpoint not resolved"
			continue
		}

		initPayload := map[string]interface{}{
			"sessionId":   req.SessionID,
			"committeeId": req.CommitteeID,
			"n":           req.N,
			"k":           req.K,
			"t":           req.T,
			"committee":   normalizedCommittee,
			"walletId":    req.WalletID,
			"keyId":       req.KeyID,
			"userId":      req.UserID,
			"curve":       req.Curve,
			"chainFamily": req.ChainFamily,
		}
		var initResp map[string]interface{}
		if err := s.postNodeJSON(ep+"/node/dkg/init", initPayload, &initResp); err != nil {
			nodeErrors[memberID] = err.Error()
		}
	}

	if len(nodeErrors) > req.T {
		return nil, &JsonRpcErr{
			Code:    -32000,
			Message: fmt.Sprintf("Failed to initialize DKG on sufficient nodes (failures: %v)", nodeErrors),
		}
	}

	// Step 2: Trigger nodes to independently start dealing their contributions
	var wg sync.WaitGroup
	for _, memberID := range normalizedCommittee {
		if _, failed := nodeErrors[memberID]; failed {
			continue
		}
		ep := s.getNodeEndpoint(memberID)
		wg.Add(1)
		go func(endpoint, mID string) {
			defer wg.Done()
			startPayload := map[string]interface{}{"sessionId": req.SessionID}
			var startResp map[string]interface{}
			_ = s.postNodeJSON(endpoint+"/node/dkg/start", startPayload, &startResp)
		}(ep, memberID)
	}
	wg.Wait()

	participants := make(map[string]*DKGParticipantSummary, req.N)
	for idx, id := range normalizedCommittee {
		participants[id] = &DKGParticipantSummary{
			NodeID:            id,
			NodeIndex:         idx + 1,
			ContributionDealt: nodeErrors[id] == "",
			Status:            "CONTRIBUTIONS_STARTED",
		}
	}

	curve := req.Curve
	if curve == "" {
		if strings.EqualFold(req.ChainFamily, "solana") {
			curve = "ed25519"
		} else {
			curve = "secp256k1"
		}
	}

	meta := &DKGSessionMeta{
		SessionID:    req.SessionID,
		CommitteeID:  req.CommitteeID,
		WalletID:     req.WalletID,
		UserID:       req.UserID,
		Epoch:        1,
		N:            req.N,
		K:            req.K,
		T:            req.T,
		State:        "CONTRIBUTIONS_STARTED",
		Committee:    normalizedCommittee,
		Curve:        curve,
		Participants: participants,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	s.avssMu.Lock()
	if s.dkgSessions == nil {
		s.dkgSessions = make(map[string]*DKGSessionMeta)
	}
	s.dkgSessions[req.SessionID] = meta
	s.avssMu.Unlock()

	s.persistSession(meta)

	return map[string]interface{}{
		"success":     true,
		"sessionId":   req.SessionID,
		"committeeId": req.CommitteeID,
		"state":       "CONTRIBUTIONS_STARTED",
		"n":           req.N,
		"k":           req.K,
		"t":           req.T,
		"committee":   normalizedCommittee,
	}, nil
}

// handleGetDKGStatus queries current DKG progress across committee nodes
func (s *Server) handleGetDKGStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &req)
	}

	s.avssMu.RLock()
	var meta *DKGSessionMeta
	if req.SessionID != "" && s.dkgSessions != nil {
		meta = s.dkgSessions[req.SessionID]
	} else if s.dkgSessions != nil {
		for _, m := range s.dkgSessions {
			meta = m
			break
		}
	}
	s.avssMu.RUnlock()

	if meta == nil {
		return map[string]interface{}{
			"status":  "NO_ACTIVE_DKG_SESSION",
			"message": "No DKG sessions recorded on coordinator",
		}, nil
	}

	// Query each node's local public DKG view
	type nodeView struct {
		State                  string                            `json:"state"`
		MasterSigningPublicKey string                            `json:"masterSigningPublicKey"`
		MasterSecretCommitment string                            `json:"masterSecretCommitment"`
		MasterPublicKey        string                            `json:"masterPublicKey"`
		QualifiedSet           []string                          `json:"qualifiedSet"`
		Participants           map[string]*DKGParticipantSummary `json:"participants"`
	}

	completedCount := 0
	var agreedPubkey string
	var agreedSigningKey string
	var agreedSecretCommit string
	var agreedQUAL []string

	for _, memberID := range meta.Committee {
		ep := s.getNodeEndpoint(memberID)
		if ep == "" {
			continue
		}
		var nv nodeView
		if err := s.getNodeJSON(fmt.Sprintf("%s/node/dkg/status?sessionId=%s", ep, meta.SessionID), &nv); err == nil {
			if nv.State == "COMPLETED" {
				completedCount++
				if agreedPubkey == "" && nv.MasterPublicKey != "" {
					agreedPubkey = nv.MasterPublicKey
					agreedSigningKey = nv.MasterSigningPublicKey
					agreedSecretCommit = nv.MasterSecretCommitment
					agreedQUAL = nv.QualifiedSet
				}
			}
			if p, ok := meta.Participants[memberID]; ok {
				if nv.State == "COMPLETED" {
					p.Status = "COMPLETED"
					p.InQualifiedSet = true
				}
			}
		}
	}

	if completedCount >= meta.N-meta.T {
		meta.State = "COMPLETED"
		meta.MasterPublicKey = agreedPubkey
		meta.MasterSigningPublicKey = agreedSigningKey
		meta.MasterSecretCommitment = agreedSecretCommit
		meta.QualifiedSet = agreedQUAL
		meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.persistSession(meta)
	}

	return map[string]interface{}{
		"sessionId":              meta.SessionID,
		"committeeId":            meta.CommitteeID,
		"epoch":                  meta.Epoch,
		"n":                      meta.N,
		"k":                      meta.K,
		"t":                      meta.T,
		"state":                  meta.State,
		"committee":              meta.Committee,
		"qualifiedSet":           meta.QualifiedSet,
		"masterSigningPublicKey": meta.MasterSigningPublicKey,
		"masterSecretCommitment": meta.MasterSecretCommitment,
		"masterPublicKey":        meta.MasterPublicKey,
		"curve":                  meta.Curve,
		"completedNodes":         completedCount,
		"totalNodes":             meta.N,
		"participants":           meta.Participants,
	}, nil
}

// handleGetDKGParticipants returns participant progress for a DKG session
func (s *Server) handleGetDKGParticipants(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG participants"}
	}
	return map[string]interface{}{
		"sessionId":    m["sessionId"],
		"committeeId":  m["committeeId"],
		"participants": m["participants"],
		"qualifiedSet": m["qualifiedSet"],
	}, nil
}

// handleGetDKGPublicKey returns the agreed master public key
func (s *Server) handleGetDKGPublicKey(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG public key"}
	}
	return map[string]interface{}{
		"sessionId":       m["sessionId"],
		"committeeId":     m["committeeId"],
		"masterPublicKey": m["masterPublicKey"],
		"curve":           m["curve"],
		"threshold":       m["k"],
		"state":           m["state"],
	}, nil
}

// handleGetDKGVerificationStatus returns public verification status across participants
func (s *Server) handleGetDKGVerificationStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDKGStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG verification status"}
	}
	allVerified := (m["state"] == "COMPLETED")
	return map[string]interface{}{
		"sessionId":       m["sessionId"],
		"committeeId":     m["committeeId"],
		"verified":        allVerified,
		"state":           m["state"],
		"masterPublicKey": m["masterPublicKey"],
		"qualifiedSet":    m["qualifiedSet"],
		"completedNodes":  m["completedNodes"],
		"totalNodes":      m["totalNodes"],
	}, nil
}

type DerivePublicKeyParams struct {
	WalletID     string `json:"walletId"`
	UserID       string `json:"userId"`
	KeyID        string `json:"keyId"`
	DKGSessionID string `json:"dkgSessionId"`
	CommitteeID  string `json:"committeeId"`
	Curve        string `json:"curve"`
	ChainFamily  string `json:"chainFamily"`
	Epoch        uint64 `json:"epoch"`
}

// handleDerivePublicKey resolves existing verified distributed DKG shares from committee nodes
// and mathematically reconstructs the same aggregate signing public key Y = \sum \lambda_i Y_i
// WITHOUT EVER exposing or reconstructing the master private scalar x.
func (s *Server) handleDerivePublicKey(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	// 1. Authorize caller via Verifier
	if s.verifierClient != nil && token != "" {
		res, err := s.verifierClient.VerifyTokenWithRole(token, "operator")
		if err != nil {
			return nil, &JsonRpcErr{Code: -32001, Message: fmt.Sprintf("Authorization rejected: %s", err.Error())}
		}
		// Validate ownership bindings if provided in claims
		if res != nil && res.Claims != nil {
			if mfa, ok := res.Claims["mfaVerified"].(bool); !ok || !mfa {
				return nil, &JsonRpcErr{Code: -32001, Message: "MFA verification claim required"}
			}
		}
	}

	var req DerivePublicKeyParams
	if len(params) > 0 {
		_ = json.Unmarshal(params, &req)
	}

	sessionID := req.DKGSessionID
	if sessionID == "" {
		sessionID = req.KeyID
	}
	if sessionID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: "dkgSessionId is required"}
	}

	expectedCommitteeID := fmt.Sprintf("committee-%s", strings.ToLower(string(s.domain)))
	if req.CommitteeID == "" {
		return nil, &JsonRpcErr{Code: -32602, Message: fmt.Sprintf("committeeId is required (expected %s)", expectedCommitteeID)}
	}
	if req.CommitteeID != expectedCommitteeID {
		return nil, &JsonRpcErr{
			Code:    -32602,
			Message: fmt.Sprintf("invalid committeeId %q for %s coordinator: expected %q", req.CommitteeID, s.domain, expectedCommitteeID),
		}
	}

	epoch := req.Epoch
	if epoch == 0 {
		epoch = 1
	}

	s.avssMu.RLock()
	var meta *DKGSessionMeta
	if s.dkgSessions != nil && sessionID != "" {
		meta = s.dkgSessions[sessionID]
	}
	s.avssMu.RUnlock()

	if meta == nil {
		return nil, &JsonRpcErr{
			Code:    -32004,
			Message: fmt.Sprintf("DKG session %q not found on coordinator", sessionID),
		}
	}

	// Verify session bindings
	if meta.CommitteeID != req.CommitteeID {
		return nil, &JsonRpcErr{
			Code:    -32001,
			Message: fmt.Sprintf("committeeId mismatch: session has %s, request specified %s", meta.CommitteeID, req.CommitteeID),
		}
	}
	if meta.WalletID != "" && req.WalletID != "" && meta.WalletID != req.WalletID {
		return nil, &JsonRpcErr{
			Code:    -32001,
			Message: fmt.Sprintf("walletId mismatch: session bound to %s, request specified %s", meta.WalletID, req.WalletID),
		}
	}
	if meta.UserID != "" && req.UserID != "" && meta.UserID != req.UserID {
		return nil, &JsonRpcErr{
			Code:    -32001,
			Message: fmt.Sprintf("userId mismatch: session bound to %s, request specified %s", meta.UserID, req.UserID),
		}
	}

	committee := meta.Committee
	kThreshold := meta.K
	if kThreshold <= 0 {
		kThreshold = 3
	}

	curveName := "secp256k1"
	if req.Curve != "" {
		curveName = req.Curve
	} else if meta != nil && meta.Curve != "" {
		curveName = meta.Curve
	} else if strings.EqualFold(req.ChainFamily, "solana") {
		curveName = "ed25519"
	} else if strings.EqualFold(req.ChainFamily, "evm") || strings.EqualFold(req.ChainFamily, "bitcoin") || strings.EqualFold(req.ChainFamily, "mst") {
		curveName = "secp256k1"
	}

	type nodeContribution struct {
		NodeID                 string `json:"nodeId"`
		NodeIndex              int    `json:"nodeIndex"`
		Epoch                  uint64 `json:"epoch"`
		PublicPoint            string `json:"publicPoint"`
		PublicSecretCommitment string `json:"publicSecretCommitment"`
	}

	// Query committee nodes for their public point contributions Y_i = x_i * G
	type indexedPoint struct {
		Index int
		Point *CurvePoint
	}
	var validPoints []indexedPoint
	var pointsMu sync.Mutex
	var wg sync.WaitGroup

	for _, memberID := range committee {
		ep := s.getNodeEndpoint(memberID)
		if ep == "" {
			continue
		}
		wg.Add(1)
		go func(endpoint, mID string) {
			defer wg.Done()
			payload := map[string]interface{}{
				"sessionId":   sessionID,
				"committeeId": req.CommitteeID,
				"epoch":       epoch,
				"userId":      req.UserID,
				"walletId":    req.WalletID,
				"keyId":       req.KeyID,
				"curve":       curveName,
				"chainFamily": req.ChainFamily,
			}
			var resp nodeContribution
			if err := s.postNodeJSONWithAuth(endpoint+"/node/dkg/share-contribution", payload, &resp, token); err == nil && resp.PublicPoint != "" {
				ptBytes, decErr := hex.DecodeString(strings.TrimPrefix(resp.PublicPoint, "0x"))
				if decErr == nil {
					cp, parseErr := ParseCurvePointFromBytes(ptBytes)
					if parseErr == nil && cp != nil {
						pointsMu.Lock()
						validPoints = append(validPoints, indexedPoint{
							Index: resp.NodeIndex,
							Point: cp,
						})
						pointsMu.Unlock()
					}
				}
			}
		}(ep, memberID)
	}
	wg.Wait()

	// Strictly require at least threshold k verified node contributions
	if len(validPoints) < kThreshold {
		return nil, &JsonRpcErr{
			Code:    -32000,
			Message: fmt.Sprintf("insufficient verified node shares: obtained %d valid points, required threshold k=%d", len(validPoints), kThreshold),
		}
	}

	// Sort by node index
	sort.Slice(validPoints, func(i, j int) bool {
		return validPoints[i].Index < validPoints[j].Index
	})

	// Pick exactly k distinct points for Lagrange interpolation at x = 0
	kPoints := validPoints[:kThreshold]
	indices := make([]int, kThreshold)
	points := make([]*CurvePoint, kThreshold)
	for i := 0; i < kThreshold; i++ {
		indices[i] = kPoints[i].Index
		points[i] = kPoints[i].Point
	}

	reconstructedY, err := InterpolatePublicContributionsAtZeroForCurve(indices, points, curveName)
	if err != nil {
		return nil, &JsonRpcErr{Code: -32000, Message: fmt.Sprintf("failed computing Lagrange interpolation: %v", err)}
	}

	derivedHex := fmt.Sprintf("04%064x%064x", reconstructedY.X, reconstructedY.Y)

	// Derive address in RAM only without persistence
	derivedAddress := ""
	switch strings.ToLower(req.ChainFamily) {
	case "mst", "evm", "ethereum":
		derivedAddress = DeriveEvmAddress(reconstructedY)
	case "solana", "sol":
		derivedAddress = DeriveSolanaAddress(reconstructedY)
	case "bitcoin", "btc":
		derivedAddress = DeriveBitcoinTaprootAddress(reconstructedY, "tb")
	default:
		if strings.Contains(strings.ToLower(curveName), "secp256k1") {
			derivedAddress = DeriveEvmAddress(reconstructedY)
		} else if strings.Contains(strings.ToLower(curveName), "ed25519") {
			derivedAddress = DeriveSolanaAddress(reconstructedY)
		}
	}

	return map[string]interface{}{
		"success":         true,
		"walletId":        req.WalletID,
		"keyId":           req.KeyID,
		"sessionId":       sessionID,
		"committeeId":     req.CommitteeID,
		"epoch":           epoch,
		"curve":           curveName,
		"threshold":       kThreshold,
		"masterPublicKey": derivedHex,
		"derivedAddress":  derivedAddress,
	}, nil
}
