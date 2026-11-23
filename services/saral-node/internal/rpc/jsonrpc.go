package rpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/crypto"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/membership"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/relay"
)

type JsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type JsonRpcResponse struct {
	JsonRpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *JsonRpcErr `json:"error,omitempty"`
}

type JsonRpcErr struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type JSONRPCServer struct {
	idMgr       *identity.IdentityManager
	domain      string
	nodeIndex   int
	p2pMgr      *p2p.P2PManager
	relayRouter *relay.RelayRouter
	dkgEngine   *dkg.Engine
	startTime   time.Time
	httpClient  *http.Client
}

func NewJSONRPCServer(
	idMgr *identity.IdentityManager,
	domain string,
	nodeIndex int,
	p2pMgr *p2p.P2PManager,
	relayRouter *relay.RelayRouter,
	dkgEngine *dkg.Engine,
	startTime time.Time,
) *JSONRPCServer {
	return &JSONRPCServer{
		idMgr:       idMgr,
		domain:      domain,
		nodeIndex:   nodeIndex,
		p2pMgr:      p2pMgr,
		relayRouter: relayRouter,
		dkgEngine:   dkgEngine,
		startTime:   startTime,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func RegisterJSONRPCRoutes(
	mux *http.ServeMux,
	idMgr *identity.IdentityManager,
	domain string,
	nodeIndex int,
	p2pMgr *p2p.P2PManager,
	relayRouter *relay.RelayRouter,
	dkgEngine *dkg.Engine,
	startTime time.Time,
) {
	server := NewJSONRPCServer(idMgr, domain, nodeIndex, p2pMgr, relayRouter, dkgEngine, startTime)
	mux.Handle("/rpc", server)
}

func (s *JSONRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Saral-Internal-Token")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"JSON-RPC requires POST"}}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		s.writeError(w, nil, -32700, "Parse error reading request body")
		return
	}

	var req JsonRpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, -32700, "Parse error invalid JSON-RPC payload")
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	var result interface{}
	var rpcErr *JsonRpcErr

	switch req.Method {
	case "saral_startDkg":
		result, rpcErr = s.handleStartDkg(req.Params, token, r)
	case "saral_getDkgStatus":
		result, rpcErr = s.handleGetDkgStatus(req.Params)
	case "saral_getDkgPublicKey":
		result, rpcErr = s.handleGetDkgPublicKey(req.Params)
	case "saral_derivePublicKey":
		result, rpcErr = s.handleDerivePublicKey(req.Params, token)
	case "saral_sendRelayMessage":
		result, rpcErr = s.handleSendRelayMessage(req.Params, token, r)
	case "saral_getNodeStatus", "saral_getCoordinatorStatus":
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) && token == "" {
			rpcErr = &JsonRpcErr{Code: -32001, Message: "Authorization required"}
		} else {
			result, rpcErr = s.handleGetNodeStatus()
		}
	case "saral_getNetworkStatus":
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) && token == "" {
			rpcErr = &JsonRpcErr{Code: -32001, Message: "Authorization required"}
		} else {
			result, rpcErr = s.handleGetNetworkStatus()
		}
	case "saral_getDomainStatus":
		result, rpcErr = s.handleGetDomainStatus()
	case "saral_createWallet":
		rpcErr = &JsonRpcErr{Code: -32000, Message: "NOT_IMPLEMENTED: Wallet generation handled by Web2 Auth Server"}
	default:
		rpcErr = &JsonRpcErr{Code: -32601, Message: fmt.Sprintf("Method '%s' not found", req.Method)}
	}

	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	_ = json.NewEncoder(w).Encode(JsonRpcResponse{
		JsonRpc: "2.0",
		ID:      req.ID,
		Result:  result,
	})
}

func (s *JSONRPCServer) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	_ = json.NewEncoder(w).Encode(JsonRpcResponse{
		JsonRpc: "2.0",
		ID:      id,
		Error:   &JsonRpcErr{Code: code, Message: message},
	})
}

func (s *JSONRPCServer) defaultCommittee() []string {
	prefix := strings.ToLower(s.domain)
	nodes := make([]string, 5)
	for i := 1; i <= 5; i++ {
		nodes[i-1] = fmt.Sprintf("saral-%s-%d", prefix, i)
	}
	return nodes
}

func (s *JSONRPCServer) getNodeEndpoint(nodeID string) string {
	ep := s.relayRouter.GetParticipantEndpoint(nodeID)
	if ep != "" {
		return ep
	}
	// Fallback to container name in docker mesh
	prefix := "f"
	if strings.Contains(nodeID, "public") {
		prefix = "p"
	} else if strings.Contains(nodeID, "private") {
		prefix = "r"
	}
	idx := "1"
	parts := strings.Split(nodeID, "-")
	if len(parts) > 0 {
		idx = parts[len(parts)-1]
	}
	return fmt.Sprintf("http://node-%s%s:8001", prefix, idx)
}

func (s *JSONRPCServer) handleStartDkg(params json.RawMessage, token string, r *http.Request) (interface{}, *JsonRpcErr) {
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
	if len(params) > 0 && json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	walletBound := req.UserID != "" || req.WalletID != "" || req.KeyID != ""
	if walletBound {
		if token == "" {
			return nil, &JsonRpcErr{Code: -32001, Message: "Authorization required for wallet DKG"}
		}
		claims, err := auth.GetNodeTokenVerifier().VerifyScopedToken(token)
		if err != nil || claims.Operation != "start_dkg" || !claims.MFAVerified || !claims.PolicySatisfied ||
			claims.UserID != req.UserID || claims.WalletID != req.WalletID || claims.KeyID != req.KeyID {
			return nil, &JsonRpcErr{Code: -32001, Message: "Invalid or unauthorized DKG authorization scope"}
		}
	} else {
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			return nil, &JsonRpcErr{Code: -32001, Message: "Authorization required"}
		}
	}

	committee := req.Committee
	if len(committee) == 0 {
		committee = s.defaultCommittee()
	}
	normalized := make([]string, 0, len(committee))
	seen := make(map[string]bool, len(committee))
	for _, node := range committee {
		id, _ := membership.NormalizeNodeID(node)
		if id == "" || seen[id] {
			return nil, &JsonRpcErr{Code: -32602, Message: "DKG committee must contain distinct node identifiers"}
		}
		seen[id] = true
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)

	n := len(normalized)
	k := req.K
	t := req.T
	if k == 0 && t == 0 {
		switch n {
		case 5:
			k, t = 3, 1
		case 15:
			k, t = 5, 4
		default:
			k, t = (n/2)+1, (n-1)/3
		}
	}

	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("dkg-%s-%d", strings.ToLower(s.domain), time.Now().UnixNano())
	}
	if req.CommitteeID == "" {
		req.CommitteeID = fmt.Sprintf("comm-%d", n)
	}

	initPayload := map[string]interface{}{
		"sessionId": req.SessionID, "committeeId": req.CommitteeID, "committee": normalized,
		"n": n, "k": k, "t": t, "walletId": req.WalletID, "keyId": req.KeyID,
		"userId": req.UserID, "curve": req.Curve, "chainFamily": req.ChainFamily,
	}

	// Dispatch init and start to all committee nodes in parallel
	var wg sync.WaitGroup
	initSuccess := make(chan string, n)
	for _, node := range normalized {
		ep := s.getNodeEndpoint(node)
		wg.Add(1)
		go func(nodeID, endpoint string) {
			defer wg.Done()
			if s.callNodeJSONWithAuth("POST", endpoint+"/node/dkg/init", initPayload, token) {
				initSuccess <- nodeID
			}
		}(node, ep)
	}
	wg.Wait()
	close(initSuccess)

	var initialized []string
	for id := range initSuccess {
		initialized = append(initialized, id)
	}
	if len(initialized) < n-t {
		return nil, &JsonRpcErr{Code: -32000, Message: fmt.Sprintf("Could not initialize enough DKG committee nodes (got %d, need %d)", len(initialized), n-t)}
	}

	// Start contributions
	startPayload := map[string]string{"sessionId": req.SessionID}
	startSuccess := make(chan string, len(initialized))
	for _, node := range initialized {
		ep := s.getNodeEndpoint(node)
		wg.Add(1)
		go func(nodeID, endpoint string) {
			defer wg.Done()
			if s.callNodeJSONWithAuth("POST", endpoint+"/node/dkg/start", startPayload, token) {
				startSuccess <- nodeID
			}
		}(node, ep)
	}
	wg.Wait()
	close(startSuccess)

	var started []string
	for id := range startSuccess {
		started = append(started, id)
	}
	if len(started) < n-t {
		return nil, &JsonRpcErr{Code: -32000, Message: fmt.Sprintf("Could not start enough DKG committee nodes (got %d, need %d)", len(started), n-t)}
	}

	return map[string]interface{}{
		"success":     true,
		"sessionId":   req.SessionID,
		"committeeId": req.CommitteeID,
		"state":       "CONTRIBUTIONS_STARTED",
		"n":           n,
		"k":           k,
		"t":           t,
		"committee":   normalized,
	}, nil
}

func (s *JSONRPCServer) handleGetDkgStatus(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var req struct {
		SessionID string `json:"sessionId"`
	}
	if len(params) > 0 && json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	committee := s.defaultCommittee()
	n := len(committee)
	k := 3
	t := 1

	type nodeStatus struct {
		NodeID                 string   `json:"nodeId"`
		State                  string   `json:"state"`
		MasterSigningPublicKey string   `json:"masterSigningPublicKey"`
		MasterPublicKey        string   `json:"masterPublicKey"`
		QualifiedSet           []string `json:"qualifiedSet"`
	}

	var wg sync.WaitGroup
	statusChan := make(chan nodeStatus, n)
	query := "?sessionId=" + req.SessionID

	for _, node := range committee {
		ep := s.getNodeEndpoint(node)
		wg.Add(1)
		go func(nodeID, endpoint string) {
			defer wg.Done()
			var st nodeStatus
			if s.getNodeJSON(endpoint+"/node/dkg/status"+query, &st) {
				st.NodeID = nodeID
				statusChan <- st
			}
		}(node, ep)
	}
	wg.Wait()
	close(statusChan)

	completedCount := 0
	masterPubKey := ""
	for st := range statusChan {
		if st.State == "COMPLETED" {
			completedCount++
			if st.MasterPublicKey != "" {
				masterPubKey = st.MasterPublicKey
			}
		}
	}

	state := "CONTRIBUTIONS_STARTED"
	if completedCount >= k {
		state = "COMPLETED"
	}

	return map[string]interface{}{
		"sessionId":       req.SessionID,
		"committeeId":     fmt.Sprintf("committee-%s", strings.ToLower(s.domain)),
		"epoch":           1,
		"n":               n,
		"k":               k,
		"t":               t,
		"state":           state,
		"committee":       committee,
		"completedNodes":  completedCount,
		"totalNodes":      n,
		"masterPublicKey": masterPubKey,
	}, nil
}

func (s *JSONRPCServer) handleGetDkgPublicKey(params json.RawMessage) (interface{}, *JsonRpcErr) {
	status, err := s.handleGetDkgStatus(params)
	if err != nil {
		return nil, err
	}
	m, ok := status.(map[string]interface{})
	if !ok {
		return nil, &JsonRpcErr{Code: -32000, Message: "failed to retrieve DKG status"}
	}
	return map[string]interface{}{
		"sessionId":       m["sessionId"],
		"committeeId":     m["committeeId"],
		"masterPublicKey": m["masterPublicKey"],
		"curve":           "secp256k1",
		"threshold":       3,
		"state":           m["state"],
	}, nil
}

func (s *JSONRPCServer) handleDerivePublicKey(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	var req struct {
		WalletID     string `json:"walletId"`
		UserID       string `json:"userId"`
		KeyID        string `json:"keyId"`
		DKGSessionID string `json:"dkgSessionId"`
		CommitteeID  string `json:"committeeId"`
		Curve        string `json:"curve"`
		ChainFamily  string `json:"chainFamily"`
		Epoch        uint64 `json:"epoch"`
	}
	if json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}
	if req.Epoch == 0 {
		req.Epoch = 1
	}

	if token == "" {
		return nil, &JsonRpcErr{Code: -32001, Message: "Authorization required"}
	}
	claims, err := auth.GetNodeTokenVerifier().VerifyScopedToken(token)
	if err != nil || claims.Operation != "derive_public_key" || !claims.MFAVerified || !claims.PolicySatisfied ||
		claims.UserID != req.UserID || claims.WalletID != req.WalletID || claims.KeyID != req.KeyID {
		return nil, &JsonRpcErr{Code: -32001, Message: "Invalid or unauthorized DKG derive authorization scope"}
	}

	committee := s.defaultCommittee()
	payload := map[string]interface{}{
		"userId": req.UserID, "walletId": req.WalletID, "keyId": req.KeyID, "sessionId": req.DKGSessionID,
		"committeeId": req.CommitteeID, "curve": req.Curve, "chainFamily": req.ChainFamily, "epoch": req.Epoch,
	}

	var wg sync.WaitGroup
	responses := make(chan crypto.WalletPublicContribution, len(committee))
	for index, node := range committee {
		ep := s.getNodeEndpoint(node)
		wg.Add(1)
		go func(idx int, nodeID, endpoint string) {
			defer wg.Done()
			var resp struct {
				NodeID                     string `json:"nodeId"`
				NodeIndex                  int    `json:"nodeIndex"`
				Epoch                      uint64 `json:"epoch"`
				PublicPoint                string `json:"publicPoint"`
				MasterSigningPublicKeyHash string `json:"masterSigningPublicKeyHash"`
			}
			if !s.callNodeJSONWithAuthAndResponse("POST", endpoint+"/node/dkg/share-contribution", payload, &resp, token) {
				return
			}
			if resp.NodeIndex != idx+1 || resp.Epoch != req.Epoch {
				return
			}
			digest, err := hex.DecodeString(resp.MasterSigningPublicKeyHash)
			if err != nil || len(digest) != sha256.Size {
				return
			}
			pt, err := crypto.DecodeWalletPublicPoint(resp.PublicPoint, req.Curve)
			if err != nil {
				return
			}
			var m [sha256.Size]byte
			copy(m[:], digest)
			responses <- crypto.WalletPublicContribution{
				Index:  resp.NodeIndex,
				Point:  pt,
				Master: m,
			}
		}(index, node, ep)
	}
	wg.Wait()
	close(responses)

	var contributions []crypto.WalletPublicContribution
	for r := range responses {
		contributions = append(contributions, r)
	}

	publicKey, _, err := crypto.ReconstructVerifiedWalletKey(contributions, req.Curve)
	if err != nil {
		return nil, &JsonRpcErr{Code: -32000, Message: err.Error()}
	}

	return map[string]interface{}{
		"success":         true,
		"walletId":        req.WalletID,
		"keyId":           req.KeyID,
		"sessionId":       req.DKGSessionID,
		"committeeId":     req.CommitteeID,
		"epoch":           req.Epoch,
		"curve":           req.Curve,
		"threshold":       3,
		"masterPublicKey": publicKey,
	}, nil
}

func (s *JSONRPCServer) handleGetNodeStatus() (interface{}, *JsonRpcErr) {
	allParts := s.relayRouter.GetAllParticipants()
	online := 1
	if s.p2pMgr != nil {
		for _, peer := range s.p2pMgr.GetPeers() {
			if peer.Connected {
				online++
			}
		}
	}
	return map[string]interface{}{
		"nodeId":        s.idMgr.Identity.NodeID,
		"domain":        s.domain,
		"status":        "ONLINE",
		"enrolledNodes": len(allParts),
		"onlineNodes":   online,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *JSONRPCServer) handleGetNetworkStatus() (interface{}, *JsonRpcErr) {
	peers := []interface{}{}
	if s.p2pMgr != nil {
		for _, p := range s.p2pMgr.GetPeers() {
			peers = append(peers, map[string]interface{}{
				"nodeId":    p.NodeID,
				"endpoint":  p.Endpoint,
				"connected": p.Connected,
			})
		}
	}
	return map[string]interface{}{
		"nodeId":         s.idMgr.Identity.NodeID,
		"domain":         s.domain,
		"peers":          peers,
		"connectedPeers": s.p2pMgr.ConnectedPeerCount(),
		"totalPeers":     len(peers),
	}, nil
}

func (s *JSONRPCServer) handleGetDomainStatus() (interface{}, *JsonRpcErr) {
	return map[string]interface{}{
		"domain":    s.domain,
		"nodeId":    s.idMgr.Identity.NodeID,
		"nodeIndex": s.nodeIndex,
		"status":    "ACTIVE",
		"uptime":    time.Since(s.startTime).String(),
	}, nil
}

func (s *JSONRPCServer) callNodeJSONWithAuth(method, url string, payload interface{}, token string) bool {
	return s.callNodeJSONWithAuthAndResponse(method, url, payload, nil, token)
}

func (s *JSONRPCServer) callNodeJSONWithAuthAndResponse(method, url string, payload interface{}, out interface{}, token string) bool {
	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil || resp.StatusCode >= 400 {
		return false
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out) == nil
	}
	return true
}

func (s *JSONRPCServer) getNodeJSON(url string, out interface{}) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())
	resp, err := s.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out) == nil
}

func (s *JSONRPCServer) handleSendRelayMessage(params json.RawMessage, token string, r *http.Request) (interface{}, *JsonRpcErr) {
	var req struct {
		MessageID    string                 `json:"messageId"`
		SourceNode   string                 `json:"sourceNode"`
		TargetNode   string                 `json:"targetNode"`
		TargetDomain string                 `json:"targetDomain"`
		Type         string                 `json:"type"`
		Payload      map[string]interface{} `json:"payload"`
		TimeoutMs    int                    `json:"timeoutMs"`
	}
	if len(params) > 0 && json.Unmarshal(params, &req) != nil {
		return nil, &JsonRpcErr{Code: -32602, Message: "Invalid parameters format"}
	}

	if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
		if token == "" {
			return nil, &JsonRpcErr{Code: -32001, Message: "Authorization required"}
		}
		if _, err := auth.GetNodeTokenVerifier().VerifyScopedToken(token); err != nil {
			return nil, &JsonRpcErr{Code: -32001, Message: "Unauthorized token: " + err.Error()}
		}
	}

	rec, err := s.relayRouter.Send(relay.RelaySendRequest{
		MessageID:    req.MessageID,
		TargetNode:   req.TargetNode,
		TargetDomain: req.TargetDomain,
		Type:         req.Type,
		Payload:      req.Payload,
		TimeoutMs:    req.TimeoutMs,
	})
	if err != nil && rec == nil {
		return nil, &JsonRpcErr{Code: -32000, Message: err.Error()}
	}
	return rec, nil
}
