package rpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/discovery"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/relay"
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

type Server struct {
	domain         membership.DomainType
	registry       *membership.NodeRegistry
	monitor        *discovery.Monitor
	verifierClient *relay.VerifierClient
	nodeClient     *relay.NodeClient
	peerClient     *relay.PeerCoordinatorClient
	peerCoords     []string
}

func NewServer(
	domain membership.DomainType,
	registry *membership.NodeRegistry,
	monitor *discovery.Monitor,
	verifierClient *relay.VerifierClient,
	peerCoordinatorURLs []string,
) *Server {
	return &Server{
		domain:         domain,
		registry:       registry,
		monitor:        monitor,
		verifierClient: verifierClient,
		nodeClient:     relay.NewNodeClient(),
		peerClient:     relay.NewPeerCoordinatorClient(),
		peerCoords:     peerCoordinatorURLs,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"JSON-RPC requires POST"}}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, -32700, "Parse error reading request body")
		return
	}

	var req JsonRpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, -32700, "Parse error invalid JSON")
		return
	}

	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))

	result, rpcErr := s.dispatch(req.Method, req.Params, token)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	resp := JsonRpcResponse{
		JsonRpc: "2.0",
		ID:      req.ID,
		Result:  result,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) dispatch(method string, params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	switch method {
	case "saral_getNetworkStatus":
		return s.handleGetNetworkStatus(token)
	case "saral_getDomainStatus":
		return s.handleGetDomainStatus()
	case "saral_getCoordinatorStatus":
		return s.handleGetCoordinatorStatus()
	case "saral_getNodes":
		return s.handleGetNodes()
	case "saral_getPeers":
		return s.handleGetPeers()
	case "saral_getTopology":
		return s.handleGetTopology()
	case "saral_probeNetwork":
		return s.handleProbeNetwork(params, token)
	case "saral_probeDomain":
		return s.handleProbeDomain(params)
	// Cryptographic Stubs - Explicitly NOT_IMPLEMENTED as per Section 8
	case "saral_signTransaction", "saral_createWallet", "saral_startDkg", "saral_getPublicKey":
		return nil, &JsonRpcErr{
			Code:    -32000,
			Message: "NOT_IMPLEMENTED: Cryptographic key generation, signing, and DKG are scheduled for future phases.",
		}
	default:
		return nil, &JsonRpcErr{Code: -32601, Message: fmt.Sprintf("Method not found: %s", method)}
	}
}

func (s *Server) handleGetCoordinatorStatus() (interface{}, *JsonRpcErr) {
	nodes := s.monitor.GetNodeStates()
	online := 0
	for _, n := range nodes {
		if n.Status == "HEALTHY" {
			online++
		}
	}

	return map[string]interface{}{
		"domain":           s.domain,
		"status":           "HEALTHY",
		"enrolledNodes":    len(nodes),
		"onlineNodes":      online,
		"peerCoordinators": s.monitor.GetPeerCoordinatorStates(),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *Server) handleGetDomainStatus() (interface{}, *JsonRpcErr) {
	nodes := s.monitor.GetNodeStates()
	online := 0
	for _, n := range nodes {
		if n.Status == "HEALTHY" {
			online++
		}
	}

	return map[string]interface{}{
		"domain":      s.domain,
		"coordinator": string(s.domain),
		"totalNodes":  len(nodes),
		"onlineNodes": online,
		"nodes":       nodes,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *Server) handleGetNodes() (interface{}, *JsonRpcErr) {
	return s.monitor.GetNodeStates(), nil
}

func (s *Server) handleGetPeers() (interface{}, *JsonRpcErr) {
	return s.monitor.GetPeerCoordinatorStates(), nil
}

func (s *Server) handleGetTopology() (interface{}, *JsonRpcErr) {
	return map[string]interface{}{
		"coordinatorDomain": s.domain,
		"domains":           []string{"FOUNDATION", "PUBLIC", "PRIVATE"},
		"localNodes":        s.registry.GetAllNodes(),
		"peerCoordinators":  s.peerCoords,
	}, nil
}

func (s *Server) handleGetNetworkStatus(token string) (interface{}, *JsonRpcErr) {
	// Verify token through local Verifier
	if s.verifierClient != nil {
		_, err := s.verifierClient.VerifyToken(token)
		if err != nil {
			return nil, &JsonRpcErr{
				Code:    -32001,
				Message: fmt.Sprintf("Authorization rejected by Verifier: %s", err.Error()),
			}
		}
	}

	// 1. Gather local domain status
	localNodes := s.monitor.GetNodeStates()
	localOnline := 0
	for _, n := range localNodes {
		if n.Status == "HEALTHY" {
			localOnline++
		}
	}

	domains := make(map[string]interface{})
	domains[string(s.domain)] = map[string]interface{}{
		"domain":      s.domain,
		"coordinator": "HEALTHY",
		"totalNodes":  len(localNodes),
		"onlineNodes": localOnline,
		"nodes":       localNodes,
	}

	totalNodes := len(localNodes)
	totalOnline := localOnline

	// 2. Query Peer Coordinators
	var wg sync.WaitGroup
	type peerResult struct {
		endpoint string
		status   *relay.DomainStatusResult
		err      error
	}

	resultsChan := make(chan peerResult, len(s.peerCoords))

	for _, pURL := range s.peerCoords {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			st, err := s.peerClient.GetDomainStatus(url, token)
			resultsChan <- peerResult{endpoint: url, status: st, err: err}
		}(pURL)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		if res.err == nil && res.status != nil {
			domains[res.status.Domain] = res.status
			totalNodes += res.status.TotalNodes
			totalOnline += res.status.OnlineNodes
		} else {
			log.Printf("[Coordinator - %s] Failed to fetch peer domain status from %s: %v", s.domain, res.endpoint, res.err)
		}
	}

	return map[string]interface{}{
		"network":        "SARAL Protocol V3",
		"leadDomain":     s.domain,
		"totalNodes":     totalNodes,
		"onlineNodes":    totalOnline,
		"domains":        domains,
		"peerCoordinators": s.monitor.GetPeerCoordinatorStates(),
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *Server) handleProbeDomain(params json.RawMessage) (interface{}, *JsonRpcErr) {
	var p struct {
		RequestID string `json:"requestId"`
		ProbeID   string `json:"probeId"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p)
	}
	if p.ProbeID == "" {
		p.ProbeID = randomHex(8)
	}
	if p.RequestID == "" {
		p.RequestID = randomHex(8)
	}

	nodes := s.registry.GetAllNodes()
	var wg sync.WaitGroup
	probeChan := make(chan relay.NodeProbeResult, len(nodes))

	for _, n := range nodes {
		wg.Add(1)
		go func(node membership.NodeInfo) {
			defer wg.Done()
			res, err := s.nodeClient.ProbeNode(node, p.RequestID, p.ProbeID, fmt.Sprintf("coord-%s", s.domain))
			if err != nil && res != nil {
				probeChan <- *res
			} else if res != nil {
				probeChan <- *res
			}
		}(n)
	}

	wg.Wait()
	close(probeChan)

	var probes []relay.NodeProbeResult
	for pr := range probeChan {
		probes = append(probes, pr)
	}

	return map[string]interface{}{
		"domain":  s.domain,
		"probeId": p.ProbeID,
		"probes":  probes,
	}, nil
}

func (s *Server) handleProbeNetwork(params json.RawMessage, token string) (interface{}, *JsonRpcErr) {
	// Verify token through Verifier
	if s.verifierClient != nil {
		_, err := s.verifierClient.VerifyToken(token)
		if err != nil {
			return nil, &JsonRpcErr{
				Code:    -32001,
				Message: fmt.Sprintf("Authorization rejected by Verifier: %s", err.Error()),
			}
		}
	}

	probeID := "probe-" + randomHex(8)
	requestID := "req-" + randomHex(8)

	// 1. Probe local nodes
	nodes := s.registry.GetAllNodes()
	var wg sync.WaitGroup
	probeChan := make(chan relay.NodeProbeResult, len(nodes)*3)

	for _, n := range nodes {
		wg.Add(1)
		go func(node membership.NodeInfo) {
			defer wg.Done()
			res, _ := s.nodeClient.ProbeNode(node, requestID, probeID, fmt.Sprintf("coord-%s", s.domain))
			if res != nil {
				probeChan <- *res
			}
		}(n)
	}

	// 2. Trigger peer coordinator probes
	for _, pURL := range s.peerCoords {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			peerProbes, err := s.peerClient.ProbePeerDomain(url, requestID, probeID, token)
			if err == nil {
				for _, pb := range peerProbes {
					probeChan <- pb
				}
			}
		}(pURL)
	}

	wg.Wait()
	close(probeChan)

	var allProbes []relay.NodeProbeResult
	acknowledged := 0
	totalLatency := int64(0)

	for pr := range probeChan {
		allProbes = append(allProbes, pr)
		if pr.Acknowledged {
			acknowledged++
			totalLatency += pr.LatencyMs
		}
	}

	avgLatency := int64(0)
	if acknowledged > 0 {
		avgLatency = totalLatency / int64(acknowledged)
	}

	return map[string]interface{}{
		"probeId":            probeID,
		"requestId":          requestID,
		"senderCoordinator": string(s.domain),
		"probesDispatched":   len(allProbes),
		"probesAcknowledged": acknowledged,
		"averageLatencyMs":   avgLatency,
		"probes":             allProbes,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *Server) writeError(w http.ResponseWriter, id interface{}, code int, msg string) {
	resp := JsonRpcResponse{
		JsonRpc: "2.0",
		ID:      id,
		Error: &JsonRpcErr{
			Code:    code,
			Message: msg,
		},
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
