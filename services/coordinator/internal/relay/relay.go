package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

type TokenVerifyResult struct {
	Valid  bool                   `json:"valid"`
	Sub    string                 `json:"sub,omitempty"`
	Domain string                 `json:"domain,omitempty"`
	Role   string                 `json:"role,omitempty"`
	Claims map[string]interface{} `json:"claims,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

type VerifierClient struct {
	endpoint   string
	httpClient *http.Client
}

func NewVerifierClient(endpoint string) *VerifierClient {
	return &VerifierClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

func (vc *VerifierClient) VerifyToken(tokenStr string) (*TokenVerifyResult, error) {
	if tokenStr == "" {
		return &TokenVerifyResult{Valid: false, Error: "missing authorization token"}, errors.New("missing token")
	}

	reqBody := map[string]string{
		"token": tokenStr,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := vc.httpClient.Post(vc.endpoint+"/verify", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("verifier unreachable at %s: %w", vc.endpoint, err)
	}
	defer resp.Body.Close()

	var res TokenVerifyResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to parse verifier response: %w", err)
	}

	if !res.Valid {
		return &res, fmt.Errorf("verifier rejected token: %s", res.Error)
	}

	return &res, nil
}

type NodeProbeResult struct {
	RequestID    string `json:"requestId"`
	ProbeID      string `json:"probeId"`
	Sender       string `json:"sender"`
	ReceiverID   string `json:"receiverId"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
	Acknowledged bool   `json:"acknowledged"`
	LatencyMs    int64  `json:"latencyMs"`
	SignatureHex string `json:"signatureHex"`
	Error        string `json:"error,omitempty"`
}

type NodeClient struct {
	httpClient *http.Client
}

func NewNodeClient() *NodeClient {
	return &NodeClient{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (nc *NodeClient) ProbeNode(node membership.NodeInfo, reqID, probeID, sender string) (*NodeProbeResult, error) {
	reqPayload := map[string]interface{}{
		"requestId": reqID,
		"probeId":   probeID,
		"sender":    sender,
		"domain":    string(node.Domain),
		"timestamp": time.Now().UnixMilli(),
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := nc.httpClient.Post(node.Endpoint+"/node/probe", "application/json", bytes.NewReader(data))
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &NodeProbeResult{
			RequestID:    reqID,
			ProbeID:      probeID,
			Sender:       sender,
			ReceiverID:   node.NodeID,
			Domain:       string(node.Domain),
			Timestamp:    time.Now().UnixMilli(),
			Acknowledged: false,
			LatencyMs:    latency,
			Error:        err.Error(),
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("node %s probe returned status %d: %s", node.NodeID, resp.StatusCode, string(b))
	}

	var res NodeProbeResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

type DomainStatusResult struct {
	Domain        string      `json:"domain"`
	Coordinator   string      `json:"coordinator"`
	TotalNodes    int         `json:"totalNodes"`
	OnlineNodes   int         `json:"onlineNodes"`
	Nodes         interface{} `json:"nodes"`
	Peers         interface{} `json:"peers"`
	LastProbeTime string      `json:"lastProbeTime,omitempty"`
}

type PeerCoordinatorClient struct {
	httpClient *http.Client
}

func NewPeerCoordinatorClient() *PeerCoordinatorClient {
	return &PeerCoordinatorClient{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (pc *PeerCoordinatorClient) GetDomainStatus(coordURL, token string) (*DomainStatusResult, error) {
	target := strings.TrimRight(coordURL, "/")
	if !strings.HasSuffix(target, "/rpc") {
		target += "/rpc"
	}

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "saral_getDomainStatus",
		"params":  map[string]interface{}{},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peer coordinator unreachable at %s: %w", coordURL, err)
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result *DomainStatusResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("peer coordinator returned error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		return nil, errors.New("empty result from peer coordinator")
	}

	return rpcResp.Result, nil
}

func (pc *PeerCoordinatorClient) ProbePeerDomain(coordURL, reqID, probeID, token string) ([]NodeProbeResult, error) {
	target := strings.TrimRight(coordURL, "/")
	if !strings.HasSuffix(target, "/rpc") {
		target += "/rpc"
	}

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "saral_probeDomain",
		"params": map[string]interface{}{
			"requestId": reqID,
			"probeId":   probeID,
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", target, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := pc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result struct {
			Probes []NodeProbeResult `json:"probes"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("peer coordinator probe error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result.Probes, nil
}
