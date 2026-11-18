package discovery

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

type NodeState struct {
	NodeID       string    `json:"nodeId"`
	Domain       string    `json:"domain"`
	Endpoint     string    `json:"endpoint"`
	Status       string    `json:"status"` // HEALTHY | UNREACHABLE | DEGRADED
	LastChecked  time.Time `json:"lastChecked"`
	LatencyMs    int64     `json:"latencyMs"`
	PublicKeyHex string    `json:"publicKeyHex,omitempty"`
	PeerCount    int       `json:"peerCount"`
}

type PeerCoordinatorState struct {
	Domain      string    `json:"domain"`
	Endpoint    string    `json:"endpoint"`
	Status      string    `json:"status"` // HEALTHY | UNREACHABLE
	LastChecked time.Time `json:"lastChecked"`
	LatencyMs   int64     `json:"latencyMs"`
}

type Monitor struct {
	registry        *membership.NodeRegistry
	peerCoords      []string
	nodeStates      map[string]*NodeState
	peerCoordStates map[string]*PeerCoordinatorState
	mu              sync.RWMutex
	httpClient      *http.Client
	stopChan        chan struct{}
}

func NewMonitor(registry *membership.NodeRegistry, peerCoordinatorURLs []string) *Monitor {
	m := &Monitor{
		registry:        registry,
		peerCoords:      peerCoordinatorURLs,
		nodeStates:      make(map[string]*NodeState),
		peerCoordStates: make(map[string]*PeerCoordinatorState),
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	for _, n := range registry.GetAllNodes() {
		m.nodeStates[n.NodeID] = &NodeState{
			NodeID:   n.NodeID,
			Domain:   string(n.Domain),
			Endpoint: n.Endpoint,
			Status:   "UNKNOWN",
		}
	}

	for _, ep := range peerCoordinatorURLs {
		m.peerCoordStates[ep] = &PeerCoordinatorState{
			Endpoint: ep,
			Status:   "UNKNOWN",
		}
	}

	return m
}

func (m *Monitor) Start() {
	go m.pollLoop()
}

func (m *Monitor) Stop() {
	close(m.stopChan)
}

func (m *Monitor) pollLoop() {
	m.pollAll()

	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.pollAll()
		}
	}
}

func (m *Monitor) pollAll() {
	nodes := m.registry.GetAllNodes()
	for _, n := range nodes {
		go m.pollNode(n)
	}

	m.mu.RLock()
	peers := make([]string, len(m.peerCoords))
	copy(peers, m.peerCoords)
	m.mu.RUnlock()

	for _, ep := range peers {
		go m.pollPeerCoordinator(ep)
	}
}

func (m *Monitor) pollNode(n membership.NodeInfo) {
	start := time.Now()
	resp, err := m.httpClient.Get(n.Endpoint + "/node/status")
	latency := time.Since(start).Milliseconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.nodeStates[n.NodeID]
	if !exists {
		state = &NodeState{NodeID: n.NodeID, Domain: string(n.Domain), Endpoint: n.Endpoint}
		m.nodeStates[n.NodeID] = state
	}

	state.LastChecked = time.Now()
	state.LatencyMs = latency

	if err != nil || resp.StatusCode != http.StatusOK {
		state.Status = "UNREACHABLE"
		return
	}
	defer resp.Body.Close()

	var statusResp struct {
		PublicKeyHex   string `json:"publicKeyHex"`
		ConnectedPeers int    `json:"connectedPeers"`
		Status         string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err == nil {
		state.Status = "HEALTHY"
		state.PublicKeyHex = statusResp.PublicKeyHex
		state.PeerCount = statusResp.ConnectedPeers
	} else {
		state.Status = "DEGRADED"
	}
}

func (m *Monitor) pollPeerCoordinator(ep string) {
	start := time.Now()
	resp, err := m.httpClient.Get(ep + "/health")
	latency := time.Since(start).Milliseconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.peerCoordStates[ep]
	if !exists {
		state = &PeerCoordinatorState{Endpoint: ep}
		m.peerCoordStates[ep] = state
	}

	state.LastChecked = time.Now()
	state.LatencyMs = latency

	if err != nil || resp.StatusCode != http.StatusOK {
		state.Status = "UNREACHABLE"
		return
	}
	defer resp.Body.Close()

	var hResp struct {
		Domain string `json:"domain"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hResp); err == nil {
		state.Status = "HEALTHY"
		state.Domain = hResp.Domain
	} else {
		state.Status = "DEGRADED"
	}
}

func (m *Monitor) GetNodeStates() []NodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]NodeState, 0, len(m.nodeStates))
	for _, s := range m.nodeStates {
		res = append(res, *s)
	}
	return res
}

func (m *Monitor) GetPeerCoordinatorStates() []PeerCoordinatorState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]PeerCoordinatorState, 0, len(m.peerCoordStates))
	for _, s := range m.peerCoordStates {
		res = append(res, *s)
	}
	return res
}

