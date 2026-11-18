package discovery

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/auth"
	"github.com/saral-protocol/saral-poc/services/coordinator/internal/membership"
)

type NodeState struct {
	NodeID          string    `json:"nodeId"`
	Domain          string    `json:"domain"`
	Endpoint        string    `json:"endpoint"`
	Status          string    `json:"status"` // HEALTHY | UNREACHABLE | DEGRADED | UNAPPROVED_NOT_ENROLLED | UNTRUSTED_KEY_MISMATCH
	LastChecked     time.Time `json:"lastChecked"`
	LatencyMs       int64     `json:"latencyMs"`
	PublicKeyHex    string    `json:"publicKeyHex,omitempty"`
	EncryptionKeyHex string   `json:"encryptionKeyHex,omitempty"`
	PeerCount       int       `json:"peerCount"`
}

type PeerCoordinatorState struct {
	Domain      string    `json:"domain"`
	Endpoint    string    `json:"endpoint"`
	Status      string    `json:"status"` // HEALTHY | UNREACHABLE
	LastChecked time.Time `json:"lastChecked"`
	LatencyMs   int64     `json:"latencyMs"`
}

type Monitor struct {
	registry         *membership.NodeRegistry
	peerCoords       []string
	nodeStates       map[string]*NodeState
	peerCoordStates  map[string]*PeerCoordinatorState
	peerNodeStates   map[string]*NodeState
	approvedRegistry map[string]membership.ParticipantEntry // Canonical ID -> approved participant
	mu               sync.RWMutex
	httpClient       *http.Client
	mtlsClient       *http.Client
	stopChan         chan struct{}
}

func (m *Monitor) SetMTLSClient(client *http.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mtlsClient = client
}

func NewMonitor(registry *membership.NodeRegistry, peerCoordinatorURLs []string) *Monitor {
	m := &Monitor{
		registry:         registry,
		peerCoords:       peerCoordinatorURLs,
		nodeStates:       make(map[string]*NodeState),
		peerCoordStates:  make(map[string]*PeerCoordinatorState),
		peerNodeStates:   make(map[string]*NodeState),
		approvedRegistry: make(map[string]membership.ParticipantEntry),
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

	// Bootstrap approved genesis registry from standard locations
	genesisPaths := []string{
		os.Getenv("SARAL_GENESIS_REGISTRY_FILE"),
		"/run/secrets/saral_genesis_participants",
		"/run/secrets/saral_genesis_participants.json",
		"infra/config/genesis_participants.json",
		"../../infra/config/genesis_participants.json",
		"../../../infra/config/genesis_participants.json",
	}
	for _, p := range genesisPaths {
		if p != "" {
			if err := m.LoadApprovedGenesisFile(p); err == nil {
				log.Printf("[Discovery Monitor] Successfully bootstrapped %d approved participants from %s",
					len(m.approvedRegistry), p)
				break
			}
		}
	}

	return m
}

func (m *Monitor) LoadApprovedGenesisFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var mapEntries map[string]membership.ParticipantEntry
	if err := json.Unmarshal(data, &mapEntries); err == nil && len(mapEntries) > 0 {
		m.mu.Lock()
		defer m.mu.Unlock()
		for k, v := range mapEntries {
			cID, domain := membership.NormalizeNodeID(k)
			if v.Domain == "" {
				v.Domain = domain
			}
			v.NodeID = cID
			if v.ApprovedBy == "" {
				v.ApprovedBy = "genesis-bootstrap"
			}
			if v.EnrolledAt == "" {
				v.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
			}
			m.approvedRegistry[cID] = v
		}
		return nil
	}

	var listEntries []membership.ParticipantEntry
	if err := json.Unmarshal(data, &listEntries); err == nil && len(listEntries) > 0 {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, v := range listEntries {
			cID, domain := membership.NormalizeNodeID(v.NodeID)
			if v.Domain == "" {
				v.Domain = domain
			}
			v.NodeID = cID
			if v.ApprovedBy == "" {
				v.ApprovedBy = "genesis-bootstrap"
			}
			if v.EnrolledAt == "" {
				v.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
			}
			m.approvedRegistry[cID] = v
		}
		return nil
	}

	return errors.New("invalid genesis participants format: expected JSON map or array")
}

// EnrollParticipant adds or updates an administrator-approved participant
func (m *Monitor) EnrollParticipant(entry membership.ParticipantEntry, approvedBy string) error {
	if entry.NodeID == "" {
		return errors.New("missing nodeId")
	}
	canonicalID, domain := membership.NormalizeNodeID(entry.NodeID)
	if entry.Domain == "" {
		entry.Domain = domain
	}
	entry.NodeID = canonicalID

	if len(entry.PublicKeyHex) != 64 {
		return fmt.Errorf("invalid Ed25519 public key length: expected 64 hex chars, got %d", len(entry.PublicKeyHex))
	}
	if _, err := hex.DecodeString(entry.PublicKeyHex); err != nil {
		return fmt.Errorf("invalid hex in public key: %w", err)
	}

	if entry.EncryptionKeyHex != "" {
		if len(entry.EncryptionKeyHex) != 64 {
			return fmt.Errorf("invalid X25519 encryption key length: expected 64 hex chars, got %d", len(entry.EncryptionKeyHex))
		}
		if _, err := hex.DecodeString(entry.EncryptionKeyHex); err != nil {
			return fmt.Errorf("invalid hex in encryption key: %w", err)
		}
	}

	entry.ApprovedBy = approvedBy
	entry.EnrolledAt = time.Now().UTC().Format(time.RFC3339)

	m.mu.Lock()
	m.approvedRegistry[canonicalID] = entry
	m.mu.Unlock()

	log.Printf("[Discovery Monitor] Successfully enrolled participant %s (%s) approved by %s",
		canonicalID, entry.Domain, approvedBy)
	return nil
}

// ReEnrollParticipant updates an enrolled participant's endpoint or keys without deleting anything
func (m *Monitor) ReEnrollParticipant(entry membership.ParticipantEntry, approvedBy string) error {
	canonicalID, domain := membership.NormalizeNodeID(entry.NodeID)
	if entry.Domain == "" {
		entry.Domain = domain
	}
	entry.NodeID = canonicalID

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.approvedRegistry[canonicalID]
	if !exists {
		return fmt.Errorf("cannot re-enroll node %s: node is not yet enrolled", canonicalID)
	}

	if entry.PublicKeyHex != "" {
		if len(entry.PublicKeyHex) != 64 {
			return errors.New("invalid public key length")
		}
		existing.PublicKeyHex = entry.PublicKeyHex
	}
	if entry.EncryptionKeyHex != "" {
		if len(entry.EncryptionKeyHex) != 64 {
			return errors.New("invalid encryption key length")
		}
		existing.EncryptionKeyHex = entry.EncryptionKeyHex
	}
	if entry.Endpoint != "" {
		existing.Endpoint = entry.Endpoint
	}
	existing.ApprovedBy = approvedBy
	existing.EnrolledAt = time.Now().UTC().Format(time.RFC3339)

	m.approvedRegistry[canonicalID] = existing
	log.Printf("[Discovery Monitor] Successfully re-enrolled participant %s approved by %s", canonicalID, approvedBy)
	return nil
}

func (m *Monitor) GetApprovedRegistry() map[string]membership.ParticipantEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make(map[string]membership.ParticipantEntry, len(m.approvedRegistry))
	for k, v := range m.approvedRegistry {
		res[k] = v
	}
	return res
}

func (m *Monitor) Start() {
	go m.pollLoop()
}

func (m *Monitor) Stop() {
	close(m.stopChan)
}

func (m *Monitor) pollLoop() {
	m.pollAll()

	ticker := time.NewTicker(3 * time.Second)
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
	var resp *http.Response
	var err error

	if m.mtlsClient != nil {
		mtlsEndpoint := n.Endpoint
		if strings.Contains(mtlsEndpoint, "8001") {
			mtlsEndpoint = strings.Replace(mtlsEndpoint, "8001", "8443", 1)
			mtlsEndpoint = strings.Replace(mtlsEndpoint, "http://", "https://", 1)
		}
		if mResp, mErr := m.mtlsClient.Get(mtlsEndpoint + "/node/status"); mErr == nil && mResp.StatusCode == http.StatusOK {
			resp = mResp
		}
	}
	if resp == nil {
		resp, err = m.httpClient.Get(n.Endpoint + "/node/status")
	}
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

	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		state.Status = "UNREACHABLE"
		return
	}
	defer resp.Body.Close()

	var statusResp struct {
		PublicKeyHex        string `json:"publicKeyHex"`
		EncryptionPubKeyHex string `json:"encryptionPubKeyHex"`
		ConnectedPeers      int    `json:"connectedPeers"`
		Status              string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err == nil {
		canonicalID, _ := membership.NormalizeNodeID(n.NodeID)
		approved, isApproved := m.approvedRegistry[canonicalID]
		if !isApproved {
			state.Status = "UNAPPROVED_NOT_ENROLLED"
			state.PublicKeyHex = ""
			state.EncryptionKeyHex = ""
			state.PeerCount = statusResp.ConnectedPeers
			return
		}

		if approved.PublicKeyHex != statusResp.PublicKeyHex {
			state.Status = "UNTRUSTED_KEY_MISMATCH"
			state.PublicKeyHex = ""
			state.EncryptionKeyHex = ""
			state.PeerCount = statusResp.ConnectedPeers
			log.Printf("[SECURITY ALERT] Node %s key mismatch! Approved: %s, Reported: %s",
				canonicalID, approved.PublicKeyHex, statusResp.PublicKeyHex)
			return
		}

		if approved.EncryptionKeyHex != "" && statusResp.EncryptionPubKeyHex != "" && approved.EncryptionKeyHex != statusResp.EncryptionPubKeyHex {
			state.Status = "UNTRUSTED_KEY_MISMATCH"
			state.PublicKeyHex = ""
			state.EncryptionKeyHex = ""
			state.PeerCount = statusResp.ConnectedPeers
			return
		}

		state.Status = "HEALTHY"
		state.PublicKeyHex = approved.PublicKeyHex
		if approved.EncryptionKeyHex != "" {
			state.EncryptionKeyHex = approved.EncryptionKeyHex
		} else {
			state.EncryptionKeyHex = statusResp.EncryptionPubKeyHex
		}
		state.PeerCount = statusResp.ConnectedPeers
	} else {
		state.Status = "DEGRADED"
	}
}

func (m *Monitor) pollPeerCoordinator(ep string) {
	start := time.Now()
	healthURL := strings.TrimRight(ep, "/") + "/health"
	resp, err := m.httpClient.Get(healthURL)
	latency := time.Since(start).Milliseconds()

	m.mu.Lock()
	state, exists := m.peerCoordStates[ep]
	if !exists {
		state = &PeerCoordinatorState{Endpoint: ep}
		m.peerCoordStates[ep] = state
	}
	state.LastChecked = time.Now()
	state.LatencyMs = latency

	if err != nil || resp.StatusCode != http.StatusOK {
		state.Status = "UNREACHABLE"
		m.mu.Unlock()
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
	m.mu.Unlock()

	// Query peer coordinator for authenticated participants
	regURL := strings.TrimRight(ep, "/") + "/registry/participants"
	req, err := http.NewRequest("GET", regURL, nil)
	if err == nil {
		req.Header.Set("X-Saral-Internal-Token", auth.GetInternalToken())
		pResp, err := m.httpClient.Do(req)
		if err == nil && pResp.StatusCode == http.StatusOK {
			defer pResp.Body.Close()
			var partResp struct {
				Participants map[string]membership.ParticipantEntry `json:"participants"`
			}
			if json.NewDecoder(pResp.Body).Decode(&partResp) == nil {
				m.mu.Lock()
				for k, p := range partResp.Participants {
					canonicalID, _ := membership.NormalizeNodeID(k)
					m.peerNodeStates[canonicalID] = &NodeState{
						NodeID:           canonicalID,
						Domain:           p.Domain,
						Endpoint:         p.Endpoint,
						Status:           "HEALTHY",
						PublicKeyHex:     p.PublicKeyHex,
						EncryptionKeyHex: p.EncryptionKeyHex,
						LastChecked:      time.Now(),
					}
					// If not present in approvedRegistry, register peer's participant if valid
					if _, exists := m.approvedRegistry[canonicalID]; !exists && len(p.PublicKeyHex) == 64 {
						m.approvedRegistry[canonicalID] = p
					}
				}
				m.mu.Unlock()
			}
		}
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

// GetAuthorizedParticipants returns all approved and verified participants
func (m *Monitor) GetAuthorizedParticipants() map[string]membership.ParticipantEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]membership.ParticipantEntry)

	for id, entry := range m.approvedRegistry {
		canonicalID, _ := membership.NormalizeNodeID(id)
		// Exclude explicitly untrusted nodes
		if s, ok := m.nodeStates[canonicalID]; ok {
			if s.Status == "UNTRUSTED_KEY_MISMATCH" || s.Status == "UNAPPROVED_NOT_ENROLLED" {
				continue
			}
		}
		result[canonicalID] = entry
	}

	return result
}
