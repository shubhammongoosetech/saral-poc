package p2p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
)

type PeerInfo struct {
	Endpoint     string    `json:"endpoint"`
	NodeID       string    `json:"nodeId,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	PublicKeyHex string    `json:"publicKeyHex,omitempty"`
	Connected    bool      `json:"connected"`
	LastSeen     time.Time `json:"lastSeen"`
	LatencyMs    int64     `json:"latencyMs"`
	Status       string    `json:"status"` // CONNECTED | DISCONNECTED | UNREACHABLE
}

type PingMessage struct {
	SenderID     string `json:"senderId"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
	PublicKeyHex string `json:"publicKeyHex"`
	SignatureHex string `json:"signatureHex"`
}

type PingAck struct {
	Acknowledged bool   `json:"acknowledged"`
	ReceiverID   string `json:"receiverId"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
}

type P2PManager struct {
	idMgr      *identity.IdentityManager
	domain     string
	peers      map[string]*PeerInfo
	mu         sync.RWMutex
	httpClient *http.Client
	stopChan   chan struct{}
}

func NewP2PManager(idMgr *identity.IdentityManager, domain string, peerEndpoints []string) *P2PManager {
	mgr := &P2PManager{
		idMgr:  idMgr,
		domain: domain,
		peers:  make(map[string]*PeerInfo),
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	for _, ep := range peerEndpoints {
		mgr.peers[ep] = &PeerInfo{
			Endpoint:  ep,
			Connected: false,
			Status:    "DISCONNECTED",
		}
	}

	return mgr
}

func (m *P2PManager) Start() {
	go m.heartbeatLoop()
}

func (m *P2PManager) Stop() {
	close(m.stopChan)
}

func (m *P2PManager) heartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Initial probe
	m.pingAllPeers()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.pingAllPeers()
		}
	}
}

func (m *P2PManager) pingAllPeers() {
	m.mu.RLock()
	endpoints := make([]string, 0, len(m.peers))
	for ep := range m.peers {
		endpoints = append(endpoints, ep)
	}
	m.mu.RUnlock()

	for _, ep := range endpoints {
		go m.pingPeer(ep)
	}
}

func (m *P2PManager) pingPeer(endpoint string) {
	now := time.Now().UnixMilli()
	msgToSign := fmt.Sprintf("%s:%s:%d", m.idMgr.Identity.NodeID, m.domain, now)
	sig := m.idMgr.Sign([]byte(msgToSign))

	pingReq := PingMessage{
		SenderID:     m.idMgr.Identity.NodeID,
		Domain:       m.domain,
		Timestamp:    now,
		PublicKeyHex: m.idMgr.Identity.PublicKeyHex,
		SignatureHex: sig,
	}

	data, err := json.Marshal(pingReq)
	if err != nil {
		return
	}

	start := time.Now()
	resp, err := m.httpClient.Post(endpoint+"/p2p/ping", "application/json", bytes.NewReader(data))
	latency := time.Since(start).Milliseconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.peers[endpoint]
	if !exists {
		info = &PeerInfo{Endpoint: endpoint}
		m.peers[endpoint] = info
	}

	if err != nil || resp.StatusCode != http.StatusOK {
		info.Connected = false
		info.Status = "UNREACHABLE"
		return
	}
	defer resp.Body.Close()

	var ack PingAck
	if decodeErr := json.NewDecoder(resp.Body).Decode(&ack); decodeErr == nil && ack.Acknowledged {
		info.Connected = true
		info.NodeID = ack.ReceiverID
		info.Domain = ack.Domain
		info.LastSeen = time.Now()
		info.LatencyMs = latency
		info.Status = "CONNECTED"
	} else {
		info.Connected = false
		info.Status = "DEGRADED"
	}
}

func (m *P2PManager) HandleIncomingPing(ping PingMessage) (*PingAck, error) {
	msgToVerify := fmt.Sprintf("%s:%s:%d", ping.SenderID, ping.Domain, ping.Timestamp)
	valid := identity.VerifySignature(ping.PublicKeyHex, []byte(msgToVerify), ping.SignatureHex)
	if !valid {
		return nil, fmt.Errorf("invalid ed25519 signature from peer %s", ping.SenderID)
	}

	ack := &PingAck{
		Acknowledged: true,
		ReceiverID:   m.idMgr.Identity.NodeID,
		Domain:       m.domain,
		Timestamp:    time.Now().UnixMilli(),
	}

	return ack, nil
}

func (m *P2PManager) GetPeers() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		res = append(res, *p)
	}
	return res
}

func (m *P2PManager) ConnectedPeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, p := range m.peers {
		if p.Connected {
			count++
		}
	}
	return count
}
