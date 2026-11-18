package p2p

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	Status       string    `json:"status"` // CONNECTED | DISCONNECTED | UNREACHABLE | UNTRUSTED
}

type PingMessage struct {
	SenderID     string `json:"senderId"`
	ReceiverID   string `json:"receiverId,omitempty"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	PublicKeyHex string `json:"publicKeyHex"`
	SignatureHex string `json:"signatureHex"`
}

type PingAck struct {
	Acknowledged bool   `json:"acknowledged"`
	ReceiverID   string `json:"receiverId"`
	SenderID     string `json:"senderId"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	PublicKeyHex string `json:"publicKeyHex"`
	SignatureHex string `json:"signatureHex"`
}

type P2PManager struct {
	idMgr               *identity.IdentityManager
	domain              string
	peers               map[string]*PeerInfo
	trustedParticipants map[string]string // NodeID -> Expected PublicKeyHex
	seenNonces          map[string]int64  // Nonce -> Expire UnixMilli
	mu                  sync.RWMutex
	httpClient          *http.Client
	stopChan            chan struct{}
}

func NewP2PManager(idMgr *identity.IdentityManager, domain string, peerEndpoints []string) *P2PManager {
	mgr := &P2PManager{
		idMgr:               idMgr,
		domain:              domain,
		peers:               make(map[string]*PeerInfo),
		trustedParticipants: make(map[string]string),
		seenNonces:          make(map[string]int64),
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

func (m *P2PManager) RegisterTrustedParticipant(nodeID, pubKeyHex string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trustedParticipants[nodeID] = pubKeyHex
}

func (m *P2PManager) Start() {
	go m.heartbeatLoop()
	go m.cleanupNoncesLoop()
}

func (m *P2PManager) Stop() {
	close(m.stopChan)
}

func (m *P2PManager) cleanupNoncesLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now().UnixMilli()
			for nonce, exp := range m.seenNonces {
				if now >= exp {
					delete(m.seenNonces, nonce)
				}
			}
			m.mu.Unlock()
		}
	}
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

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *P2PManager) pingPeer(endpoint string) {
	now := time.Now().UnixMilli()
	nonce := generateNonce()

	m.mu.RLock()
	peerObj := m.peers[endpoint]
	receiverID := ""
	if peerObj != nil {
		receiverID = peerObj.NodeID
	}
	m.mu.RUnlock()

	// Canonical payload: SenderID:ReceiverID:Domain:Timestamp:Nonce
	msgToSign := fmt.Sprintf("%s:%s:%s:%d:%s", m.idMgr.Identity.NodeID, receiverID, m.domain, now, nonce)
	sig := m.idMgr.Sign([]byte(msgToSign))

	pingReq := PingMessage{
		SenderID:     m.idMgr.Identity.NodeID,
		ReceiverID:   receiverID,
		Domain:       m.domain,
		Timestamp:    now,
		Nonce:        nonce,
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
	if decodeErr := json.NewDecoder(resp.Body).Decode(&ack); decodeErr != nil || !ack.Acknowledged {
		info.Connected = false
		info.Status = "DEGRADED"
		return
	}

	// Phase 1.5: Verify signed acknowledgement from receiver
	ackPayload := fmt.Sprintf("%s:%s:%s:%d:%s", ack.ReceiverID, m.idMgr.Identity.NodeID, ack.Domain, ack.Timestamp, nonce)
	if !identity.VerifySignature(ack.PublicKeyHex, []byte(ackPayload), ack.SignatureHex) {
		info.Connected = false
		info.Status = "UNTRUSTED_ACK_SIGNATURE"
		return
	}

	// Phase 1.4: Check receiver against trusted registry if configured
	if trustedKey, hasKey := m.trustedParticipants[ack.ReceiverID]; hasKey && trustedKey != ack.PublicKeyHex {
		info.Connected = false
		info.Status = "UNTRUSTED_KEY_MISMATCH"
		return
	}

	// Update peer status
	info.Connected = true
	info.NodeID = ack.ReceiverID
	info.Domain = ack.Domain
	info.PublicKeyHex = ack.PublicKeyHex
	info.LastSeen = time.Now()
	info.LatencyMs = latency
	info.Status = "CONNECTED"

	// Register in participant cache
	m.trustedParticipants[ack.ReceiverID] = ack.PublicKeyHex
}

func (m *P2PManager) HandleIncomingPing(ping PingMessage) (*PingAck, error) {
	now := time.Now().UnixMilli()

	// 1. Participant ID format verification
	if ping.SenderID == "" || !strings.HasPrefix(ping.SenderID, "saral-") {
		return nil, fmt.Errorf("invalid sender node id: %s", ping.SenderID)
	}

	// 2. Receiver identity verification
	if ping.ReceiverID != "" && ping.ReceiverID != m.idMgr.Identity.NodeID {
		return nil, fmt.Errorf("receiver mismatch: intended for %s, got %s", ping.ReceiverID, m.idMgr.Identity.NodeID)
	}

	// 3. Timestamp freshness check (allow max 5s into future, max 30s in past)
	diff := now - ping.Timestamp
	if diff < -5000 || diff > 30000 {
		return nil, fmt.Errorf("timestamp freshness expired (diff: %d ms)", diff)
	}

	// 4. Replay protection check
	if ping.Nonce == "" {
		return nil, errors.New("missing message nonce for replay protection")
	}

	m.mu.Lock()
	if exp, exists := m.seenNonces[ping.Nonce]; exists && now < exp {
		m.mu.Unlock()
		return nil, fmt.Errorf("replay attack rejected: nonce %s already seen", ping.Nonce)
	}
	m.seenNonces[ping.Nonce] = now + (60 * 1000) // keep for 60 seconds

	// 5. Trusted participant registry verification
	if expectedKey, exists := m.trustedParticipants[ping.SenderID]; exists {
		if expectedKey != ping.PublicKeyHex {
			m.mu.Unlock()
			return nil, fmt.Errorf("participant key mismatch for %s: registered %s, received %s",
				ping.SenderID, expectedKey, ping.PublicKeyHex)
		}
	} else {
		// Enroll peer key
		m.trustedParticipants[ping.SenderID] = ping.PublicKeyHex
	}
	m.mu.Unlock()

	// 6. Ed25519 signature verification on canonical wire payload
	msgToVerify := fmt.Sprintf("%s:%s:%s:%d:%s", ping.SenderID, ping.ReceiverID, ping.Domain, ping.Timestamp, ping.Nonce)
	valid := identity.VerifySignature(ping.PublicKeyHex, []byte(msgToVerify), ping.SignatureHex)
	if !valid {
		return nil, fmt.Errorf("invalid Ed25519 signature from peer %s", ping.SenderID)
	}

	// 7. Generate Signed Acknowledgement
	ackTime := time.Now().UnixMilli()
	ackPayload := fmt.Sprintf("%s:%s:%s:%d:%s", m.idMgr.Identity.NodeID, ping.SenderID, m.domain, ackTime, ping.Nonce)
	ackSig := m.idMgr.Sign([]byte(ackPayload))

	ack := &PingAck{
		Acknowledged: true,
		ReceiverID:   m.idMgr.Identity.NodeID,
		SenderID:     ping.SenderID,
		Domain:       m.domain,
		Timestamp:    ackTime,
		Nonce:        ping.Nonce,
		PublicKeyHex: m.idMgr.Identity.PublicKeyHex,
		SignatureHex: ackSig,
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
