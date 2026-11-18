package rpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
)

type ProbeRequest struct {
	RequestID string `json:"requestId"`
	ProbeID   string `json:"probeId"`
	Sender    string `json:"sender"`
	Domain    string `json:"domain"`
	Timestamp int64  `json:"timestamp"`
}

type ProbeResponse struct {
	RequestID    string `json:"requestId"`
	ProbeID      string `json:"probeId"`
	Sender       string `json:"sender"`
	ReceiverID   string `json:"receiverId"`
	Domain       string `json:"domain"`
	Timestamp    int64  `json:"timestamp"`
	Acknowledged bool   `json:"acknowledged"`
	LatencyMs    int64  `json:"latencyMs"`
	SignatureHex string `json:"signatureHex"`
}

type NodeStatusResponse struct {
	NodeID          string         `json:"nodeId"`
	Domain          string         `json:"domain"`
	NodeIndex       int            `json:"nodeIndex"`
	PublicKeyHex    string         `json:"publicKeyHex"`
	ConnectedPeers  int            `json:"connectedPeers"`
	TotalPeers      int            `json:"totalPeers"`
	Peers           []p2p.PeerInfo `json:"peers"`
	Status          string         `json:"status"`
	UptimeSec       int64          `json:"uptimeSec"`
	VaultDirectory  string         `json:"vaultDirectory"`
}

func RegisterRoutes(
	mux *http.ServeMux,
	idMgr *identity.IdentityManager,
	domain string,
	nodeIndex int,
	p2pMgr *p2p.P2PManager,
	startTime time.Time,
) {
	// Status endpoint
	mux.HandleFunc("/node/status", func(w http.ResponseWriter, r *http.Request) {
		peers := p2pMgr.GetPeers()
		resp := NodeStatusResponse{
			NodeID:         idMgr.Identity.NodeID,
			Domain:         domain,
			NodeIndex:      nodeIndex,
			PublicKeyHex:   idMgr.Identity.PublicKeyHex,
			ConnectedPeers: p2pMgr.ConnectedPeerCount(),
			TotalPeers:     len(peers),
			Peers:          peers,
			Status:         "ACTIVE",
			UptimeSec:      int64(time.Since(startTime).Seconds()),
			VaultDirectory: idMgr.GetVaultPath(),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Peers endpoint
	mux.HandleFunc("/node/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p2pMgr.GetPeers())
	})

	// Probe endpoint (Network probe handled with real evidence)
	mux.HandleFunc("/node/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req ProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid probe JSON payload"}`, http.StatusBadRequest)
			return
		}

		now := time.Now().UnixMilli()
		latency := now - req.Timestamp
		if latency < 0 {
			latency = 0
		}

		msgToSign := fmt.Sprintf("%s:%s:%s:%d", req.ProbeID, idMgr.Identity.NodeID, domain, now)
		sig := idMgr.Sign([]byte(msgToSign))

		resp := ProbeResponse{
			RequestID:    req.RequestID,
			ProbeID:      req.ProbeID,
			Sender:       req.Sender,
			ReceiverID:   idMgr.Identity.NodeID,
			Domain:       domain,
			Timestamp:    now,
			Acknowledged: true,
			LatencyMs:    latency,
			SignatureHex: sig,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// P2P Ping endpoint
	mux.HandleFunc("/p2p/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var ping p2p.PingMessage
		if err := json.NewDecoder(r.Body).Decode(&ping); err != nil {
			http.Error(w, `{"error":"Invalid ping payload"}`, http.StatusBadRequest)
			return
		}

		ack, err := p2pMgr.HandleIncomingPing(ping)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ack)
	})
}
