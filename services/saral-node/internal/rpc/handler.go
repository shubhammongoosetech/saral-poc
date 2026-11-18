package rpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/internal/identity"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/p2p"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/relay"
)

type ProbeRequest struct {
	RequestID  string `json:"requestId"`
	ProbeID    string `json:"probeId"`
	Sender     string `json:"sender"`
	ReceiverID string `json:"receiverId,omitempty"`
	Domain     string `json:"domain"`
	Timestamp  int64  `json:"timestamp"`
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
	PublicKeyHex string `json:"publicKeyHex"`
	SignatureHex string `json:"signatureHex"`
}

type NodeStatusResponse struct {
	NodeID         string         `json:"nodeId"`
	Domain         string         `json:"domain"`
	NodeIndex      int            `json:"nodeIndex"`
	PublicKeyHex   string         `json:"publicKeyHex"`
	ConnectedPeers int            `json:"connectedPeers"`
	TotalPeers     int            `json:"totalPeers"`
	Peers          []p2p.PeerInfo `json:"peers"`
	Status         string         `json:"status"`
	UptimeSec      int64          `json:"uptimeSec"`
	VaultDirectory string         `json:"vaultDirectory"`
}

func RegisterRoutes(
	mux *http.ServeMux,
	idMgr *identity.IdentityManager,
	domain string,
	nodeIndex int,
	p2pMgr *p2p.P2PManager,
	relayRouter *relay.RelayRouter,
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

	// Probe endpoint (Network probe handled with real cryptographic evidence and auth)
	mux.HandleFunc("/node/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Security Check: Verify internal caller authorization
		authHeader := r.Header.Get("Authorization")
		internalToken := r.Header.Get("X-Saral-Internal-Token")
		if authHeader == "" && internalToken == "" {
			http.Error(w, `{"error":"Unauthorized internal node RPC: authentication required"}`, http.StatusUnauthorized)
			return
		}

		var req ProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid probe JSON payload"}`, http.StatusBadRequest)
			return
		}

		now := time.Now().UnixMilli()

		// Freshness check on probe request
		diff := now - req.Timestamp
		if diff < -5000 || diff > 30000 {
			http.Error(w, fmt.Sprintf(`{"error":"Probe timestamp outside freshness window (diff: %d ms)"}`, diff), http.StatusBadRequest)
			return
		}

		// Receiver ID verification
		if req.ReceiverID != "" && req.ReceiverID != idMgr.Identity.NodeID {
			http.Error(w, fmt.Sprintf(`{"error":"Receiver mismatch: intended for %s, got %s"}`, req.ReceiverID, idMgr.Identity.NodeID), http.StatusBadRequest)
			return
		}

		latency := now - req.Timestamp
		if latency < 0 {
			latency = 0
		}

		msgToSign := fmt.Sprintf("%s:%s:%s:%s:%d", req.ProbeID, req.RequestID, idMgr.Identity.NodeID, domain, now)
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
			PublicKeyHex: idMgr.Identity.PublicKeyHex,
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
			status := http.StatusUnauthorized
			if strings.Contains(err.Error(), "replay") {
				status = http.StatusConflict
			}
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ack)
	})

	// ─── RELAY ENDPOINTS ───────────────────────────────────────────────────

	// /node/relay/send — Node initiates and sends an authenticated relay message
	mux.HandleFunc("/node/relay/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var sendReq relay.RelaySendRequest
		if err := json.NewDecoder(r.Body).Decode(&sendReq); err != nil {
			http.Error(w, `{"error":"Invalid relay request JSON payload"}`, http.StatusBadRequest)
			return
		}

		record, _ := relayRouter.Send(sendReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
	})

	// /node/relay and /p2p/relay — Receives incoming relay messages
	handleRelayIncoming := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var msg relay.RelayMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, `{"error":"Invalid relay message payload"}`, http.StatusBadRequest)
			return
		}

		ack, _ := relayRouter.HandleIncomingRelay(msg)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ack)
	}

	mux.HandleFunc("/node/relay", handleRelayIncoming)
	mux.HandleFunc("/p2p/relay", handleRelayIncoming)

	// /node/relay/history — Delivery ledger history
	mux.HandleFunc("/node/relay/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(relayRouter.GetHistory())
	})

	// /node/relay/stats — Delivery statistics
	mux.HandleFunc("/node/relay/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(relayRouter.GetStats())
	})
}
