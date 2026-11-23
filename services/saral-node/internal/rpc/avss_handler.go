package rpc

import (
	"encoding/json"
	"net/http"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
)

// RegisterAVSSRoutes wires the AVSS and Proactive HTTP endpoints into the node's serve mux
func RegisterAVSSRoutes(
	mux *http.ServeMux,
	avssEngine *avss.Engine,
	proactiveMgr *proactive.Manager,
) {
	// POST /node/avss/session/create — Authorize and initialize a session
	mux.HandleFunc("/node/avss/session/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			SessionID   string   `json:"sessionId"`
			CommitteeID string   `json:"committeeId"`
			DealerID    string   `json:"dealerId"`
			Epoch       uint64   `json:"epoch"`
			N           int      `json:"n"`
			K           int      `json:"k"`
			T           int      `json:"t"`
			Committee   []string `json:"committee"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		sess, err := avssEngine.CreateSession(req.SessionID, req.CommitteeID, req.DealerID, req.Epoch, req.N, req.K, req.T, req.Committee)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"sessionId": sess.SessionID,
			"state":     string(sess.State),
			"nodeId":    avssEngine.NodeID,
		})
	})

	// POST /node/avss/dealer/start — Dealer initiates sharing
	mux.HandleFunc("/node/avss/dealer/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			SessionID   string   `json:"sessionId"`
			CommitteeID string   `json:"committeeId"`
			Committee   []string `json:"committee"`
			K           int      `json:"k"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		pkg, err := avssEngine.StartDealerSharing(req.SessionID, req.CommitteeID, req.Committee, req.K, nil, nil)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          true,
			"sessionId":        pkg.SessionID,
			"commitments":      pkg.CommitmentMatrix.ToHexMatrix(),
			"secretCommitment": pkg.CommitmentMatrix.SecretCommitment().Hex(),
		})
	})

	// GET /node/avss/session/status
	mux.HandleFunc("/node/avss/session/status", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			http.Error(w, `{"error":"sessionId required"}`, http.StatusBadRequest)
			return
		}

		sess, err := avssEngine.GetSession(sessionID)
		if err != nil {
			http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
			return
		}

		pubShare := ""
		if sess.PublicShareCommitment != nil {
			pubShare = sess.PublicShareCommitment.Hex()
		}
		pubSecret := ""
		if sess.PublicSecretCommitment != nil {
			pubSecret = sess.PublicSecretCommitment.Hex()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessionId":              sess.SessionID,
			"committeeId":            sess.CommitteeID,
			"dealerId":               sess.DealerID,
			"nodeId":                 avssEngine.NodeID,
			"epoch":                  sess.Epoch,
			"n":                      sess.N,
			"k":                      sess.K,
			"t":                      sess.T,
			"state":                  string(sess.State),
			"publicShareCommitment":  pubShare,
			"publicSecretCommitment": pubSecret,
			"echoCount":              len(sess.ReceivedEchos),
			"readyCount":             len(sess.ReceivedReadys),
			"completed":              sess.State == avss.StateSharingCompleted,
		})
	})

	// GET /node/avss/commitments
	mux.HandleFunc("/node/avss/commitments", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		sess, err := avssEngine.GetSession(sessionID)
		if err != nil || sess.Commitments == nil {
			http.Error(w, `{"error":"Commitments not found for session"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessionId":        sess.SessionID,
			"commitments":      sess.Commitments.ToHexMatrix(),
			"secretCommitment": sess.Commitments.SecretCommitment().Hex(),
		})
	})

	// GET /node/avss/verification/status
	mux.HandleFunc("/node/avss/verification/status", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		sess, err := avssEngine.GetSession(sessionID)
		if err != nil {
			http.Error(w, `{"error":"Session not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessionId":      sess.SessionID,
			"nodeId":         avssEngine.NodeID,
			"hasRowPoly":     sess.RowPoly != nil,
			"hasColPoly":     sess.ColPoly != nil,
			"echoCount":      len(sess.ReceivedEchos),
			"readyCount":     len(sess.ReceivedReadys),
			"requiredEchos":  sess.N - sess.T,
			"requiredReadys": sess.K + sess.T,
			"state":          string(sess.State),
		})
	})

	// POST /node/avss/reconstruct — HARD DISABLED BY PROTOCOL POLICY (Requirement R4)
	// Private signing keys are NEVER created, assembled, reconstructed, or persisted on any server, node, or coordinator.
	mux.HandleFunc("/node/avss/reconstruct", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Forbidden: Secret reconstruction is strictly prohibited by SARAL Protocol Security Policy R4"}`, http.StatusForbidden)
	})

	// GET /node/proactive/status
	mux.HandleFunc("/node/proactive/status", func(w http.ResponseWriter, r *http.Request) {
		status := proactiveMgr.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	// POST /node/proactive/refresh
	mux.HandleFunc("/node/proactive/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			CommitteeID string   `json:"committeeId"`
			Committee   []string `json:"committee"`
			K           int      `json:"k"`
			T           int      `json:"t"`
			PeerCommitments map[string]string `json:"peerCommitments"`
			MasterCommitment string `json:"masterCommitment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		parsedPeers := make(map[string]*cryptography.CurvePoint)
		for id, h := range req.PeerCommitments {
			pt, err := cryptography.ParseCurvePointFromHex(h)
			if err == nil {
				parsedPeers[id] = pt
			}
		}
		masterPt, _ := cryptography.ParseCurvePointFromHex(req.MasterCommitment)

		rs, err := proactiveMgr.RequestProactiveRefresh(req.CommitteeID, req.Committee, req.K, req.T, parsedPeers, masterPt)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"committee": req.CommitteeID,
			"oldEpoch":  rs.OldEpoch,
			"newEpoch":  rs.NewEpoch,
			"state":     string(rs.State),
		})
	})
}

