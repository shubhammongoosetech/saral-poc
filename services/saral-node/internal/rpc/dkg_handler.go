package rpc

import (
	"encoding/json"
	"net/http"

	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/internal/auth"
)

// RegisterDKGRoutes registers HTTP endpoints for DKG coordination on the node
func RegisterDKGRoutes(mux *http.ServeMux, dkgEngine *dkg.Engine) {
	// POST /node/dkg/init — Initialize a DKG session on the node
	mux.HandleFunc("/node/dkg/init", func(w http.ResponseWriter, r *http.Request) {
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
			N           int      `json:"n"`
			K           int      `json:"k"`
			T           int      `json:"t"`
			Committee   []string `json:"committee"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		sess, err := dkgEngine.CreateSession(req.SessionID, req.CommitteeID, req.N, req.K, req.T, req.Committee)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"sessionId": sess.SessionID,
			"nodeId":    dkgEngine.NodeID,
			"state":     string(sess.State),
		})
	})

	// POST /node/dkg/start — Trigger the node to independently deal its contribution
	mux.HandleFunc("/node/dkg/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}

		if err := dkgEngine.StartContribution(req.SessionID); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		sess, _ := dkgEngine.GetSession(req.SessionID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"sessionId": req.SessionID,
			"nodeId":    dkgEngine.NodeID,
			"state":     string(sess.State),
		})
	})

	// GET /node/dkg/status — Query public view of a DKG session
	mux.HandleFunc("/node/dkg/status", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			// Return all sessions
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"nodeId":   dkgEngine.NodeID,
				"sessions": dkgEngine.GetAllSessionViews(),
			})
			return
		}

		sess, err := dkgEngine.GetSession(sessionID)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sess.GetPublicView())
	})

	// GET /node/dkg/publickey — Query the agreed master public key
	mux.HandleFunc("/node/dkg/publickey", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("sessionId")
		sess, err := dkgEngine.GetSession(sessionID)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}

		view := sess.GetPublicView()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessionId":       sess.SessionID,
			"committeeId":     sess.CommitteeID,
			"masterPublicKey": view.MasterPublicKey,
			"curve":           view.Curve,
			"state":           string(view.State),
		})
	})
}
