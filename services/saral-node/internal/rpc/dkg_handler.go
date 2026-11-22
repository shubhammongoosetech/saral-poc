package rpc

import (
	"encoding/json"
	"net/http"
	"strings"

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
			WalletID    string   `json:"walletId"`
			KeyID       string   `json:"keyId"`
			UserID      string   `json:"userId"`
			Curve       string   `json:"curve"`
			ChainFamily string   `json:"chainFamily"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
			return
		}
		if (req.UserID != "" || req.WalletID != "" || req.KeyID != "") &&
			!hasDKGScope(r, "start_dkg", req.UserID, req.WalletID, req.KeyID, req.SessionID, req.CommitteeID, req.Curve, req.ChainFamily, 1) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		sess, err := dkgEngine.CreateSessionWithBinding(
			req.SessionID, req.CommitteeID, req.WalletID, req.KeyID, req.UserID, req.Curve, req.ChainFamily,
			req.N, req.K, req.T, req.Committee,
		)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"sessionId": sess.SessionID,
			"nodeId":    dkgEngine.NodeID,
			"state":     string(sess.GetPublicView().State),
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

		sess, err := dkgEngine.GetSession(req.SessionID)
		if err != nil {
			http.Error(w, "DKG session unavailable", http.StatusNotFound)
			return
		}
		if sess.UserBindingID != "" && !hasDKGScope(r, "start_dkg", sess.UserBindingID, sess.WalletID, sess.KeyID,
			sess.SessionID, sess.CommitteeID, string(sess.Curve), sess.ChainFamily, sess.Epoch) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if err := dkgEngine.StartContribution(req.SessionID); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"sessionId": req.SessionID,
			"nodeId":    dkgEngine.NodeID,
			"state":     string(sess.GetPublicView().State),
		})
	})

	// GET /node/dkg/status — Query public view of a DKG session
	mux.HandleFunc("/node/dkg/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
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
		if err != nil && dkgEngine.HasPersistedWalletShare(sessionID, r.URL.Query().Get("keyId")) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"state": dkg.StateCompleted})
			return
		}
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

	// POST /node/dkg/share-contribution resolves a public point for an exact share.
	mux.HandleFunc("/node/dkg/share-contribution", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			SessionID   string `json:"sessionId"`
			CommitteeID string `json:"committeeId"`
			Epoch       uint64 `json:"epoch"`
			UserID      string `json:"userId"`
			WalletID    string `json:"walletId"`
			KeyID       string `json:"keyId"`
			Curve       string `json:"curve"`
			ChainFamily string `json:"chainFamily"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		bound := req.UserID != "" || req.WalletID != "" || req.KeyID != ""
		if bound {
			if !hasDKGScope(r, "derive_public_key", req.UserID, req.WalletID, req.KeyID, req.SessionID, req.CommitteeID, req.Curve, req.ChainFamily, req.Epoch) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		} else if !auth.ValidateInternalAuth(r) && !auth.ValidateAdminAuth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		point, nodeIndex, epoch, commitment, meta, err := dkgEngine.GetPublicShareContribution(
			req.KeyID, req.SessionID, req.CommitteeID, req.Curve, req.Epoch,
		)
		if err != nil {
			http.Error(w, "Verified DKG share unavailable", http.StatusNotFound)
			return
		}
		if meta.UserBindingID != req.UserID || meta.WalletID != req.WalletID || meta.ChainFamily != req.ChainFamily {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":                    true,
			"nodeId":                     meta.NodeID,
			"nodeIndex":                  nodeIndex,
			"epoch":                      epoch,
			"publicPoint":                point,
			"publicSecretCommitment":     commitment,
			"masterSigningPublicKeyHash": meta.MasterSigningPublicKeyHash,
		})
	})
}

func hasDKGScope(r *http.Request, operation, userID, walletID, keyID, sessionID, committeeID, curve, chain string, epoch uint64) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || userID == "" || walletID == "" || keyID == "" || sessionID == "" || committeeID == "" ||
		curve == "" || chain == "" || epoch == 0 {
		return false
	}
	claims, err := auth.GetNodeTokenVerifier().VerifyScopedToken(token)
	return err == nil && claims.Operation == operation && claims.MFAVerified && claims.PolicySatisfied &&
		claims.Sub == userID && claims.UserID == userID && claims.WalletID == walletID && claims.KeyID == keyID &&
		claims.DKGSessionID == sessionID && claims.CommitteeID == committeeID && claims.Curve == curve &&
		claims.ChainFamily == chain && claims.Epoch == epoch
}
