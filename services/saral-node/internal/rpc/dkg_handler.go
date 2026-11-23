package rpc

import (
	"encoding/json"
	"fmt"
	"log"
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Invalid request payload"}`, http.StatusBadRequest)
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

	// POST /node/dkg/share-contribution — Returns public verification point Y_i = x_i * G
	// strictly WITHOUT EVER exposing or reconstructing the private scalar share x_i.
	// Enforces INDEPENDENT NODE-LEVEL OWNERSHIP VERIFICATION (Section 11):
	// Verifies EdDSA token signature, MFA claim, derive_public_key operation, and
	// authenticates that token caller user ID matches stored vault user binding.
	mux.HandleFunc("/node/dkg/share-contribution", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
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
			Token       string `json:"token"`
		}

		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&req)
		} else {
			req.SessionID = r.URL.Query().Get("sessionId")
			req.CommitteeID = r.URL.Query().Get("committeeId")
			req.KeyID = r.URL.Query().Get("keyId")
			req.UserID = r.URL.Query().Get("userId")
			req.WalletID = r.URL.Query().Get("walletId")
			req.Curve = r.URL.Query().Get("curve")
			req.ChainFamily = r.URL.Query().Get("chainFamily")
			req.Token = r.URL.Query().Get("token")
		}

		if req.SessionID == "" && req.KeyID != "" {
			req.SessionID = req.KeyID
		}

		bearerToken := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			bearerToken = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}
		if bearerToken == "" {
			bearerToken = r.Header.Get("X-Saral-Auth-Token")
		}
		if bearerToken == "" {
			bearerToken = req.Token
		}

		isInternal := auth.ValidateInternalAuth(r) || auth.ValidateAdminAuth(r)

		// 1. INDEPENDENT NODE-LEVEL OWNERSHIP & AUTH VERIFICATION (Section 11)
		var claims *auth.ScopedTokenClaims
		if !isInternal || req.UserID != "" || req.WalletID != "" || bearerToken != "" {
			if bearerToken == "" {
				log.Printf("[SECURITY_ALERT] Missing bearer token for user-bound key on node %s", dkgEngine.NodeID)
				http.Error(w, `{"error":"SECURITY_ALERT: missing required bearer authorization token for user wallet key"}`, http.StatusUnauthorized)
				return
			}

			verifier := auth.GetNodeTokenVerifier()
			c, verifyErr := verifier.VerifyScopedToken(bearerToken)
			if verifyErr != nil {
				log.Printf("[SECURITY_ALERT] Invalid token signature/expiry on node %s: %v", dkgEngine.NodeID, verifyErr)
				http.Error(w, fmt.Sprintf(`{"error":"SECURITY_ALERT: invalid caller authorization: %s"}`, verifyErr.Error()), http.StatusForbidden)
				return
			}
			claims = c

			// Verify required claims:
			if claims.Operation != "" && claims.Operation != "derive_public_key" {
				log.Printf("[SECURITY_ALERT] Invalid operation '%s' requested on node %s", claims.Operation, dkgEngine.NodeID)
				http.Error(w, `{"error":"SECURITY_ALERT: unauthorized operation claim"}`, http.StatusForbidden)
				return
			}

			if !claims.MFAVerified {
				log.Printf("[SECURITY_ALERT] MFA not verified in token on node %s", dkgEngine.NodeID)
				http.Error(w, `{"error":"SECURITY_ALERT: MFA verification required"}`, http.StatusForbidden)
				return
			}

			if req.UserID != "" && claims.UserID != "" && claims.UserID != req.UserID {
				log.Printf("[SECURITY_ALERT] Cross-user access blocked on node %s: token=%s requested=%s", dkgEngine.NodeID, claims.UserID, req.UserID)
				http.Error(w, `{"error":"SECURITY_ALERT: cross-user access denied"}`, http.StatusForbidden)
				return
			}
		} else if !isInternal {
			http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// 2. Resolve key share from vault or in-memory engine
		pointHex, nodeIndex, actualEpoch, commit, meta, err := dkgEngine.GetPublicShareContribution(
			req.KeyID, req.SessionID, req.CommitteeID, req.Curve, req.Epoch,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
			return
		}

		// 3. Ownership binding validation against loaded share metadata
		if claims != nil {
			tokenUser := claims.UserID
			if tokenUser == "" {
				tokenUser = claims.Sub
			}

			// STRICT OWNERSHIP BINDING: Token user MUST match stored vault user binding!
			if meta != nil && meta.UserBindingID != "" {
				if tokenUser != meta.UserBindingID {
					log.Printf("[SECURITY_ALERT] UNAUTHORIZED SHARE CONTRIBUTION ATTEMPT on node %s: caller identity does not match stored binding",
						dkgEngine.NodeID)
					http.Error(w, `{"error":"SECURITY_ALERT: unauthorized share contribution attempt: user ownership binding mismatch"}`, http.StatusForbidden)
					return
				}
			}

			if req.UserID != "" && tokenUser != req.UserID {
				log.Printf("[SECURITY_ALERT] User ID parameter mismatch on node %s", dkgEngine.NodeID)
				http.Error(w, `{"error":"SECURITY_ALERT: user ID parameter does not match token subject"}`, http.StatusForbidden)
				return
			}

			if meta != nil && meta.WalletID != "" && claims.WalletID != "" && claims.WalletID != meta.WalletID {
				log.Printf("[SECURITY_ALERT] Wallet ID mismatch on node %s", dkgEngine.NodeID)
				http.Error(w, `{"error":"SECURITY_ALERT: wallet binding mismatch"}`, http.StatusForbidden)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":                true,
			"nodeId":                 dkgEngine.NodeID,
			"nodeIndex":              nodeIndex,
			"epoch":                  actualEpoch,
			"publicPoint":            pointHex,
			"publicSecretCommitment": commit,
		})
	})
}
