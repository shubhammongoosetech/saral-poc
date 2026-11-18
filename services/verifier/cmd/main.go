package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/saral-protocol/saral-poc/services/verifier/internal/auth"
	"github.com/saral-protocol/saral-poc/services/verifier/internal/health"
)

type VerifyRequest struct {
	Token        string `json:"token"`
	RequiredRole string `json:"requiredRole,omitempty"`
}

func main() {
	domainFlag := flag.String("domain", getEnv("DOMAIN", "FOUNDATION"), "Domain: FOUNDATION | PUBLIC | PRIVATE")
	portFlag := flag.Int("port", getEnvInt("PORT", getEnvInt("HTTP_PORT", 9101)), "HTTP Port to listen on")
	pubKeyFlag := flag.String("pubkey", getEnv("PUBLIC_KEY_PATH", "/keys/auth_public_key.pem"), "Path to auth server RSA public key PEM")
	authServerFlag := flag.String("auth-server-url", getEnv("AUTH_SERVER_URL", "http://localhost:3001"), "Auth Server URL for public key discovery")
	flag.Parse()

	domain := strings.ToUpper(*domainFlag)
	log.Printf("[SARAL Verifier - %s] Starting on port %d...", domain, *portFlag)

	verifier := auth.NewTokenVerifier(domain, *pubKeyFlag, *authServerFlag)

	http.HandleFunc("/health", health.Handler(domain, verifier.Ready))

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"valid":false,"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			tokenHeader := r.Header.Get("Authorization")
			req.Token = tokenHeader
		}

		if req.Token == "" {
			req.Token = r.Header.Get("Authorization")
		}

		result, _ := verifier.VerifyTokenWithRole(req.Token, req.RequiredRole)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(result)
	})

	addr := fmt.Sprintf(":%d", *portFlag)
	log.Printf("[SARAL Verifier - %s] Ready and listening on http://localhost%s", domain, addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Verifier server fatal error: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var out int
		if _, err := fmt.Sscanf(v, "%d", &out); err == nil {
			return out
		}
	}
	return defaultVal
}
