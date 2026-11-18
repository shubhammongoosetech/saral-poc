package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthResult struct {
	Valid  bool                   `json:"valid"`
	Sub    string                 `json:"sub,omitempty"`
	Domain string                 `json:"domain,omitempty"`
	Role   string                 `json:"role,omitempty"`
	Claims map[string]interface{} `json:"claims,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

type TokenVerifier struct {
	domain        string
	pubKeyPath    string
	authServerURL string
	parsedPubKey  *rsa.PublicKey
	mu            sync.RWMutex
}

func NewTokenVerifier(domain, pubKeyPath, authServerURL string) *TokenVerifier {
	tv := &TokenVerifier{
		domain:        strings.ToUpper(domain),
		pubKeyPath:    pubKeyPath,
		authServerURL: authServerURL,
	}

	// Try initial key load
	_ = tv.LoadPublicKey()
	return tv
}

func (tv *TokenVerifier) Ready() bool {
	tv.mu.RLock()
	defer tv.mu.RUnlock()
	return tv.parsedPubKey != nil
}

func (tv *TokenVerifier) LoadPublicKey() error {
	var pemBytes []byte

	// 1. Try file path if specified
	if tv.pubKeyPath != "" {
		if b, readErr := os.ReadFile(tv.pubKeyPath); readErr == nil && len(b) > 0 {
			pemBytes = b
		}
	}

	// 2. Fall back to Auth Server URL if file not found
	if len(pemBytes) == 0 && tv.authServerURL != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, fetchErr := client.Get(strings.TrimRight(tv.authServerURL, "/") + "/auth/public-key")
		if fetchErr == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			pemBytes, _ = io.ReadAll(resp.Body)
		}
	}

	if len(pemBytes) == 0 {
		return errors.New("no public key material available (file or auth server)")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("failed to parse PEM block from public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not an RSA public key")
	}

	tv.mu.Lock()
	tv.parsedPubKey = rsaPub
	tv.mu.Unlock()
	return nil
}

func (tv *TokenVerifier) VerifyToken(tokenStr string) (*AuthResult, error) {
	return tv.VerifyTokenWithRole(tokenStr, "")
}

func (tv *TokenVerifier) VerifyTokenWithRole(tokenStr string, requiredRole string) (*AuthResult, error) {
	// Re-attempt load if not yet ready
	if !tv.Ready() {
		if err := tv.LoadPublicKey(); err != nil {
			return &AuthResult{
				Valid: false,
				Error: "Trust material unavailable (fail closed): " + err.Error(),
			}, errors.New("verifier trust material unavailable")
		}
	}

	tv.mu.RLock()
	pubKey := tv.parsedPubKey
	tv.mu.RUnlock()

	if pubKey == nil {
		return &AuthResult{
			Valid: false,
			Error: "Public key is not initialized",
		}, errors.New("uninitialized public key")
	}

	tokenClean := strings.TrimSpace(strings.TrimPrefix(tokenStr, "Bearer "))
	if tokenClean == "" {
		return &AuthResult{Valid: false, Error: "Missing or empty bearer token"}, errors.New("missing token")
	}

	// Parse and validate signature, alg, iss, aud, exp, nbf
	token, err := jwt.Parse(tokenClean, func(token *jwt.Token) (interface{}, error) {
		// Strict RS256 algorithm enforcement
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("invalid token algorithm %v: only RS256 is permitted", token.Header["alg"])
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	},
		jwt.WithIssuer("saral-auth-server"),
		jwt.WithAudience("saral-domain-coordinators"),
		jwt.WithLeeway(10*time.Second),
	)

	if err != nil || !token.Valid {
		// In case of auth-server restart or key rotation, attempt a fresh key reload
		if tv.authServerURL != "" {
			if reloadErr := tv.LoadPublicKey(); reloadErr == nil {
				tv.mu.RLock()
				refreshedPubKey := tv.parsedPubKey
				tv.mu.RUnlock()

				token, err = jwt.Parse(tokenClean, func(token *jwt.Token) (interface{}, error) {
					if token.Method.Alg() != "RS256" {
						return nil, fmt.Errorf("invalid token algorithm %v: only RS256 is permitted", token.Header["alg"])
					}
					return refreshedPubKey, nil
				},
					jwt.WithIssuer("saral-auth-server"),
					jwt.WithAudience("saral-domain-coordinators"),
					jwt.WithLeeway(10*time.Second),
				)
			}
		}
	}

	if err != nil || !token.Valid {
		errMsg := "invalid token signature, algorithm or claims"
		if err != nil {
			errMsg = err.Error()
		}
		return &AuthResult{
			Valid: false,
			Error: errMsg,
		}, fmt.Errorf("token verification failed: %s", errMsg)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &AuthResult{Valid: false, Error: "Invalid claims structure"}, errors.New("invalid claims")
	}

	// Validate MFA claim
	if mfa, ok := claims["mfaVerified"].(bool); !ok || !mfa {
		return &AuthResult{Valid: false, Error: "MFA verification claim missing or false"}, errors.New("mfa claim required")
	}

	sub, _ := claims.GetSubject()
	role, _ := claims["domainRole"].(string)

	// Validate role authorization if required
	if requiredRole != "" {
		if role != "admin" && role != requiredRole {
			return &AuthResult{
				Valid: false,
				Sub:   sub,
				Role:  role,
				Error: fmt.Sprintf("insufficient permissions: required %s, got %s", requiredRole, role),
			}, fmt.Errorf("insufficient role permissions: %s", role)
		}
	}

	return &AuthResult{
		Valid:  true,
		Sub:    sub,
		Domain: tv.domain,
		Role:   role,
		Claims: claims,
	}, nil
}
