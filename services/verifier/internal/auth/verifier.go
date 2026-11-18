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
	var err error

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

	token, err := jwt.Parse(tokenClean, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	}, jwt.WithIssuer("saral-auth-server"))

	if err != nil || !token.Valid {
		errMsg := "invalid token signature or claims"
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

	sub, _ := claims.GetSubject()
	role, _ := claims["domainRole"].(string)

	return &AuthResult{
		Valid:  true,
		Sub:    sub,
		Domain: tv.domain,
		Role:   role,
		Claims: claims,
	}, nil
}
