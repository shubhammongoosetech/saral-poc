package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

type JWKKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
}

type JWKSResponse struct {
	Keys []JWKKey `json:"keys"`
}

type TokenVerifier struct {
	domain        string
	pubKeyPath    string
	authServerURL string
	keysByKid     map[string]ed25519.PublicKey
	defaultKey    ed25519.PublicKey
	lastLoaded    time.Time
	mu            sync.RWMutex
}

func NewTokenVerifier(domain, pubKeyPath, authServerURL string) *TokenVerifier {
	tv := &TokenVerifier{
		domain:        strings.ToUpper(domain),
		pubKeyPath:    pubKeyPath,
		authServerURL: authServerURL,
		keysByKid:     make(map[string]ed25519.PublicKey),
	}

	// Try initial key load
	_ = tv.LoadPublicKey()
	return tv
}

func (tv *TokenVerifier) Ready() bool {
	tv.mu.RLock()
	defer tv.mu.RUnlock()
	return len(tv.keysByKid) > 0 || len(tv.defaultKey) > 0
}

func parseJWKToEd25519(jwk JWKKey) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || (jwk.Crv != "Ed25519" && jwk.Crv != "ed25519") {
		return nil, fmt.Errorf("unsupported key type: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode jwk x parameter: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: expected %d, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func (tv *TokenVerifier) LoadPublicKey() error {
	var keyBytes []byte
	isJWKS := false

	// 1. Try file path if specified
	if tv.pubKeyPath != "" {
		if b, readErr := os.ReadFile(tv.pubKeyPath); readErr == nil && len(b) > 0 {
			keyBytes = b
			trimmed := strings.TrimSpace(string(b))
			if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, "keys") {
				isJWKS = true
			}
		}
	}

	// 2. Fetch from Auth Server JWKS endpoint if not loaded from file
	if len(keyBytes) == 0 && tv.authServerURL != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		jwksEndpoints := []string{
			strings.TrimRight(tv.authServerURL, "/") + "/.well-known/jwks.json",
			strings.TrimRight(tv.authServerURL, "/") + "/api/.well-known/jwks.json",
			strings.TrimRight(tv.authServerURL, "/") + "/auth/jwks.json",
			strings.TrimRight(tv.authServerURL, "/") + "/auth/public-key",
		}

		for _, endpoint := range jwksEndpoints {
			resp, fetchErr := client.Get(endpoint)
			if fetchErr == nil && resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if len(body) > 0 {
					keyBytes = body
					trimmed := strings.TrimSpace(string(body))
					if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, "keys") {
						isJWKS = true
					}
					break
				}
			}
		}
	}

	if len(keyBytes) == 0 {
		return errors.New("no public key material available (file or auth server)")
	}

	tv.mu.Lock()
	defer tv.mu.Unlock()

	// Parse JWKS payload
	if isJWKS || (strings.HasPrefix(strings.TrimSpace(string(keyBytes)), "{") && strings.Contains(string(keyBytes), "keys")) {
		var jwks JWKSResponse
		if err := json.Unmarshal(keyBytes, &jwks); err == nil && len(jwks.Keys) > 0 {
			for _, k := range jwks.Keys {
				if pub, err := parseJWKToEd25519(k); err == nil {
					kid := k.Kid
					if kid == "" {
						kid = "saral-auth-ed25519-2026-01"
					}
					tv.keysByKid[kid] = pub
					if len(tv.defaultKey) == 0 {
						tv.defaultKey = pub
					}
				}
			}
			tv.lastLoaded = time.Now()
			return nil
		}
	}

	// Parse PEM block (SPKI or Ed25519 public key)
	block, _ := pem.Decode(keyBytes)
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKIX public key: %w", err)
		}

		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("public key is not an Ed25519 public key (RSA and other algorithms rejected)")
		}

		defaultKid := "saral-auth-ed25519-2026-01"
		tv.keysByKid[defaultKid] = edPub
		tv.defaultKey = edPub
		tv.lastLoaded = time.Now()
		return nil
	}

	// Try parsing raw 32-byte Ed25519 public key
	if len(keyBytes) == ed25519.PublicKeySize {
		edPub := ed25519.PublicKey(keyBytes)
		defaultKid := "saral-auth-ed25519-2026-01"
		tv.keysByKid[defaultKid] = edPub
		tv.defaultKey = edPub
		tv.lastLoaded = time.Now()
		return nil
	}

	return errors.New("failed to parse valid Ed25519 public key or JWKS from trust material")
}

func (tv *TokenVerifier) getKeyByKid(kid string) (ed25519.PublicKey, bool) {
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	if kid != "" {
		if k, ok := tv.keysByKid[kid]; ok {
			return k, true
		}
		// When kid is explicitly specified, fail-closed: do NOT fall back to a different key!
		return nil, false
	}
	if len(tv.defaultKey) > 0 {
		return tv.defaultKey, true
	}
	return nil, false
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

	tokenClean := strings.TrimSpace(strings.TrimPrefix(tokenStr, "Bearer "))
	if tokenClean == "" {
		return &AuthResult{Valid: false, Error: "Missing or empty bearer token"}, errors.New("missing token")
	}

	// Parse unverified header to extract kid and validate algorithm
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenClean, jwt.MapClaims{})
	if err != nil {
		return &AuthResult{Valid: false, Error: "Malformed JWT token structure"}, fmt.Errorf("malformed token: %w", err)
	}

	// Strict EdDSA algorithm check
	alg, ok := unverifiedToken.Header["alg"].(string)
	if !ok || alg != "EdDSA" {
		errMsg := fmt.Sprintf("invalid token algorithm %v: only EdDSA is permitted", unverifiedToken.Header["alg"])
		return &AuthResult{Valid: false, Error: errMsg}, errors.New(errMsg)
	}

	kid, _ := unverifiedToken.Header["kid"].(string)
	pubKey, found := tv.getKeyByKid(kid)

	// If kid not found in cache, attempt a fresh JWKS reload (key rotation support)
	if !found && tv.authServerURL != "" {
		_ = tv.LoadPublicKey()
		pubKey, found = tv.getKeyByKid(kid)
	}

	if !found || len(pubKey) == 0 {
		errMsg := fmt.Sprintf("no trusted verification key found for kid '%s' (fail closed)", kid)
		return &AuthResult{Valid: false, Error: errMsg}, errors.New(errMsg)
	}

	// Parse and validate signature, alg, iss, aud, exp, nbf
	token, err := jwt.Parse(tokenClean, func(token *jwt.Token) (interface{}, error) {
		// Strict EdDSA algorithm enforcement
		if token.Method.Alg() != "EdDSA" {
			return nil, fmt.Errorf("invalid token algorithm %v: only EdDSA is permitted", token.Header["alg"])
		}
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	},
		jwt.WithIssuer("saral-auth-server"),
		jwt.WithAudience("saral-domain-coordinators"),
		jwt.WithLeeway(10*time.Second),
	)

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
