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
)

// ScopedTokenClaims represents verified claims in an authorization token
type ScopedTokenClaims struct {
	Sub             string `json:"sub"`
	UserID          string `json:"userId"`
	WalletID        string `json:"walletId"`
	KeyID           string `json:"keyId"`
	DKGSessionID    string `json:"dkgSessionId"`
	CommitteeID     string `json:"committeeId"`
	ChainFamily     string `json:"chainFamily"`
	Curve           string `json:"curve"`
	Operation       string `json:"operation"`
	MFAVerified     bool   `json:"mfaVerified"`
	PolicySatisfied bool   `json:"policySatisfied"`
	Exp             int64  `json:"exp"`
	Iat             int64  `json:"iat"`
}

type NodeTokenVerifier struct {
	pubKeyPath    string
	authServerURL string
	keysByKid     map[string]ed25519.PublicKey
	defaultKey    ed25519.PublicKey
	lastLoaded    time.Time
	mu            sync.RWMutex
}

var (
	globalVerifier *NodeTokenVerifier
	verifierOnce   sync.Once
)

// GetNodeTokenVerifier returns the singleton NodeTokenVerifier
func GetNodeTokenVerifier() *NodeTokenVerifier {
	verifierOnce.Do(func() {
		pubPath := os.Getenv("SARAL_AUTH_PUBLIC_KEY_FILE")
		if pubPath == "" {
			pubPath = "/run/secrets/auth_ed25519_pub.pem"
		}
		authURL := os.Getenv("AUTH_SERVER_URL")
		if authURL == "" {
			authURL = "http://auth-server:3001"
		}
		globalVerifier = NewNodeTokenVerifier(pubPath, authURL)
	})
	return globalVerifier
}

// NewNodeTokenVerifier constructs a verifier
func NewNodeTokenVerifier(pubKeyPath, authServerURL string) *NodeTokenVerifier {
	v := &NodeTokenVerifier{
		pubKeyPath:    pubKeyPath,
		authServerURL: authServerURL,
		keysByKid:     make(map[string]ed25519.PublicKey),
	}
	_ = v.LoadPublicKey()
	return v
}

// SetDefaultKey allows explicit key injection (e.g. for unit tests)
func (v *NodeTokenVerifier) SetDefaultKey(pub ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.defaultKey = pub
	v.keysByKid["default"] = pub
}

func (v *NodeTokenVerifier) LoadPublicKey() error {
	var keyBytes []byte

	// 1. Try file
	if v.pubKeyPath != "" {
		if b, err := os.ReadFile(v.pubKeyPath); err == nil && len(b) > 0 {
			keyBytes = b
		}
	}

	// 2. Try raw public key env var
	if len(keyBytes) == 0 {
		if raw := os.Getenv("SARAL_AUTH_PUBLIC_KEY"); raw != "" {
			keyBytes = []byte(raw)
		}
	}

	// 3. Try JWKS from auth server
	if len(keyBytes) == 0 && v.authServerURL != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		endpoints := []string{
			strings.TrimRight(v.authServerURL, "/") + "/.well-known/jwks.json",
			strings.TrimRight(v.authServerURL, "/") + "/auth/public-key",
		}
		for _, ep := range endpoints {
			resp, err := client.Get(ep)
			if err == nil && resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if len(body) > 0 {
					keyBytes = body
					break
				}
			}
		}
	}

	if len(keyBytes) == 0 {
		return errors.New("no public key material found for NodeTokenVerifier")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Parse JWKS JSON if present
	trimmed := strings.TrimSpace(string(keyBytes))
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, "keys") {
		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Crv string `json:"crv"`
				Kid string `json:"kid"`
				X   string `json:"x"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(keyBytes, &jwks); err == nil && len(jwks.Keys) > 0 {
			for _, k := range jwks.Keys {
				if k.Kty == "OKP" && strings.EqualFold(k.Crv, "Ed25519") {
					raw, decErr := base64.RawURLEncoding.DecodeString(k.X)
					if decErr != nil {
						raw, decErr = base64.URLEncoding.DecodeString(k.X)
					}
					if decErr == nil && len(raw) == ed25519.PublicKeySize {
						pub := ed25519.PublicKey(raw)
						kid := k.Kid
						if kid == "" {
							kid = "saral-auth-ed25519-2026-01"
						}
						v.keysByKid[kid] = pub
						if len(v.defaultKey) == 0 {
							v.defaultKey = pub
						}
					}
				}
			}
			v.lastLoaded = time.Now()
			return nil
		}
	}

	// Parse PEM format
	block, _ := pem.Decode(keyBytes)
	if block != nil {
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if edPub, ok := pub.(ed25519.PublicKey); ok {
				v.defaultKey = edPub
				v.keysByKid["default"] = edPub
				v.lastLoaded = time.Now()
				return nil
			}
		}
	}

	// Parse raw 32-byte key
	if len(keyBytes) == ed25519.PublicKeySize {
		v.defaultKey = ed25519.PublicKey(keyBytes)
		v.keysByKid["default"] = v.defaultKey
		v.lastLoaded = time.Now()
		return nil
	}

	return errors.New("failed parsing valid Ed25519 public key")
}

// VerifyScopedToken decodes and cryptographically verifies an EdDSA JWT token
func (v *NodeTokenVerifier) VerifyScopedToken(tokenStr string) (*ScopedTokenClaims, error) {
	tokenClean := strings.TrimSpace(strings.TrimPrefix(tokenStr, "Bearer "))
	if tokenClean == "" {
		return nil, errors.New("missing or empty token")
	}

	parts := strings.Split(tokenClean, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT structure: expected 3 segments")
	}

	// 1. Decode header
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed decoding token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid token header JSON: %w", err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("invalid algorithm %s: only EdDSA is permitted", header.Alg)
	}

	// 2. Decode claims
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed decoding token payload: %w", err)
	}
	var claims ScopedTokenClaims
	if err := json.Unmarshal(pBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims JSON: %w", err)
	}

	// 3. Resolve key
	v.mu.RLock()
	var pub ed25519.PublicKey
	if header.Kid != "" {
		pub = v.keysByKid[header.Kid]
	}
	if len(pub) == 0 {
		pub = v.defaultKey
	}
	v.mu.RUnlock()

	if len(pub) == 0 {
		_ = v.LoadPublicKey()
		v.mu.RLock()
		if header.Kid != "" {
			pub = v.keysByKid[header.Kid]
		}
		if len(pub) == 0 {
			pub = v.defaultKey
		}
		v.mu.RUnlock()
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("trusted Ed25519 verification key unavailable (fail-closed)")
	}

	// 4. Verify cryptographic signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed decoding token signature: %w", err)
	}
	signedPayload := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pub, signedPayload, sig) {
		return nil, errors.New("invalid EdDSA token signature")
	}

	// 5. Check expiry (with 10-second grace window)
	now := time.Now().Unix()
	if claims.Exp != 0 && claims.Exp < now-10 {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

