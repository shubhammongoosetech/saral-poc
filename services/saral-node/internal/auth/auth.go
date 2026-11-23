package auth

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	HeaderInternalToken = "X-Saral-Internal-Token"
	HeaderAdminKey      = "X-Admin-Key"
	HeaderAuthorization = "Authorization"
	DefaultSecretPath   = "/run/secrets/saral_internal_token"
	DefaultAdminPath    = "/run/secrets/saral_admin_key"
)

var knownInsecureTokens = map[string]bool{
	"saral-internal-secure-token-2026-v3": true,
	"saral-mesh-secure-internal-token-v3": true,
	"saral-mesh-admin-secret-2026":        true,
	"admin":                               true,
	"secret":                              true,
	"password":                            true,
	"default":                             true,
}

var (
	tokenMu       sync.RWMutex
	activeToken   string
	allowedTokens []string

	adminMu     sync.RWMutex
	activeAdmin string
)

func IsKnownInsecure(t string) bool {
	return knownInsecureTokens[strings.ToLower(strings.TrimSpace(t))]
}

// LoadInternalToken reads internal credentials strictly without hardcoded fallback.
func LoadInternalToken() string {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	// 1. Docker secret file
	secretPath := os.Getenv("SARAL_INTERNAL_TOKEN_FILE")
	if secretPath == "" {
		secretPath = DefaultSecretPath
	}
	if data, err := os.ReadFile(secretPath); err == nil {
		tok := strings.TrimSpace(string(data))
		if tok != "" && !IsKnownInsecure(tok) {
			activeToken = tok
			allowedTokens = []string{tok}
			return tok
		}
	}

	// 2. Environment variable
	if tok := strings.TrimSpace(os.Getenv("SARAL_INTERNAL_TOKEN")); tok != "" {
		if !IsKnownInsecure(tok) {
			activeToken = tok
			allowedTokens = []string{tok}
			return tok
		}
	}

	// Fail closed
	activeToken = ""
	allowedTokens = nil
	return ""
}

// GetInternalToken returns the currently active service token
func GetInternalToken() string {
	tokenMu.RLock()
	tok := activeToken
	tokenMu.RUnlock()
	if tok != "" {
		return tok
	}
	return LoadInternalToken()
}

// RotateToken dynamically rotates the active token with grace period support
func RotateToken(newToken string) bool {
	clean := strings.TrimSpace(newToken)
	if clean == "" || IsKnownInsecure(clean) || len(clean) < 16 {
		return false
	}

	tokenMu.Lock()
	defer tokenMu.Unlock()

	prev := activeToken
	activeToken = clean
	if prev != "" && prev != clean {
		allowedTokens = []string{clean, prev}
	} else {
		allowedTokens = []string{clean}
	}
	return true
}

func GetAllowedTokens() []string {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	res := make([]string, len(allowedTokens))
	copy(res, allowedTokens)
	return res
}

// GetAdminKey reads administrative key from file or environment
func GetAdminKey() string {
	adminMu.RLock()
	key := activeAdmin
	adminMu.RUnlock()
	if key != "" {
		return key
	}

	adminMu.Lock()
	defer adminMu.Unlock()

	adminPath := os.Getenv("SARAL_ADMIN_KEY_FILE")
	if adminPath == "" {
		adminPath = DefaultAdminPath
	}
	if data, err := os.ReadFile(adminPath); err == nil {
		k := strings.TrimSpace(string(data))
		if k != "" && !IsKnownInsecure(k) {
			activeAdmin = k
			return k
		}
	}

	if k := strings.TrimSpace(os.Getenv("SARAL_ADMIN_KEY")); k != "" {
		if !IsKnownInsecure(k) {
			activeAdmin = k
			return k
		}
	}

	activeAdmin = ""
	return ""
}

// ValidateAdminAuth validates administrator requests
func ValidateAdminAuth(r *http.Request) bool {
	expected := GetAdminKey()
	if expected == "" {
		return false
	}

	provided := strings.TrimSpace(r.Header.Get(HeaderAdminKey))
	if provided == "" {
		if authHeader := r.Header.Get(HeaderAuthorization); authHeader != "" {
			provided = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}
	}

	if provided == "" || IsKnownInsecure(provided) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// ValidateInternalAuth checks if request contains valid service-to-service credentials
func ValidateInternalAuth(r *http.Request) bool {
	tokenMu.RLock()
	tokens := allowedTokens
	active := activeToken
	tokenMu.RUnlock()

	if len(tokens) == 0 && active == "" {
		LoadInternalToken()
		tokenMu.RLock()
		tokens = allowedTokens
		active = activeToken
		tokenMu.RUnlock()
	}

	if len(tokens) == 0 && active == "" {
		// Strict fail-closed
		return false
	}

	var candidate string
	if it := r.Header.Get(HeaderInternalToken); it != "" {
		candidate = strings.TrimSpace(it)
	} else if authHeader := r.Header.Get(HeaderAuthorization); authHeader != "" {
		candidate = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}

	if candidate == "" || IsKnownInsecure(candidate) {
		return false
	}

	for _, expected := range tokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}

	return false
}
