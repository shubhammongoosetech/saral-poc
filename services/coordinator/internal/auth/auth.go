package auth

import (
	"net/http"
	"os"
	"strings"
)

const (
	HeaderInternalToken = "X-Saral-Internal-Token"
	HeaderAuthorization = "Authorization"
	DevDefaultToken     = "saral-internal-secure-token-2026-v3"
)

// GetInternalToken returns the provisioned internal service-to-service token
func GetInternalToken() string {
	if token := os.Getenv("SARAL_INTERNAL_TOKEN"); token != "" {
		return token
	}
	if os.Getenv("ENABLE_DEV_AUTH") == "true" || os.Getenv("NODE_ENV") != "production" {
		return DevDefaultToken
	}
	return ""
}

// ValidateInternalAuth checks if the request contains valid service-to-service credentials
func ValidateInternalAuth(r *http.Request) bool {
	expectedToken := GetInternalToken()
	if expectedToken == "" {
		// In strict production with no token provisioned, fail closed
		return false
	}

	// 1. Check X-Saral-Internal-Token
	if internalToken := r.Header.Get(HeaderInternalToken); internalToken != "" {
		if internalToken == expectedToken {
			return true
		}
	}

	// 2. Check Authorization: Bearer <token>
	if authHeader := r.Header.Get(HeaderAuthorization); authHeader != "" {
		bearerToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if bearerToken == expectedToken {
			return true
		}
	}

	return false
}
