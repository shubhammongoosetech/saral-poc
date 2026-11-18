package auth_test

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/auth"
)

func TestAuthSecurityAndRotation(t *testing.T) {
	// 1. Fail closed when absent
	os.Unsetenv("SARAL_INTERNAL_TOKEN")
	os.Unsetenv("SARAL_INTERNAL_TOKEN_FILE")
	auth.LoadInternalToken()

	req := httptest.NewRequest("GET", "/test", nil)
	if auth.ValidateInternalAuth(req) {
		t.Fatal("expected ValidateInternalAuth to fail closed when no token provisioned")
	}

	// 2. Reject known insecure/default tokens
	insecureTokens := []string{
		"saral-internal-coordinator-secret",
		"saral-internal-secure-token-2026-v3",
		"saral-mesh-secure-internal-token-v3",
		"saral-mesh-admin-secret-2026",
		"admin",
		"secret",
	}
	for _, bad := range insecureTokens {
		os.Setenv("SARAL_INTERNAL_TOKEN", bad)
		auth.LoadInternalToken()
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Saral-Internal-Token", bad)
		if auth.ValidateInternalAuth(req) {
			t.Fatalf("expected insecure token %q to be rejected", bad)
		}
	}

	// 3. Valid securely provisioned token
	validToken := "sec-token-98f7a6b5c4d3e2f10293847561a"
	os.Setenv("SARAL_INTERNAL_TOKEN", validToken)
	auth.LoadInternalToken()

	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Saral-Internal-Token", validToken)
	if !auth.ValidateInternalAuth(req) {
		t.Fatal("expected valid token to pass")
	}

	// 4. Test Token Rotation
	rotatedToken := "rotated-sec-token-112233445566778899aabbcc"
	ok := auth.RotateToken(rotatedToken)
	if !ok {
		t.Fatal("failed to rotate token")
	}

	// During grace period: both rotated and previous token should validate
	reqRotated := httptest.NewRequest("GET", "/test", nil)
	reqRotated.Header.Set("X-Saral-Internal-Token", rotatedToken)
	if !auth.ValidateInternalAuth(reqRotated) {
		t.Fatal("expected rotated token to validate")
	}

	reqPrev := httptest.NewRequest("GET", "/test", nil)
	reqPrev.Header.Set("X-Saral-Internal-Token", validToken)
	if !auth.ValidateInternalAuth(reqPrev) {
		t.Fatal("expected previous token to validate during rotation grace period")
	}
}

