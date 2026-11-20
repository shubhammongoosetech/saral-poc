package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestEdDSAVerifierWithJWKS(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating ed25519 key: %v", err)
	}

	kid := "saral-auth-ed25519-2026-01"
	xEncoded := base64.RawURLEncoding.EncodeToString(pub)

	jwks := JWKSResponse{
		Keys: []JWKKey{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: kid,
				Alg: "EdDSA",
				Use: "sig",
				X:   xEncoded,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	verifier := NewTokenVerifier("FOUNDATION", "", server.URL)
	if err := verifier.LoadPublicKey(); err != nil {
		t.Fatalf("verifier failed loading public key from JWKS: %v", err)
	}
	if !verifier.Ready() {
		t.Fatalf("expected verifier to be ready")
	}

	// 1. Valid Genuine Token
	claims := jwt.MapClaims{
		"sub":         "operator-1",
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"mfaVerified": true,
		"domainRole":  "operator",
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("failed signing token: %v", err)
	}

	res, err := verifier.VerifyTokenWithRole(signedToken, "operator")
	if err != nil || !res.Valid {
		t.Fatalf("expected genuine token to pass verification, got err: %v, res: %+v", err, res)
	}
	if res.Sub != "operator-1" {
		t.Errorf("expected sub operator-1, got %s", res.Sub)
	}

	// 2. Reject Incompatible Algorithm (e.g. HS256)
	hsClaims := jwt.MapClaims{
		"sub":         "hacker",
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"mfaVerified": true,
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
	}
	hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, hsClaims)
	signedHS, _ := hsToken.SignedString([]byte("symmetric-secret-key-attack"))
	_, err = verifier.VerifyToken(signedHS)
	if err == nil {
		t.Errorf("expected algorithm confusion attack (HS256) to be rejected")
	}

	// 3. Reject Token with Missing MFA
	claimsNoMfa := jwt.MapClaims{
		"sub":         "operator-no-mfa",
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"mfaVerified": false,
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
	}
	tokenNoMfa := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claimsNoMfa)
	tokenNoMfa.Header["kid"] = kid
	signedNoMfa, _ := tokenNoMfa.SignedString(priv)
	_, err = verifier.VerifyToken(signedNoMfa)
	if err == nil {
		t.Errorf("expected missing MFA to be rejected")
	}

	// 4. Reject Expired Token
	claimsExpired := jwt.MapClaims{
		"sub":         "operator-expired",
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"mfaVerified": true,
		"exp":         time.Now().Add(-10 * time.Minute).Unix(),
	}
	tokenExpired := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claimsExpired)
	tokenExpired.Header["kid"] = kid
	signedExpired, _ := tokenExpired.SignedString(priv)
	_, err = verifier.VerifyToken(signedExpired)
	if err == nil {
		t.Errorf("expected expired token to be rejected")
	}

	// 5. Reject Unknown kid Fail-Closed
	tokenUnknownKid := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenUnknownKid.Header["kid"] = "unknown-kid-xyz"
	signedUnknownKid, _ := tokenUnknownKid.SignedString(priv)
	_, err = verifier.VerifyToken(signedUnknownKid)
	if err == nil {
		t.Errorf("expected unknown kid to fail closed")
	}
}

