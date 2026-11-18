package tlsutil_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/coordinator/internal/tlsutil"
)

func TestTLSAndMutualAuthentication(t *testing.T) {
	// 1. Generate Root CA
	caCert, caKey, err := tlsutil.GenerateCA("saral-cluster-root-ca")
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// 2. Generate Server Certificate
	serverCert, serverKey, err := tlsutil.GenerateCert(caCert, caKey, "saral-coord-foundation", []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	// 3. Generate Legitimate Node Client Certificate (CN: saral-foundation-1)
	clientCert, clientKey, err := tlsutil.GenerateCert(caCert, caKey, "saral-foundation-1", []string{"localhost"})
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	// 4. Generate Untrusted / Invalid Identity Certificate (CN: rogue-attacker)
	untrustedCert, untrustedKey, err := tlsutil.GenerateCert(caCert, caKey, "rogue-attacker", []string{"localhost"})
	if err != nil {
		t.Fatalf("failed to generate untrusted cert: %v", err)
	}

	// 5. Start mTLS test server
	serverTLSConfig, err := tlsutil.BuildServerTLSConfig(serverCert, serverKey, caCert, true)
	if err != nil {
		t.Fatalf("failed to build server TLS config: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("mtls-authenticated-success"))
	}))
	server.TLS = serverTLSConfig
	server.StartTLS()
	defer server.Close()

	// 6. Test valid mTLS client request
	validClient, err := tlsutil.NewClient(caCert, clientCert, clientKey, 3*time.Second)
	if err != nil {
		t.Fatalf("failed to create valid mTLS client: %v", err)
	}

	resp, err := validClient.Get(server.URL)
	if err != nil {
		t.Fatalf("valid mTLS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mtls-authenticated-success" {
		t.Fatalf("unexpected response body: %s", string(body))
	}

	// 7. Test rogue identity rejection (rogue-attacker rejected by VerifyPeerCertificate)
	rogueClient, err := tlsutil.NewClient(caCert, untrustedCert, untrustedKey, 3*time.Second)
	if err != nil {
		t.Fatalf("failed to create rogue mTLS client: %v", err)
	}

	_, err = rogueClient.Get(server.URL)
	if err == nil {
		t.Fatal("expected rogue client with invalid CN to be rejected, but request succeeded!")
	}

	// 8. Test unauthenticated client (no cert) rejected
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}
	_, err = unauthClient.Get(server.URL)
	if err == nil {
		t.Fatal("expected unauthenticated client without certificate to be rejected, but succeeded!")
	}
}
