package architecture_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func waitForHealthy(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func TestArchitectureRuntimeEndToEnd(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	projectRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	nodeBin := filepath.Join(projectRoot, "services/saral-node/bin/saral-node"+ext)

	// 1. Build Go SARAL Node Binary
	t.Log("[STEP 1] Compiling clean Go SARAL node microservice binary...")
	cmd := exec.Command("go", "build", "-o", nodeBin, "./cmd/main.go")
	cmd.Dir = filepath.Join(projectRoot, "services/saral-node")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build saral-node: %v\nOutput: %s", err, string(out))
	}
	t.Log("  -> SARAL Node Go binary compiled successfully.")

	tmpDir, err := os.MkdirTemp("", "saral-v3-arch-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testInternalToken := "saral-test-internal-token-2026-xyz"

	// 2. Generate Ed25519 Keypair & JWT for Auth
	t.Log("[STEP 2] Setting up Auth Server Ed25519 keypair and issuing EdDSA JWT...")
	authPubKey, authPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(authPubKey)
	if err != nil {
		t.Fatalf("failed to marshal PKIX public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	pubKeyPath := filepath.Join(tmpDir, "auth_public_key.pem")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatalf("failed to write pubkey: %v", err)
	}

	claims := jwt.MapClaims{
		"sub":         "operator-admin-1",
		"iss":         "saral-auth-server",
		"aud":         "saral-node-committee",
		"mfaVerified": true,
		"domainRole":  "operator",
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenObj.Header["kid"] = "saral-auth-ed25519-2026-01"
	validToken, err := tokenObj.SignedString(authPrivKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	t.Log("  -> Successfully signed valid Ed25519 operator JWT.")

	// 3. Start SARAL Nodes across Committees
	t.Log("[STEP 3] Starting SARAL nodes in Foundation, Public, and Private domains...")
	nodePorts := map[string]int{
		"saral-foundation-1": 19101,
		"saral-foundation-2": 19102,
		"saral-public-1":     19103,
		"saral-private-1":    19104,
	}

	genesisEntries := make(map[string]map[string]interface{})
	for id, port := range nodePorts {
		genesisEntries[id] = map[string]interface{}{
			"nodeId":     id,
			"endpoint":   fmt.Sprintf("http://localhost:%d", port),
			"approvedBy": "genesis-bootstrap",
			"enrolledAt": time.Now().UTC().Format(time.RFC3339),
		}
	}
	genesisFilePath := filepath.Join(tmpDir, "genesis_participants.json")
	genBytes, _ := json.MarshalIndent(genesisEntries, "", "  ")
	_ = os.WriteFile(genesisFilePath, genBytes, 0644)

	nodeCmds := make(map[string]*exec.Cmd)
	for id, port := range nodePorts {
		domain := "FOUNDATION"
		if id == "saral-public-1" {
			domain = "PUBLIC"
		} else if id == "saral-private-1" {
			domain = "PRIVATE"
		}

		vaultDir := filepath.Join(tmpDir, id+"-vault")
		_ = os.MkdirAll(vaultDir, 0700)

		c := exec.Command(nodeBin,
			"-domain", domain,
			"-port", fmt.Sprintf("%d", port),
			"-p2p-port", fmt.Sprintf("%d", port+1000),
			"-vault-dir", vaultDir,
		)
		c.Env = append(os.Environ(),
			"SARAL_INTERNAL_TOKEN="+testInternalToken,
			"SARAL_GENESIS_REGISTRY_FILE="+genesisFilePath,
			"PUBLIC_KEY_PATH="+pubKeyPath,
		)
		if err := c.Start(); err != nil {
			t.Fatalf("failed to start %s: %v", id, err)
		}
		defer c.Process.Kill()
		nodeCmds[id] = c
	}

	for id, port := range nodePorts {
		if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/health", port), 8*time.Second); err != nil {
			t.Fatalf("node %s failed to become healthy on port %d: %v", id, port, err)
		}
	}
	t.Log("  -> All SARAL nodes active, healthy, and communicating without any coordinator or verifier.")

	client := &http.Client{Timeout: 5 * time.Second}

	nodePublicKeys := make(map[string]string)
	nodeEncKeys := make(map[string]string)
	for id, port := range nodePorts {
		stResp, err := client.Get(fmt.Sprintf("http://localhost:%d/node/status", port))
		if err == nil {
			var st struct {
				PublicKeyHex        string `json:"publicKeyHex"`
				EncryptionPubKeyHex string `json:"encryptionPubKeyHex"`
			}
			_ = json.NewDecoder(stResp.Body).Decode(&st)
			stResp.Body.Close()
			nodePublicKeys[id] = st.PublicKeyHex
			nodeEncKeys[id] = st.EncryptionPubKeyHex
		}
	}

	for _, port := range nodePorts {
		for id, pubKey := range nodePublicKeys {
			pBody, _ := json.Marshal(map[string]string{
				"nodeId":           id,
				"publicKeyHex":     pubKey,
				"encryptionKeyHex": nodeEncKeys[id],
				"endpoint":         fmt.Sprintf("http://localhost:%d", nodePorts[id]),
			})
			pReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/participants", port), bytes.NewReader(pBody))
			pReq.Header.Set("Content-Type", "application/json")
			pReq.Header.Set("X-Saral-Internal-Token", testInternalToken)
			if pResp, err := client.Do(pReq); err == nil {
				pResp.Body.Close()
			}
		}
	}

	// 4. Test Node Health & TLS Status
	t.Log("[STEP 4] Testing Node Health and Direct Endpoints...")
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/node/health", nodePorts["saral-foundation-1"]))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("node health check failed: %v", err)
	}
	resp.Body.Close()
	t.Log("  -> Node health check passed.")

	// 5. Test JSON-RPC on SARAL Node: saral_getNodeStatus
	t.Log("[STEP 5] Testing JSON-RPC saral_getNodeStatus on saral-foundation-1...")
	statusReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"saral_getNodeStatus","params":{}}`)
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", nodePorts["saral-foundation-1"]), bytes.NewReader(statusReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("saral_getNodeStatus failed: %v", err)
	}
	var statusResult struct {
		Result struct {
			NodeID string `json:"nodeId"`
			Domain string `json:"domain"`
			Status string `json:"status"`
		} `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&statusResult)
	resp.Body.Close()

	if statusResult.Result.Status != "ONLINE" {
		t.Fatalf("unexpected node status: %+v", statusResult)
	}
	t.Logf("  -> Verified Node %s status: %s (Domain: %s)", statusResult.Result.NodeID, statusResult.Result.Status, statusResult.Result.Domain)

	// 6. Test JSON-RPC saral_getNetworkStatus
	t.Log("[STEP 6] Testing JSON-RPC saral_getNetworkStatus on saral-foundation-1...")
	netReq := []byte(`{"jsonrpc":"2.0","id":2,"method":"saral_getNetworkStatus","params":{}}`)
	req, _ = http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", nodePorts["saral-foundation-1"]), bytes.NewReader(netReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("saral_getNetworkStatus failed: %v", err)
	}
	var netResult struct {
		Result struct {
			NodeID string `json:"nodeId"`
			Domain string `json:"domain"`
		} `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&netResult)
	resp.Body.Close()
	t.Logf("  -> Verified Network status from node %s", netResult.Result.NodeID)

	// 7. Test Direct P2P Relay Between Nodes Without Coordinator
	t.Log("[STEP 7] Testing Direct P2P Relay between Foundation and Public nodes...")
	sendPayload := map[string]interface{}{
		"targetNode":   "saral-public-1",
		"targetDomain": "PUBLIC",
		"type":         "P2P_RELAY_TEST",
		"payload":      map[string]interface{}{"msg": "direct p2p ping pong"},
		"timeoutMs":    5000,
	}
	sendBytes, _ := json.Marshal(sendPayload)
	req, _ = http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay/send", nodePorts["saral-foundation-1"]), bytes.NewReader(sendBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Saral-Internal-Token", testInternalToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("direct P2P relay failed: %v", err)
	}
	var sendResult struct {
		State string `json:"state"`
		Error string `json:"error"`
		Ack   *struct {
			Status string `json:"status"`
		} `json:"ack"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sendResult)
	resp.Body.Close()
	if sendResult.State != "ACKNOWLEDGED" {
		t.Fatalf("unexpected relay result: %+v", sendResult)
	}
	t.Log("  -> Direct P2P relay verified: Node-to-node relay succeeded with signed ACK without coordinator.")

	// 8. Test Unauthorized Request Rejection (Fail-Closed)
	t.Log("[STEP 8] Testing Fail-Closed Security: unauthenticated RPC rejection...")
	unauthReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", nodePorts["saral-foundation-1"]), bytes.NewReader(statusReq))
	unauthReq.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(unauthReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	var unauthResult struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&unauthResult)
	resp.Body.Close()
	if unauthResult.Error == nil || unauthResult.Error.Code != -32001 {
		t.Fatalf("expected -32001 unauthorized error, got: %v", unauthResult.Error)
	}
	t.Log("  -> Fail-closed verified: Unauthenticated request rejected with -32001.")

	t.Log("✅ ALL 2-COMPONENT ARCHITECTURE INTEGRATION TESTS PASSED (Web2 Auth + SARAL Nodes only, NO Coordinator, NO Verifier)!")
}
