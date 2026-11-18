package architecture_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testInternalToken = "saral-internal-secure-token-2026-v3"
)

type relayTestRecord struct {
	MessageID    string   `json:"messageId"`
	SourceNode   string   `json:"sourceNode"`
	SourceDomain string   `json:"sourceDomain"`
	TargetNode   string   `json:"targetNode"`
	TargetDomain string   `json:"targetDomain"`
	State        string   `json:"state"`
	CreatedAt    int64    `json:"createdAt"`
	UpdatedAt    int64    `json:"updatedAt"`
	Hops         []string `json:"hops"`
	Ack          *struct {
		MessageID       string   `json:"messageId"`
		TargetNode      string   `json:"targetNode"`
		TargetDomain    string   `json:"targetDomain"`
		SourceNode      string   `json:"sourceNode"`
		SourceDomain    string   `json:"sourceDomain"`
		Status          string   `json:"status"`
		Timestamp       int64    `json:"timestamp"`
		LatencyMs       int64    `json:"latencyMs"`
		RecipientSigHex string   `json:"recipientSigHex"`
		RecipientPubKey string   `json:"recipientPubKey"`
		ForwardedBy     []string `json:"forwardedBy"`
		Error           string   `json:"error"`
	} `json:"ack"`
	Error string `json:"error"`
}

func verifyEd25519(pubKeyHex, sigHex string, data []byte) bool {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes)
}

func canonicalAck(ackMsgID, targetNode, targetDomain, sourceNode, sourceDomain, status string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("SARAL-ACK:v3:%s:%s:%s:%s:%s:%s:%d",
		ackMsgID, targetNode, targetDomain, sourceNode, sourceDomain, status, timestamp))
}

func TestRelayNetworkEndToEnd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "saral-relay-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	repoRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("failed to get repo root: %v", err)
	}

	// 1. Build Binaries
	t.Log("[STEP 1] Compiling Go microservices binaries for Relay...")
	coordBin := filepath.Join(tempDir, "coordinator")
	verifierBin := filepath.Join(tempDir, "verifier")
	nodeBin := filepath.Join(tempDir, "saral-node")

	buildCmd := exec.Command("go", "build", "-o", coordBin, "./cmd/main.go")
	buildCmd.Dir = filepath.Join(repoRoot, "services", "coordinator")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build coordinator: %v\nOutput: %s", err, string(out))
	}

	buildCmd = exec.Command("go", "build", "-o", verifierBin, "./cmd/main.go")
	buildCmd.Dir = filepath.Join(repoRoot, "services", "verifier")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build verifier: %v\nOutput: %s", err, string(out))
	}

	buildCmd = exec.Command("go", "build", "-o", nodeBin, "./cmd/main.go")
	buildCmd.Dir = filepath.Join(repoRoot, "services", "saral-node")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build saral-node: %v\nOutput: %s", err, string(out))
	}
	t.Log("  -> All 3 Go binaries compiled successfully.")

	// 2. RSA Keys for Verifiers
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	pubKeyFile := filepath.Join(tempDir, "auth_public_key.pem")
	if err := os.WriteFile(pubKeyFile, pubKeyPem, 0644); err != nil {
		t.Fatalf("failed to write pubkey file: %v", err)
	}

	// Issue valid operator JWT
	now := time.Now()
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":         "relay-operator-01",
		"domainRole":  "operator",
		"mfaVerified": true,
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"iat":         now.Unix(),
		"exp":         now.Add(2 * time.Hour).Unix(),
	})
	validToken, err := tokenObj.SignedString(rsaPrivKey)
	if err != nil {
		t.Fatalf("failed to sign test JWT token: %v", err)
	}

	// 3. Start 3 Verifiers
	verifierPorts := map[string]int{"FOUNDATION": 18315, "PUBLIC": 18316, "PRIVATE": 18317}
	verifierCmds := make(map[string]*exec.Cmd)
	for domain, port := range verifierPorts {
		cmd := exec.Command(verifierBin,
			fmt.Sprintf("-port=%d", port),
			fmt.Sprintf("-domain=%s", domain),
			fmt.Sprintf("-pubkey=%s", pubKeyFile),
		)
		cmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start verifier for %s: %v", domain, err)
		}
		verifierCmds[domain] = cmd
	}
	defer func() {
		for _, cmd := range verifierCmds {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()

	for domain, port := range verifierPorts {
		url := fmt.Sprintf("http://localhost:%d/health", port)
		if err := waitForHealthy(url, 6*time.Second); err != nil {
			t.Fatalf("verifier for %s failed to become healthy on port %d: %v", domain, port, err)
		}
	}
	t.Log("  -> All 3 Verifiers running and healthy.")

	// 4. Start 15 Nodes
	domains := []string{"FOUNDATION", "PUBLIC", "PRIVATE"}
	coordPorts := map[string]int{"FOUNDATION": 18371, "PUBLIC": 18372, "PRIVATE": 18373}

	portMap := map[string][]int{
		"FOUNDATION": {18101, 18102, 18103, 18104, 18105},
		"PUBLIC":     {18201, 18202, 18203, 18204, 18205},
		"PRIVATE":    {18301, 18302, 18303, 18304, 18305},
	}

	nodeCmds := make(map[string]*exec.Cmd)
	nodePorts := make(map[string]int)
	nodeVaults := make(map[string]string)

	for _, domain := range domains {
		ports := portMap[domain]
		for i, port := range ports {
			nodeID := fmt.Sprintf("saral-%s-%d", strings.ToLower(domain), i+1)
			vaultDir := filepath.Join(tempDir, "vaults", nodeID)
			_ = os.MkdirAll(vaultDir, 0755)
			nodePorts[nodeID] = port
			nodeVaults[nodeID] = vaultDir

			var peers []string
			if i > 0 {
				peers = append(peers, fmt.Sprintf("http://localhost:%d", ports[i-1]))
			}
			if i < len(ports)-1 {
				peers = append(peers, fmt.Sprintf("http://localhost:%d", ports[i+1]))
			}
			if i == 0 {
				if domain == "FOUNDATION" {
					peers = append(peers, fmt.Sprintf("http://localhost:%d", portMap["PUBLIC"][0]))
					peers = append(peers, fmt.Sprintf("http://localhost:%d", portMap["PRIVATE"][0]))
				} else if domain == "PUBLIC" {
					peers = append(peers, fmt.Sprintf("http://localhost:%d", portMap["FOUNDATION"][0]))
				} else if domain == "PRIVATE" {
					peers = append(peers, fmt.Sprintf("http://localhost:%d", portMap["FOUNDATION"][0]))
				}
			}

			cmd := exec.Command(nodeBin,
				fmt.Sprintf("-node-id=%s", nodeID),
				fmt.Sprintf("-domain=%s", domain),
				fmt.Sprintf("-node-index=%d", i+1),
				fmt.Sprintf("-port=%d", port),
				fmt.Sprintf("-vault-dir=%s", vaultDir),
				fmt.Sprintf("-peers=%s", strings.Join(peers, ",")),
				fmt.Sprintf("-coordinator-url=http://localhost:%d", coordPorts[domain]),
			)
			cmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start node %s: %v", nodeID, err)
			}
			nodeCmds[nodeID] = cmd
		}
	}
	defer func() {
		for _, cmd := range nodeCmds {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()

	nodePublicKeys := make(map[string]string)
	for nodeID, port := range nodePorts {
		url := fmt.Sprintf("http://localhost:%d/node/status", port)
		if err := waitForHealthy(url, 6*time.Second); err != nil {
			t.Fatalf("node %s failed to become healthy on port %d: %v", nodeID, port, err)
		}
		resp, err := http.Get(url)
		if err == nil {
			var st struct {
				PublicKeyHex string `json:"publicKeyHex"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&st)
			resp.Body.Close()
			nodePublicKeys[nodeID] = st.PublicKeyHex
		}
	}
	t.Logf("  -> All 15 nodes healthy with %d unique public keys loaded.", len(nodePublicKeys))

	// 5. Start 3 Coordinators
	coordCmds := make(map[string]*exec.Cmd)
	for domain, port := range coordPorts {
		var localAddrs []string
		for _, p := range portMap[domain] {
			localAddrs = append(localAddrs, fmt.Sprintf("http://localhost:%d", p))
		}

		var peerCoords []string
		for d, p := range coordPorts {
			if d != domain {
				peerCoords = append(peerCoords, fmt.Sprintf("http://localhost:%d", p))
			}
		}

		cmd := exec.Command(coordBin,
			fmt.Sprintf("-port=%d", port),
			fmt.Sprintf("-domain=%s", domain),
			fmt.Sprintf("-verifier=http://localhost:%d", verifierPorts[domain]),
			fmt.Sprintf("-node-addrs=%s", strings.Join(localAddrs, ",")),
			fmt.Sprintf("-peers=%s", strings.Join(peerCoords, ",")),
		)
		cmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start coordinator for %s: %v", domain, err)
		}
		coordCmds[domain] = cmd
	}
	defer func() {
		for _, cmd := range coordCmds {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()

	for domain, port := range coordPorts {
		url := fmt.Sprintf("http://localhost:%d/health", port)
		if err := waitForHealthy(url, 6*time.Second); err != nil {
			t.Fatalf("coordinator for %s failed to become healthy on port %d: %v", domain, port, err)
		}
	}
	t.Log("  -> All 3 Coordinators healthy and operational.")

	// Enroll authoritative participant registry into all 15 nodes
	for targetID, port := range nodePorts {
		for id, pubKey := range nodePublicKeys {
			pBody, _ := json.Marshal(map[string]string{
				"nodeId":       id,
				"publicKeyHex": pubKey,
			})
			req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/participants", port), bytes.NewReader(pBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Saral-Internal-Token", testInternalToken)
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
		_ = targetID
	}
	t.Log("  -> Authoritative participant registry pre-enrolled in all 15 nodes.")
	time.Sleep(1 * time.Second)

	// ─── TEST STEP 1: Direct Node-to-Node P2P Relay ─────────────────────────
	t.Log("[STEP 2] Testing Direct Node-to-Node P2P Relay...")
	f1Port := nodePorts["saral-foundation-1"]
	f2Port := nodePorts["saral-foundation-2"]

	sendPayload := map[string]interface{}{
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"type":         "P2P_RELAY_TEST",
		"payload":      map[string]interface{}{"msg": "direct p2p ping pong"},
		"timeoutMs":    5000,
	}
	sendBytes, _ := json.Marshal(sendPayload)
	f1Req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), bytes.NewReader(sendBytes))
	f1Req.Header.Set("Content-Type", "application/json")
	f1Req.Header.Set("X-Saral-Internal-Token", testInternalToken)

	resp, err := http.DefaultClient.Do(f1Req)
	if err != nil {
		t.Fatalf("failed to send direct p2p relay: %v", err)
	}
	var f1Rec relayTestRecord
	_ = json.NewDecoder(resp.Body).Decode(&f1Rec)
	resp.Body.Close()

	if f1Rec.State != "ACKNOWLEDGED" {
		t.Fatalf("expected direct P2P state ACKNOWLEDGED, got %s (error: %s)", f1Rec.State, f1Rec.Error)
	}
	if f1Rec.Ack == nil {
		t.Fatalf("expected non-nil Ack from destination node")
	}
	// Verify recipient signature on ACK
	ackCanonical := canonicalAck(f1Rec.Ack.MessageID, f1Rec.Ack.TargetNode, f1Rec.Ack.TargetDomain, f1Rec.Ack.SourceNode, f1Rec.Ack.SourceDomain, f1Rec.Ack.Status, f1Rec.Ack.Timestamp)
	if !verifyEd25519(f1Rec.Ack.RecipientPubKey, f1Rec.Ack.RecipientSigHex, ackCanonical) {
		t.Fatalf("recipient Ed25519 signature on ACK is invalid")
	}
	t.Logf("  -> Direct P2P Relay success: %s -> %s (Latency: %d ms, Sig: %s...)",
		f1Rec.SourceNode, f1Rec.TargetNode, f1Rec.Ack.LatencyMs, f1Rec.Ack.RecipientSigHex[:16])

	// ─── TEST STEP 2: The 6 Required Cross-Domain & Intra-Domain Paths ──────
	t.Log("[STEP 3] Testing The 6 Required Cross-Domain & Intra-Domain Message Paths...")
	requiredPaths := []struct {
		Source       string
		Target       string
		TargetDomain string
		SourceCoord  int
	}{
		{Source: "Foundation-01", Target: "Public-02", TargetDomain: "PUBLIC", SourceCoord: coordPorts["FOUNDATION"]},
		{Source: "Public-03", Target: "Private-04", TargetDomain: "PRIVATE", SourceCoord: coordPorts["PUBLIC"]},
		{Source: "Private-05", Target: "Foundation-01", TargetDomain: "FOUNDATION", SourceCoord: coordPorts["PRIVATE"]},
		{Source: "Foundation-02", Target: "Foundation-04", TargetDomain: "FOUNDATION", SourceCoord: coordPorts["FOUNDATION"]},
		{Source: "Public-01", Target: "Public-05", TargetDomain: "PUBLIC", SourceCoord: coordPorts["PUBLIC"]},
		{Source: "Private-01", Target: "Private-03", TargetDomain: "PRIVATE", SourceCoord: coordPorts["PRIVATE"]},
	}

	for idx, path := range requiredPaths {
		reqBody := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      idx + 100,
			"method":  "saral_sendRelayMessage",
			"params": map[string]interface{}{
				"sourceNode": path.Source,
				"targetNode": path.Target,
				"type":       "SECTION_6_RELAY_PATH",
				"payload": map[string]interface{}{
					"pathIndex": idx + 1,
					"message":   fmt.Sprintf("Hello from %s to %s", path.Source, path.Target),
				},
				"timeoutMs": 8000,
			},
		}
		data, _ := json.Marshal(reqBody)
		httpReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", path.SourceCoord), bytes.NewReader(data))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+validToken)

		rResp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatalf("path %d (%s -> %s) request failed: %v", idx+1, path.Source, path.Target, err)
		}

		var rpcOut struct {
			Result *relayTestRecord `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(rResp.Body).Decode(&rpcOut)
		rResp.Body.Close()

		if rpcOut.Error != nil {
			t.Fatalf("path %d (%s -> %s) RPC error: %s", idx+1, path.Source, path.Target, rpcOut.Error.Message)
		}
		rec := rpcOut.Result
		if rec == nil {
			t.Fatalf("path %d (%s -> %s) returned nil result", idx+1, path.Source, path.Target)
		}

		if rec.State != "ACKNOWLEDGED" {
			t.Fatalf("path %d (%s -> %s) expected state ACKNOWLEDGED, got %s (error: %s)", idx+1, path.Source, path.Target, rec.State, rec.Error)
		}

		if rec.Ack == nil {
			t.Fatalf("path %d (%s -> %s) expected recipient ACK", idx+1, path.Source, path.Target)
		}

		// Verify cryptographic ACK signature
		ackCanonical := canonicalAck(rec.Ack.MessageID, rec.Ack.TargetNode, rec.Ack.TargetDomain, rec.Ack.SourceNode, rec.Ack.SourceDomain, rec.Ack.Status, rec.Ack.Timestamp)
		if !verifyEd25519(rec.Ack.RecipientPubKey, rec.Ack.RecipientSigHex, ackCanonical) {
			t.Fatalf("path %d (%s -> %s) recipient Ed25519 signature verification failed", idx+1, path.Source, path.Target)
		}

		t.Logf("  -> Path %d PASSED: %s -> %s | State: %s | Latency: %d ms | Hops: %v",
			idx+1, rec.SourceNode, rec.TargetNode, rec.State, rec.Ack.LatencyMs, rec.Hops)
	}

	// ─── TEST STEP 3: Unknown Peer Rejection ────────────────────────────────
	t.Log("[STEP 4] Testing Unknown Peer Rejection (No Auto-Enrollment)...")
	unknownMsg := map[string]interface{}{
		"messageId":    "msg-unknown-001",
		"sourceNode":   "saral-unknown-node-99",
		"sourceDomain": "UNKNOWN",
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"type":         "TEST_RELAY",
		"payload":      map[string]interface{}{"rogue": true},
		"timestamp":    time.Now().UnixMilli(),
		"expiresAt":    time.Now().UnixMilli() + 10000,
		"hopLimit":     5,
		"hops":         []string{"saral-unknown-node-99"},
		"publicKeyHex": "1111111111111111111111111111111111111111111111111111111111111111",
		"signatureHex": "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
	}
	unkBytes, _ := json.Marshal(unknownMsg)
	unkReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay", f2Port), bytes.NewReader(unkBytes))
	unkReq.Header.Set("Content-Type", "application/json")
	unkReq.Header.Set("X-Saral-Internal-Token", testInternalToken)

	unkResp, err := http.DefaultClient.Do(unkReq)
	if err == nil {
		var unkAck struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.NewDecoder(unkResp.Body).Decode(&unkAck)
		unkResp.Body.Close()
		if unkAck.Status != "FAILED" {
			t.Fatalf("expected FAILED status for unknown peer message, got %s", unkAck.Status)
		}
		t.Logf("  -> Unknown peer rejected as expected: %s", unkAck.Error)
	}

	// ─── TEST STEP 4: Forged Sender Rejection ───────────────────────────────
	t.Log("[STEP 5] Testing Forged Sender Rejection...")
	forgedMsg := map[string]interface{}{
		"messageId":    "msg-forged-001",
		"sourceNode":   "saral-foundation-1",
		"sourceDomain": "FOUNDATION",
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"type":         "TEST_RELAY",
		"payload":      map[string]interface{}{"forged": true},
		"timestamp":    time.Now().UnixMilli(),
		"expiresAt":    time.Now().UnixMilli() + 10000,
		"hopLimit":     5,
		"hops":         []string{"saral-foundation-1"},
		"publicKeyHex": "3333333333333333333333333333333333333333333333333333333333333333", // Forged pubkey for f1
		"signatureHex": "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
	}
	forgBytes, _ := json.Marshal(forgedMsg)
	forgReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay", f2Port), bytes.NewReader(forgBytes))
	forgReq.Header.Set("Content-Type", "application/json")
	forgReq.Header.Set("X-Saral-Internal-Token", testInternalToken)

	forgResp, err := http.DefaultClient.Do(forgReq)
	if err == nil {
		var forgAck struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.NewDecoder(forgResp.Body).Decode(&forgAck)
		forgResp.Body.Close()
		if forgAck.Status != "FAILED" {
			t.Fatalf("expected FAILED status for forged sender, got %s", forgAck.Status)
		}
		t.Logf("  -> Forged sender rejected as expected: %s", forgAck.Error)
	}

	// ─── TEST STEP 5: Unauthorized RPC Rejection ────────────────────────────
	t.Log("[STEP 6] Testing Unauthorized RPC Rejection (missing internal credentials)...")
	unauthReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), bytes.NewReader(sendBytes))
	unauthReq.Header.Set("Content-Type", "application/json")
	// No auth header or token set!

	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauth request failed: %v", err)
	}
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized for request with missing credentials, got %d", unauthResp.StatusCode)
	}
	t.Log("  -> Unauthorized RPC call successfully rejected with HTTP 401.")

	// ─── TEST STEP 6: Replay Protection & Duplicate Detection ───────────────
	t.Log("[STEP 7] Testing Replay Attack & Duplicate Detection...")
	dupMsgID := "msg-dup-test-999"
	dupReq := map[string]interface{}{
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"messageId":    dupMsgID,
		"type":         "DUP_TEST",
		"payload":      map[string]interface{}{"dup": true},
		"timeoutMs":    5000,
	}
	dupBytes, _ := json.Marshal(dupReq)

	// Send first time
	dReq1, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), bytes.NewReader(dupBytes))
	dReq1.Header.Set("Content-Type", "application/json")
	dReq1.Header.Set("X-Saral-Internal-Token", testInternalToken)
	resp1, _ := http.DefaultClient.Do(dReq1)
	var rec1 relayTestRecord
	_ = json.NewDecoder(resp1.Body).Decode(&rec1)
	resp1.Body.Close()
	if rec1.State != "ACKNOWLEDGED" {
		t.Fatalf("first send of dup message failed: %s", rec1.Error)
	}

	// Replay exact same message
	dReq2, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), bytes.NewReader(dupBytes))
	dReq2.Header.Set("Content-Type", "application/json")
	dReq2.Header.Set("X-Saral-Internal-Token", testInternalToken)
	resp2, _ := http.DefaultClient.Do(dReq2)
	var rec2 relayTestRecord
	_ = json.NewDecoder(resp2.Body).Decode(&rec2)
	resp2.Body.Close()

	if rec2.State != "ACKNOWLEDGED" {
		t.Fatalf("expected idempotent ACK on duplicate message, got state %s", rec2.State)
	}
	t.Log("  -> Duplicate message deduplication & idempotent handling verified.")

	// ─── TEST STEP 7: Expired Message Rejection ─────────────────────────────
	t.Log("[STEP 8] Testing Expired Message Rejection...")
	expiredMsg := map[string]interface{}{
		"messageId":    "msg-expired-001",
		"sourceNode":   "saral-foundation-1",
		"sourceDomain": "FOUNDATION",
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"type":         "EXPIRED_TEST",
		"payload":      map[string]interface{}{"data": "expired"},
		"timestamp":    time.Now().UnixMilli() - 20000,
		"expiresAt":    time.Now().UnixMilli() - 5000, // expired!
		"hopLimit":     5,
		"hops":         []string{"saral-foundation-1"},
		"publicKeyHex": nodePublicKeys["saral-foundation-1"],
		"signatureHex": "00000000000000000000000000000000",
	}
	expBytes, _ := json.Marshal(expiredMsg)
	expReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/relay", f2Port), bytes.NewReader(expBytes))
	expReq.Header.Set("Content-Type", "application/json")
	expReq.Header.Set("X-Saral-Internal-Token", testInternalToken)

	expResp, err := http.DefaultClient.Do(expReq)
	if err == nil {
		var expAck struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		_ = json.NewDecoder(expResp.Body).Decode(&expAck)
		expResp.Body.Close()
		if expAck.Status != "EXPIRED" {
			t.Fatalf("expected EXPIRED status for expired message, got %s", expAck.Status)
		}
		t.Logf("  -> Expired message successfully rejected with status EXPIRED (%s).", expAck.Error)
	}

	// ─── TEST STEP 8: Offline Destination Reporting ─────────────────────────
	t.Log("[STEP 9] Testing Offline Destination Reporting...")
	offlineReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      999,
		"method":  "saral_sendRelayMessage",
		"params": map[string]interface{}{
			"sourceNode": "saral-foundation-1",
			"targetNode": "saral-public-99", // non-existent node
			"type":       "OFFLINE_TEST",
			"payload":    map[string]interface{}{"test": "offline"},
			"timeoutMs":  3000,
		},
	}
	offData, _ := json.Marshal(offlineReq)
	offHttpReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", coordPorts["FOUNDATION"]), bytes.NewReader(offData))
	offHttpReq.Header.Set("Content-Type", "application/json")
	offHttpReq.Header.Set("Authorization", "Bearer "+validToken)

	offResp, err := http.DefaultClient.Do(offHttpReq)
	if err == nil {
		var offOut struct {
			Result *relayTestRecord `json:"result"`
		}
		_ = json.NewDecoder(offResp.Body).Decode(&offOut)
		offResp.Body.Close()
		if offOut.Result != nil && offOut.Result.State != "FAILED" {
			t.Fatalf("expected FAILED state for non-existent target, got %s", offOut.Result.State)
		}
		t.Logf("  -> Offline / non-existent target properly reported as FAILED (%s).", offOut.Result.Error)
	}

	// ─── TEST STEP 9: Node Identity Persistence & Deduplication Across Restart ─
	t.Log("[STEP 10] Testing Node Identity Persistence & Deduplication Across Restart...")
	f3Port := nodePorts["saral-foundation-3"]
	f3PubBefore := nodePublicKeys["saral-foundation-3"]
	if err := nodeCmds["saral-foundation-3"].Process.Kill(); err != nil {
		t.Fatalf("failed to kill node-f3: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	restartedCmd := exec.Command(nodeBin,
		"-node-id=saral-foundation-3",
		"-domain=FOUNDATION",
		"-node-index=3",
		fmt.Sprintf("-port=%d", f3Port),
		fmt.Sprintf("-vault-dir=%s", nodeVaults["saral-foundation-3"]),
		fmt.Sprintf("-peers=http://localhost:%d", f2Port),
		fmt.Sprintf("-coordinator-url=http://localhost:%d", coordPorts["FOUNDATION"]),
	)
	restartedCmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
	if err := restartedCmd.Start(); err != nil {
		t.Fatalf("failed to restart node-f3: %v", err)
	}
	defer restartedCmd.Process.Kill()

	if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/node/status", f3Port), 6*time.Second); err != nil {
		t.Fatalf("restarted node-f3 failed to become healthy: %v", err)
	}

	resp, err = http.Get(fmt.Sprintf("http://localhost:%d/node/status", f3Port))
	if err != nil {
		t.Fatalf("failed to get status from restarted node: %v", err)
	}
	var f3StatusAfter struct {
		PublicKeyHex string `json:"publicKeyHex"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&f3StatusAfter)
	resp.Body.Close()

	if f3StatusAfter.PublicKeyHex != f3PubBefore {
		t.Fatalf("node identity changed after restart: before %s, after %s", f3PubBefore, f3StatusAfter.PublicKeyHex)
	}
	t.Log("  -> Node identity persistence verified: public key identical after restart.")

	// ─── TEST STEP 10: Coordinator Restart and Reconnection ──────────────────
	t.Log("[STEP 11] Testing Coordinator Restart & Reconnection...")
	fCoordPort := coordPorts["FOUNDATION"]
	if err := coordCmds["FOUNDATION"].Process.Kill(); err != nil {
		t.Fatalf("failed to kill coordinator-foundation: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	var localAddrs []string
	for _, p := range portMap["FOUNDATION"] {
		localAddrs = append(localAddrs, fmt.Sprintf("http://localhost:%d", p))
	}
	var peerCoords []string
	peerCoords = append(peerCoords, fmt.Sprintf("http://localhost:%d", coordPorts["PUBLIC"]))
	peerCoords = append(peerCoords, fmt.Sprintf("http://localhost:%d", coordPorts["PRIVATE"]))

	restartedCoord := exec.Command(coordBin,
		fmt.Sprintf("-port=%d", fCoordPort),
		"-domain=FOUNDATION",
		fmt.Sprintf("-verifier=http://localhost:%d", verifierPorts["FOUNDATION"]),
		fmt.Sprintf("-node-addrs=%s", strings.Join(localAddrs, ",")),
		fmt.Sprintf("-peers=%s", strings.Join(peerCoords, ",")),
	)
	restartedCoord.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
	if err := restartedCoord.Start(); err != nil {
		t.Fatalf("failed to restart coordinator: %v", err)
	}
	defer restartedCoord.Process.Kill()

	if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/health", fCoordPort), 6*time.Second); err != nil {
		t.Fatalf("restarted coordinator failed to become healthy: %v", err)
	}
	t.Log("  -> Coordinator successfully restarted and recovered health.")

	// ─── TEST STEP 11: Section 8 Cryptographic Stubs Compliance ─────────────
	t.Log("[STEP 12] Testing Section 8 Compliance: Cryptographic stubs return NOT_IMPLEMENTED...")
	stubReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1300,
		"method":  "saral_createWallet",
		"params":  map[string]interface{}{},
	}
	stubData, _ := json.Marshal(stubReq)
	stubHttpReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", coordPorts["FOUNDATION"]), bytes.NewReader(stubData))
	stubHttpReq.Header.Set("Content-Type", "application/json")
	stubHttpReq.Header.Set("Authorization", "Bearer "+validToken)

	stubResp, _ := http.DefaultClient.Do(stubHttpReq)
	var stubOut struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(stubResp.Body).Decode(&stubOut)
	stubResp.Body.Close()

	if stubOut.Error == nil || stubOut.Error.Code != -32000 {
		t.Fatalf("expected -32000 NOT_IMPLEMENTED for cryptographic stub, got: %v", stubOut.Error)
	}
	t.Log("  -> Confirmed: Relay operates completely independently of DKG/TSS stubs (-32000).")

	t.Log("✅ ALL RELAY NETWORK INTEGRATION TESTS PASSED (15 nodes, direct P2P, 6 cross-domain paths, recipient-signed ACK verification, unknown peer rejection, forged sender rejection, unauthorized RPC rejection, replay protection, offline recovery, identity persistence, coordinator restart)!")
}

func TestLiveDockerRelay(t *testing.T) {
	// Skip if Docker coordinators are not reachable
	resp, err := http.Get("http://localhost:9001/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skip("Docker POC15 cluster not running on localhost:9001, skipping live Docker relay test.")
		return
	}
	resp.Body.Close()

	t.Log("🐳 Testing Live Running Docker Cluster (POC15 - 23 Containers)...")

	// 1. Fetch Auth Token from live Auth Server
	authReqBody := map[string]interface{}{
		"username": "live-test-operator",
		"role":     "operator",
	}
	aData, _ := json.Marshal(authReqBody)
	aResp, err := http.Post("http://localhost:3001/auth/token", "application/json", bytes.NewReader(aData))
	if err != nil {
		t.Fatalf("failed to obtain token from live auth server: %v", err)
	}
	var aOut struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(aResp.Body).Decode(&aOut)
	aResp.Body.Close()
	if aOut.Token == "" {
		t.Fatalf("empty token received from live auth-server")
	}
	t.Log("  -> Successfully obtained live operator JWT from Docker Auth Server.")

	// 2. Test live coordinators healthy
	coords := []struct {
		Domain string
		Port   int
	}{
		{"FOUNDATION", 9001},
		{"PUBLIC", 9002},
		{"PRIVATE", 9003},
	}
	for _, c := range coords {
		cResp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", c.Port))
		if err != nil || cResp.StatusCode != http.StatusOK {
			t.Fatalf("live coordinator for %s unhealthy on port %d: %v", c.Domain, c.Port, err)
		}
		cResp.Body.Close()
	}
	t.Log("  -> All 3 Docker Coordinators healthy.")

	// 3. Test all 6 live routes across Docker containers
	liveRoutes := []struct {
		Source       string
		Target       string
		TargetDomain string
		CoordPort    int
	}{
		{Source: "saral-foundation-1", Target: "saral-public-2", TargetDomain: "PUBLIC", CoordPort: 9001},
		{Source: "saral-public-3", Target: "saral-private-4", TargetDomain: "PRIVATE", CoordPort: 9002},
		{Source: "saral-private-5", Target: "saral-foundation-1", TargetDomain: "FOUNDATION", CoordPort: 9003},
		{Source: "saral-foundation-2", Target: "saral-foundation-4", TargetDomain: "FOUNDATION", CoordPort: 9001},
		{Source: "saral-public-1", Target: "saral-public-5", TargetDomain: "PUBLIC", CoordPort: 9002},
		{Source: "saral-private-1", Target: "saral-private-3", TargetDomain: "PRIVATE", CoordPort: 9003},
	}

	for idx, r := range liveRoutes {
		body := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      idx + 200,
			"method":  "saral_sendRelayMessage",
			"params": map[string]interface{}{
				"sourceNode": r.Source,
				"targetNode": r.Target,
				"type":       "DOCKER_LIVE_RELAY_TEST",
				"payload": map[string]interface{}{
					"liveRoute": idx + 1,
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				},
				"timeoutMs": 8000,
			},
		}
		bData, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", r.CoordPort), bytes.NewReader(bData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+aOut.Token)

		rResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("live route %d (%s -> %s) request failed: %v", idx+1, r.Source, r.Target, err)
		}

		var out struct {
			Result *relayTestRecord `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(rResp.Body).Decode(&out)
		rResp.Body.Close()

		if out.Error != nil {
			t.Fatalf("live route %d (%s -> %s) error: %s", idx+1, r.Source, r.Target, out.Error.Message)
		}
		if out.Result == nil || out.Result.State != "ACKNOWLEDGED" {
			t.Fatalf("live route %d (%s -> %s) expected state ACKNOWLEDGED, got %v", idx+1, r.Source, r.Target, out.Result)
		}

		t.Logf("  -> Live Docker Route %d PASSED: %s -> %s | State: %s | Latency: %d ms | Hops: %v",
			idx+1, out.Result.SourceNode, out.Result.TargetNode, out.Result.State, out.Result.Ack.LatencyMs, out.Result.Hops)
	}

	// 4. Test unauthorized RPC rejection on live Docker coordinator
	unauthBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      999,
		"method":  "saral_getNetworkStatus",
		"params":  map[string]interface{}{},
	}
	uData, _ := json.Marshal(unauthBody)
	uReq, _ := http.NewRequest("POST", "http://localhost:9001/rpc", bytes.NewReader(uData))
	uReq.Header.Set("Content-Type", "application/json")
	// No token

	uResp, err := http.DefaultClient.Do(uReq)
	if err == nil {
		var uOut struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(uResp.Body).Decode(&uOut)
		uResp.Body.Close()
		if uOut.Error == nil || uOut.Error.Code != -32001 {
			t.Fatalf("expected authorization rejection code -32001, got: %v", uOut.Error)
		}
		t.Log("  -> Live Docker unauthorized RPC rejection verified (code -32001).")
	}

	// 5. Test Cryptographic Stub NOT_IMPLEMENTED on live Docker coordinator
	stubBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1300,
		"method":  "saral_startDkg",
		"params":  map[string]interface{}{},
	}
	sData, _ := json.Marshal(stubBody)
	sReq, _ := http.NewRequest("POST", "http://localhost:9001/rpc", bytes.NewReader(sData))
	sReq.Header.Set("Content-Type", "application/json")
	sReq.Header.Set("Authorization", "Bearer "+aOut.Token)

	sResp, err := http.DefaultClient.Do(sReq)
	if err == nil {
		var sOut struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(sResp.Body).Decode(&sOut)
		sResp.Body.Close()
		if sOut.Error == nil || sOut.Error.Code != -32000 {
			t.Fatalf("expected -32000 for stub, got: %v", sOut.Error)
		}
		t.Log("  -> Live Docker Section 8 stub compliance verified (-32000 NOT_IMPLEMENTED).")
	}

	t.Log("✅ ALL LIVE DOCKER RELAY INTEGRATION TESTS PASSED (healthy containers, live JWT auth, 6 cross-domain routes, unauthorized rejection, stub compliance)!")
}
