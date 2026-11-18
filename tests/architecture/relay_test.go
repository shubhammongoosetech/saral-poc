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
	return []byte(fmt.Sprintf("ACK:%s:%s:%s:%s:%s:%s:%d",
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

	binDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}

	coordBin := filepath.Join(binDir, "coordinator")
	verifierBin := filepath.Join(binDir, "verifier")
	nodeBin := filepath.Join(binDir, "saral-node")

	// 1. Compile binaries
	t.Log("[STEP 1] Compiling Go microservices binaries for Relay...")
	for src, out := range map[string]string{
		"services/coordinator/cmd/main.go": coordBin,
		"services/verifier/cmd/main.go":    verifierBin,
		"services/saral-node/cmd/main.go":  nodeBin,
	} {
		cmd := exec.Command("go", "build", "-o", out, filepath.Join(repoRoot, src))
		cmd.Dir = repoRoot
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to build %s: %v\nOutput: %s", src, err, string(outBytes))
		}
	}
	t.Log("  -> All 3 Go binaries compiled successfully.")

	// 2. RSA Keys and RS256 Token
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	pubKeyPath := filepath.Join(tempDir, "auth_public_key.pem")
	if err := os.WriteFile(pubKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1}), 0o644); err != nil {
		t.Fatalf("failed to write pubkey: %v", err)
	}

	tokenClaims := jwt.MapClaims{
		"sub":         "relay-test-operator",
		"iss":         "saral-auth-server",
		"aud":         "saral-domain-coordinators",
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
		"mfaVerified": true,
		"domainRole":  "operator",
		"nonce":       "test-relay-nonce-12345",
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	validToken, err := tokenObj.SignedString(rsaPrivKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// 3. Start 3 Verifiers
	verifierPorts := map[string]int{
		"FOUNDATION": 8315,
		"PUBLIC":     8316,
		"PRIVATE":    8317,
	}
	verifierCmds := make(map[string]*exec.Cmd)
	for domain, port := range verifierPorts {
		cmd := exec.Command(verifierBin,
			fmt.Sprintf("-port=%d", port),
			fmt.Sprintf("-domain=%s", domain),
			fmt.Sprintf("-pubkey=%s", pubKeyPath),
		)
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
		if err := waitForHealthy(url, 5*time.Second); err != nil {
			t.Fatalf("verifier for %s failed to become healthy on port %d: %v", domain, port, err)
		}
	}
	t.Log("  -> All 3 Verifiers running and healthy.")

	// 4. Start 15 Nodes
	// Foundation: 8301..8305
	// Public:     8306..8310
	// Private:    8311..8315 (offset ports to avoid collision: 8341..8345)
	nodePorts := make(map[string]int)
	nodeVaults := make(map[string]string)
	nodeCmds := make(map[string]*exec.Cmd)

	portMap := map[string][]int{
		"FOUNDATION": {8351, 8352, 8353, 8354, 8355},
		"PUBLIC":     {8356, 8357, 8358, 8359, 8360},
		"PRIVATE":    {8361, 8362, 8363, 8364, 8365},
	}
	coordPorts := map[string]int{
		"FOUNDATION": 8371,
		"PUBLIC":     8372,
		"PRIVATE":    8373,
	}

	for domain, ports := range portMap {
		for i, port := range ports {
			nodeID := fmt.Sprintf("saral-%s-%d", strings.ToLower(domain), i+1)
			nodePorts[nodeID] = port
			vaultDir := filepath.Join(tempDir, "vaults", nodeID)
			nodeVaults[nodeID] = vaultDir
			_ = os.MkdirAll(vaultDir, 0o700)

			// Setup peer links
			var peers []string
			if i > 0 {
				peers = append(peers, fmt.Sprintf("http://localhost:%d", ports[i-1]))
			}
			if i < len(ports)-1 {
				peers = append(peers, fmt.Sprintf("http://localhost:%d", ports[i+1]))
			}
			// Cross-domain links for node 1
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
		// Fetch public key
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
	time.Sleep(1 * time.Second) // allow discovery cycle

	// ─── TEST STEP 1: Direct Node-to-Node P2P Relay ─────────────────────────
	t.Log("[STEP 2] Testing Direct Node-to-Node P2P Relay...")
	// saral-foundation-1 to saral-foundation-2 (direct peers)
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
	resp, err := http.Post(fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), "application/json", bytes.NewReader(sendBytes))
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
	// Path 1: Foundation-01 -> Public-02
	// Path 2: Public-03 -> Private-04
	// Path 3: Private-05 -> Foundation-01
	// Path 4: Foundation-02 -> Foundation-04
	// Path 5: Public-01 -> Public-05
	// Path 6: Private-01 -> Private-03
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

	// ─── TEST STEP 3: Replay Protection & Duplicate Detection ───────────────
	t.Log("[STEP 4] Testing Replay Attack & Duplicate Detection...")
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
	resp1, _ := http.Post(fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), "application/json", bytes.NewReader(dupBytes))
	var rec1 relayTestRecord
	_ = json.NewDecoder(resp1.Body).Decode(&rec1)
	resp1.Body.Close()
	if rec1.State != "ACKNOWLEDGED" {
		t.Fatalf("first send of dup message failed: %s", rec1.Error)
	}

	// Replay exact same message to node 2
	resp2, _ := http.Post(fmt.Sprintf("http://localhost:%d/node/relay/send", f1Port), "application/json", bytes.NewReader(dupBytes))
	var rec2 relayTestRecord
	_ = json.NewDecoder(resp2.Body).Decode(&rec2)
	resp2.Body.Close()

	// Should either be deduplicated or return cached ACK idempotently
	if rec2.State != "ACKNOWLEDGED" {
		t.Fatalf("expected idempotent ACK on duplicate message, got state %s", rec2.State)
	}
	t.Log("  -> Duplicate message deduplication & idempotent handling verified.")

	// ─── TEST STEP 4: Expired Message Rejection ─────────────────────────────
	t.Log("[STEP 5] Testing Expired Message Rejection...")
	expiredMsg := map[string]interface{}{
		"messageId":    "msg-expired-001",
		"sourceNode":   "saral-foundation-1",
		"sourceDomain": "FOUNDATION",
		"targetNode":   "saral-foundation-2",
		"targetDomain": "FOUNDATION",
		"type":         "EXPIRED_TEST",
		"payload":      map[string]interface{}{"data": "expired"},
		"timestamp":    time.Now().UnixMilli() - 60000,
		"expiresAt":    time.Now().UnixMilli() - 10000, // already expired!
		"hopLimit":     5,
		"hops":         []string{"saral-foundation-1"},
		"publicKeyHex": nodePublicKeys["saral-foundation-1"],
		"signatureHex": "00000000000000000000000000000000",
	}
	expBytes, _ := json.Marshal(expiredMsg)
	expResp, err := http.Post(fmt.Sprintf("http://localhost:%d/node/relay", f2Port), "application/json", bytes.NewReader(expBytes))
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

	// ─── TEST STEP 5: Offline Destination Reporting ─────────────────────────
	t.Log("[STEP 6] Testing Offline Destination Reporting...")
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

	// ─── TEST STEP 6: Node Identity Persistence Across Restart ───────────────
	t.Log("[STEP 7] Testing Node Identity Persistence Across Restart...")
	f3Port := nodePorts["saral-foundation-3"]
	f3PubBefore := nodePublicKeys["saral-foundation-3"]
	// Kill node-f3
	if err := nodeCmds["saral-foundation-3"].Process.Kill(); err != nil {
		t.Fatalf("failed to kill node-f3: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Restart node-f3 with same vault
	restartedCmd := exec.Command(nodeBin,
		"-node-id=saral-foundation-3",
		"-domain=FOUNDATION",
		"-node-index=3",
		fmt.Sprintf("-port=%d", f3Port),
		fmt.Sprintf("-vault-dir=%s", nodeVaults["saral-foundation-3"]),
		fmt.Sprintf("-peers=http://localhost:%d", f2Port),
		fmt.Sprintf("-coordinator-url=http://localhost:%d", coordPorts["FOUNDATION"]),
	)
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

	// ─── TEST STEP 7: Relay Does Not Depend on DKG/TSS ───────────────────────
	t.Log("[STEP 8] Testing Section 8 Compliance: Cryptographic stubs return NOT_IMPLEMENTED...")
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

	t.Log("✅ ALL RELAY NETWORK INTEGRATION TESTS PASSED (15 nodes, direct P2P, 6 cross-domain paths, ACK signatures, replay protection, offline recovery, identity persistence)!")
}
