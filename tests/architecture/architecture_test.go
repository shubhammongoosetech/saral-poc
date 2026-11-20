package architecture_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	verifierBin := filepath.Join(projectRoot, "services/verifier/bin/verifier"+ext)
	coordBin := filepath.Join(projectRoot, "services/coordinator/bin/coordinator"+ext)
	nodeBin := filepath.Join(projectRoot, "services/saral-node/bin/saral-node"+ext)

	// 1. Build Go Binaries
	t.Log("[STEP 1] Compiling clean Go microservices binaries...")
	buildCmds := [][]string{
		{"go", "build", "-o", verifierBin, "./cmd/main.go"},
		{"go", "build", "-o", coordBin, "./cmd/main.go"},
		{"go", "build", "-o", nodeBin, "./cmd/main.go"},
	}
	dirs := []string{
		filepath.Join(projectRoot, "services/verifier"),
		filepath.Join(projectRoot, "services/coordinator"),
		filepath.Join(projectRoot, "services/saral-node"),
	}

	for i, cmdArgs := range buildCmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Dir = dirs[i]
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build %s: %v\nOutput: %s", cmdArgs[3], err, string(out))
		}
	}
	t.Log("  -> All 3 Go binaries compiled successfully.")

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
		"aud":         "saral-domain-coordinators",
		"mfaVerified": true,
		"domainRole":  "admin",
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenObj.Header["kid"] = "saral-auth-ed25519-2026-01"
	validToken, err := tokenObj.SignedString(authPrivKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	// 3. Launch All 3 Verifiers (Foundation, Public, Private)
	t.Log("[STEP 3] Launching All 3 Domain Verifiers (Ports: 8115, 8116, 8117)...")
	verifierPorts := map[string]int{
		"FOUNDATION": 8115,
		"PUBLIC":     8116,
		"PRIVATE":    8117,
	}
	verifierCmds := make(map[string]*exec.Cmd)
	defer func() {
		for _, cmd := range verifierCmds {
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()

	for _, domain := range []string{"FOUNDATION", "PUBLIC", "PRIVATE"} {
		port := verifierPorts[domain]
		vCmd := exec.Command(verifierBin,
			"-domain", domain,
			"-port", fmt.Sprintf("%d", port),
			"-pubkey", pubKeyPath,
		)
		if err := vCmd.Start(); err != nil {
			t.Fatalf("failed to start %s verifier: %v", domain, err)
		}
		verifierCmds[domain] = vCmd

		if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/health", port), 5*time.Second); err != nil {
			t.Fatalf("%s verifier failed to become healthy: %v", domain, err)
		}
	}

	// Test Verifier token verification
	vClient := &http.Client{Timeout: 3 * time.Second}
	vReqBody, _ := json.Marshal(map[string]string{"token": validToken})
	vResp, err := vClient.Post(fmt.Sprintf("http://localhost:%d/verify", verifierPorts["FOUNDATION"]), "application/json", bytes.NewReader(vReqBody))
	if err != nil || vResp.StatusCode != http.StatusOK {
		t.Fatalf("verifier rejected valid token: %v", err)
	}
	var vResult struct {
		Valid bool   `json:"valid"`
		Sub   string `json:"sub"`
	}
	_ = json.NewDecoder(vResp.Body).Decode(&vResult)
	vResp.Body.Close()
	if !vResult.Valid || vResult.Sub != "operator-admin-1" {
		t.Fatalf("unexpected verifier response: %v", vResult)
	}

	// Test Verifier invalid token rejection (Fail closed)
	vBadBody, _ := json.Marshal(map[string]string{"token": "invalid.forged.jwt"})
	vBadResp, err := vClient.Post(fmt.Sprintf("http://localhost:%d/verify", verifierPorts["FOUNDATION"]), "application/json", bytes.NewReader(vBadBody))
	if err != nil {
		t.Fatalf("failed to post bad token: %v", err)
	}
	var vBadResult struct {
		Valid bool `json:"valid"`
	}
	_ = json.NewDecoder(vBadResp.Body).Decode(&vBadResult)
	vBadResp.Body.Close()
	if vBadResult.Valid {
		t.Fatalf("verifier accepted forged token!")
	}
	t.Log("  -> All 3 Verifiers active: validated genuine EdDSA token and rejected forged token.")

	// 4. Launch 15 Nodes across 3 Domains
	t.Log("[STEP 4] Launching 15 independent SARAL Node instances (5 Foundation, 5 Public, 5 Private)...")
	type domainConfig struct {
		name     string
		basePort int
		baseP2P  int
	}
	domains := []domainConfig{
		{name: "FOUNDATION", basePort: 19100, baseP2P: 29100},
		{name: "PUBLIC", basePort: 19110, baseP2P: 29110},
		{name: "PRIVATE", basePort: 19120, baseP2P: 29120},
	}

	var allNodeCmds []*exec.Cmd
	defer func() {
		for _, cmd := range allNodeCmds {
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()

	uniquePubKeys := make(map[string]string)
	nodeIDToPubKey := make(map[string]string)

	for _, d := range domains {
		for i := 1; i <= 5; i++ {
			nodePort := d.basePort + i
			p2pPort := d.baseP2P + i
			nodeVault := filepath.Join(tmpDir, fmt.Sprintf("vault_%s_%d", strings.ToLower(d.name), i))
			nodeID := fmt.Sprintf("saral-%s-%d", strings.ToLower(d.name), i)

			cmd := exec.Command(nodeBin,
				"-node-id", nodeID,
				"-domain", d.name,
				"-node-index", fmt.Sprintf("%d", i),
				"-port", fmt.Sprintf("%d", nodePort),
				"-p2p-port", fmt.Sprintf("%d", p2pPort),
				"-vault-dir", nodeVault,
			)
			cmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start %s node %d: %v", d.name, i, err)
			}
			allNodeCmds = append(allNodeCmds, cmd)

			if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/node/health", nodePort), 5*time.Second); err != nil {
				t.Fatalf("%s node %d failed to become healthy on port %d: %v", d.name, i, nodePort, err)
			}

			// Verify unique identity
			statusResp, err := http.Get(fmt.Sprintf("http://localhost:%d/node/status", nodePort))
			if err != nil {
				t.Fatalf("failed to fetch status of %s: %v", nodeID, err)
			}
			var st struct {
				NodeID       string `json:"nodeId"`
				PublicKeyHex string `json:"publicKeyHex"`
				Status       string `json:"status"`
			}
			_ = json.NewDecoder(statusResp.Body).Decode(&st)
			statusResp.Body.Close()

			if st.PublicKeyHex == "" {
				t.Fatalf("node %s has empty public key", nodeID)
			}
			if existing, found := uniquePubKeys[st.PublicKeyHex]; found {
				t.Fatalf("duplicate public key between %s and %s", existing, nodeID)
			}
			uniquePubKeys[st.PublicKeyHex] = nodeID
			nodeIDToPubKey[nodeID] = st.PublicKeyHex
		}
	}
	t.Logf("  -> All 15 nodes active, healthy, and verified with 15 unique Ed25519 identities.")

	// 5. Test P2P Authentication, Replay Protection, and Invalid Peer Rejection
	t.Log("[STEP 5] Testing P2P Peer Authentication, Replay Protection & Rejection...")
	// 5A: Valid Signed P2P Ping
	node1Port := 19101
	node2Port := 19102
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UnixMilli()
	nonce1 := "test-nonce-0001"
	sender2ID := "saral-foundation-2"
	receiver1ID := "saral-foundation-1"

	// Pre-enroll sender2's public key in node1's trusted participant registry
	enrollBody, _ := json.Marshal(map[string]string{
		"nodeId":       sender2ID,
		"publicKeyHex": hex.EncodeToString(pub2),
		"domain":       "FOUNDATION",
	})
	eReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/node/participants", node1Port), bytes.NewReader(enrollBody))
	eReq.Header.Set("Content-Type", "application/json")
	eReq.Header.Set("X-Saral-Internal-Token", testInternalToken)
	if eResp, err := http.DefaultClient.Do(eReq); err == nil {
		eResp.Body.Close()
	}

	msgToSign := fmt.Sprintf("%s:%s:%s:%d:%s", sender2ID, receiver1ID, "FOUNDATION", now, nonce1)
	sig2 := hex.EncodeToString(ed25519.Sign(priv2, []byte(msgToSign)))

	pingReq := map[string]interface{}{
		"senderId":     sender2ID,
		"receiverId":   receiver1ID,
		"domain":       "FOUNDATION",
		"timestamp":    now,
		"nonce":        nonce1,
		"publicKeyHex": hex.EncodeToString(pub2),
		"signatureHex": sig2,
	}
	pingBody, _ := json.Marshal(pingReq)
	pResp, err := http.Post(fmt.Sprintf("http://localhost:%d/p2p/ping", node1Port), "application/json", bytes.NewReader(pingBody))
	if err != nil {
		t.Fatalf("p2p ping failed: %v", err)
	}
	var ack struct {
		Acknowledged bool   `json:"acknowledged"`
		ReceiverID   string `json:"receiverId"`
		SignatureHex string `json:"signatureHex"`
	}
	respBodyBytes, _ := io.ReadAll(pResp.Body)
	_ = json.Unmarshal(respBodyBytes, &ack)
	pResp.Body.Close()
	if !ack.Acknowledged || ack.ReceiverID != receiver1ID || ack.SignatureHex == "" {
		t.Fatalf("expected valid signed ack, status %d, body: %s", pResp.StatusCode, string(respBodyBytes))
	}
	t.Log("  -> Valid P2P ping successfully verified and signed ACK received.")

	// 5B: Replay Attack Rejection Test (same nonce)
	pRespReplay, err := http.Post(fmt.Sprintf("http://localhost:%d/p2p/ping", node1Port), "application/json", bytes.NewReader(pingBody))
	if err != nil {
		t.Fatalf("replay post failed: %v", err)
	}
	pRespReplay.Body.Close()
	if pRespReplay.StatusCode != http.StatusConflict && pRespReplay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected replay attack to be rejected with 409 or 401, got status %d", pRespReplay.StatusCode)
	}
	t.Log("  -> Replay attack successfully rejected.")

	// 5C: Invalid Peer Rejection (Invalid signature)
	badPingReq := map[string]interface{}{
		"senderId":     "saral-foundation-3",
		"receiverId":   receiver1ID,
		"domain":       "FOUNDATION",
		"timestamp":    now,
		"nonce":        "test-nonce-bad-sig",
		"publicKeyHex": hex.EncodeToString(pub2),
		"signatureHex": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
	badBody, _ := json.Marshal(badPingReq)
	pBadResp, _ := http.Post(fmt.Sprintf("http://localhost:%d/p2p/ping", node1Port), "application/json", bytes.NewReader(badBody))
	if pBadResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected forged signature to be rejected with 401, got: %d", pBadResp.StatusCode)
	}
	pBadResp.Body.Close()
	t.Log("  -> Forged peer signature successfully rejected.")

	// 6. Test Node Identity Persistence after Restart
	t.Log("[STEP 6] Testing Node identity persistence across restarts...")
	node1Vault := filepath.Join(tmpDir, "vault_foundation_1")
	node1OrigKey := nodeIDToPubKey["saral-foundation-1"]

	// Kill node-f1
	allNodeCmds[0].Process.Kill()
	_ = allNodeCmds[0].Wait()
	time.Sleep(200 * time.Millisecond)

	// Restart node-f1 pointing to same vault
	cmdRestart := exec.Command(nodeBin,
		"-node-id", "saral-foundation-1",
		"-domain", "FOUNDATION",
		"-node-index", "1",
		"-port", "19101",
		"-p2p-port", "29101",
		"-vault-dir", node1Vault,
	)
	cmdRestart.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken)
	if err := cmdRestart.Start(); err != nil {
		t.Fatalf("failed to restart node-f1: %v", err)
	}
	allNodeCmds[0] = cmdRestart
	if err := waitForHealthy("http://localhost:19101/node/health", 5*time.Second); err != nil {
		t.Fatalf("node-f1 failed to recover: %v", err)
	}

	stResp, _ := http.Get("http://localhost:19101/node/status")
	var stAfter struct {
		PublicKeyHex string `json:"publicKeyHex"`
	}
	_ = json.NewDecoder(stResp.Body).Decode(&stAfter)
	stResp.Body.Close()

	if stAfter.PublicKeyHex != node1OrigKey {
		t.Fatalf("node identity changed after restart! expected %s, got %s", node1OrigKey, stAfter.PublicKeyHex)
	}
	t.Log("  -> Identity persistence verified: public key identical after restart.")

	// 7. Launch 3 Coordinators
	t.Log("[STEP 7] Launching 3 Coordinators (Foundation: 8011, Public: 8012, Private: 8013)...")
	coordFPort := 8011
	coordPPort := 8012
	coordRPort := 8013

	// Write dynamic genesis registry for coordinators with the actual ephemeral node identities
	genesisEntries := make(map[string]interface{})
	for nodeID, pubKey := range nodeIDToPubKey {
		d := "FOUNDATION"
		if strings.Contains(nodeID, "public") {
			d = "PUBLIC"
		} else if strings.Contains(nodeID, "private") {
			d = "PRIVATE"
		}
		genesisEntries[nodeID] = map[string]interface{}{
			"nodeId":       nodeID,
			"domain":       d,
			"publicKeyHex": pubKey,
			"approvedBy":   "genesis-bootstrap",
			"enrolledAt":   time.Now().UTC().Format(time.RFC3339),
		}
	}
	genesisFilePath := filepath.Join(tmpDir, "genesis_participants.json")
	genBytes, _ := json.MarshalIndent(genesisEntries, "", "  ")
	_ = os.WriteFile(genesisFilePath, genBytes, 0644)

	coordFCmd := exec.Command(coordBin,
		"-domain", "FOUNDATION",
		"-port", fmt.Sprintf("%d", coordFPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPorts["FOUNDATION"]),
		"-nodes", "5",
		"-base-node-port", "19100",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordPPort, coordRPort),
	)
	coordFCmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken, "SARAL_GENESIS_REGISTRY_FILE="+genesisFilePath)
	if err := coordFCmd.Start(); err != nil {
		t.Fatalf("failed to start foundation coordinator: %v", err)
	}
	defer coordFCmd.Process.Kill()

	coordPCmd := exec.Command(coordBin,
		"-domain", "PUBLIC",
		"-port", fmt.Sprintf("%d", coordPPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPorts["PUBLIC"]),
		"-nodes", "5",
		"-base-node-port", "19110",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordFPort, coordRPort),
	)
	coordPCmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken, "SARAL_GENESIS_REGISTRY_FILE="+genesisFilePath)
	if err := coordPCmd.Start(); err != nil {
		t.Fatalf("failed to start public coordinator: %v", err)
	}
	defer coordPCmd.Process.Kill()

	coordRCmd := exec.Command(coordBin,
		"-domain", "PRIVATE",
		"-port", fmt.Sprintf("%d", coordRPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPorts["PRIVATE"]),
		"-nodes", "5",
		"-base-node-port", "19120",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordFPort, coordPPort),
	)
	coordRCmd.Env = append(os.Environ(), "ENABLE_DEV_AUTH=true", "SARAL_INTERNAL_TOKEN="+testInternalToken, "SARAL_GENESIS_REGISTRY_FILE="+genesisFilePath)
	if err := coordRCmd.Start(); err != nil {
		t.Fatalf("failed to start private coordinator: %v", err)
	}
	defer coordRCmd.Process.Kill()

	for _, p := range []int{coordFPort, coordPPort, coordRPort} {
		if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/health", p), 5*time.Second); err != nil {
			t.Fatalf("coordinator at port %d failed to become healthy: %v", p, err)
		}
	}
	t.Log("  -> All 3 Coordinators active and healthy with peer mesh configured.")

	// Allow discovery monitor to poll nodes
	time.Sleep(1 * time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	// 8. Test Coordinator JSON-RPC saral_getDomainStatus
	t.Log("[STEP 8] Calling saral_getDomainStatus on Foundation Coordinator...")
	domReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"saral_getDomainStatus","params":{}}`)
	domResp, err := client.Post(fmt.Sprintf("http://localhost:%d/rpc", coordFPort), "application/json", bytes.NewReader(domReq))
	if err != nil {
		t.Fatalf("saral_getDomainStatus failed: %v", err)
	}
	var domResult struct {
		Result struct {
			Domain      string `json:"domain"`
			TotalNodes  int    `json:"totalNodes"`
			OnlineNodes int    `json:"onlineNodes"`
		} `json:"result"`
	}
	_ = json.NewDecoder(domResp.Body).Decode(&domResult)
	domResp.Body.Close()

	if domResult.Result.TotalNodes != 5 || domResult.Result.OnlineNodes != 5 {
		t.Fatalf("unexpected domain status: total=%d, online=%d", domResult.Result.TotalNodes, domResult.Result.OnlineNodes)
	}
	t.Logf("  -> Verified Foundation Domain: %d/5 nodes online.", domResult.Result.OnlineNodes)

	// 9. Test Unauthorized RPC Rejection (No token on protected RPC)
	t.Log("[STEP 9] Testing Unauthorized RPC Rejection (Calling saral_getNetworkStatus without token)...")
	unauthReqBody := []byte(`{"jsonrpc":"2.0","id":99,"method":"saral_getNetworkStatus","params":{}}`)
	unauthResp, err := client.Post(fmt.Sprintf("http://localhost:%d/rpc", coordFPort), "application/json", bytes.NewReader(unauthReqBody))
	if err != nil {
		t.Fatalf("rpc call failed: %v", err)
	}
	var unauthResult struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(unauthResp.Body).Decode(&unauthResult)
	unauthResp.Body.Close()

	if unauthResult.Error == nil || unauthResult.Error.Code != -32001 {
		t.Fatalf("expected -32001 unauthorized error for unauthenticated call, got: %v", unauthResult.Error)
	}
	t.Log("  -> Unauthorized RPC rejected properly with -32001.")

	// 10. Test Cross-Domain Aggregated Network Status: saral_getNetworkStatus
	t.Log("[STEP 10] Calling saral_getNetworkStatus with EdDSA JWT...")
	netReqBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"saral_getNetworkStatus","params":{}}`)
	netReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", coordFPort), bytes.NewReader(netReqBody))
	netReq.Header.Set("Content-Type", "application/json")
	netReq.Header.Set("Authorization", "Bearer "+validToken)

	netResp, err := client.Do(netReq)
	if err != nil {
		t.Fatalf("saral_getNetworkStatus call failed: %v", err)
	}
	var netResult struct {
		Result struct {
			TotalNodes  int `json:"totalNodes"`
			OnlineNodes int `json:"onlineNodes"`
			Domains     map[string]struct {
				Domain      string `json:"domain"`
				OnlineNodes int    `json:"onlineNodes"`
			} `json:"domains"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(netResp.Body).Decode(&netResult)
	netResp.Body.Close()

	if netResult.Error != nil {
		t.Fatalf("saral_getNetworkStatus returned error: %s", netResult.Error.Message)
	}
	if netResult.Result.TotalNodes != 15 || netResult.Result.OnlineNodes != 15 {
		t.Fatalf("expected 15/15 online nodes across 3 domains, got %d/%d",
			netResult.Result.OnlineNodes, netResult.Result.TotalNodes)
	}
	if len(netResult.Result.Domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(netResult.Result.Domains))
	}
	t.Logf("  -> Cross-domain network status verified: 15/15 nodes online across 3 domains.")

	// 11. Test Network Probe: saral_probeNetwork
	t.Log("[STEP 11] Calling saral_probeNetwork to orchestrate real process-to-process probes...")
	probeReqBody := []byte(`{"jsonrpc":"2.0","id":3,"method":"saral_probeNetwork","params":{}}`)
	probeReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", coordFPort), bytes.NewReader(probeReqBody))
	probeReq.Header.Set("Content-Type", "application/json")
	probeReq.Header.Set("Authorization", "Bearer "+validToken)

	probeResp, err := client.Do(probeReq)
	if err != nil {
		t.Fatalf("saral_probeNetwork call failed: %v", err)
	}
	var probeResult struct {
		Result struct {
			ProbeID            string `json:"probeId"`
			ProbesDispatched   int    `json:"probesDispatched"`
			ProbesAcknowledged int    `json:"probesAcknowledged"`
			AverageLatencyMs   int64  `json:"averageLatencyMs"`
			Probes             []struct {
				ReceiverID   string `json:"receiverId"`
				Domain       string `json:"domain"`
				Acknowledged bool   `json:"acknowledged"`
				LatencyMs    int64  `json:"latencyMs"`
				SignatureHex string `json:"signatureHex"`
			} `json:"probes"`
		} `json:"result"`
	}
	_ = json.NewDecoder(probeResp.Body).Decode(&probeResult)
	probeResp.Body.Close()

	if probeResult.Result.ProbesAcknowledged != 15 {
		t.Fatalf("expected 15 acknowledged probes, got %d", probeResult.Result.ProbesAcknowledged)
	}
	t.Logf("  -> Probe %s successfully acknowledged by all 15 nodes with Ed25519 signatures (Avg Latency: %d ms).",
		probeResult.Result.ProbeID, probeResult.Result.AverageLatencyMs)

	// 12. Test Verifier Failure (Fail-Closed Behavior)
	t.Log("[STEP 12] Testing Verifier Failure (Fail-Closed: terminating Foundation verifier)...")
	verifierCmds["FOUNDATION"].Process.Kill()
	_ = verifierCmds["FOUNDATION"].Wait()
	time.Sleep(200 * time.Millisecond)

	failReq, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/rpc", coordFPort), bytes.NewReader(netReqBody))
	failReq.Header.Set("Content-Type", "application/json")
	failReq.Header.Set("Authorization", "Bearer "+validToken)

	failResp, err := client.Do(failReq)
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	var failResult struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(failResp.Body).Decode(&failResult)
	failResp.Body.Close()

	if failResult.Error == nil || !strings.Contains(failResult.Error.Message, "Authorization rejected") {
		t.Fatalf("expected fail-closed rejection when verifier is down, got: %v", failResult.Error)
	}
	t.Log("  -> Fail-closed verified: Coordinator immediately rejected requests when Verifier went offline.")

	// 13. Test Cryptographic Stubs return explicit NOT_IMPLEMENTED
	t.Log("[STEP 13] Testing Section 8 Compliance: Cryptographic stubs return NOT_IMPLEMENTED...")
	cryptoReqBody := []byte(`{"jsonrpc":"2.0","id":4,"method":"saral_signTransaction","params":{}}`)
	cryptoResp, err := client.Post(fmt.Sprintf("http://localhost:%d/rpc", coordPPort), "application/json", bytes.NewReader(cryptoReqBody))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	var cryptoResult struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(cryptoResp.Body).Decode(&cryptoResult)
	cryptoResp.Body.Close()

	if cryptoResult.Error == nil || cryptoResult.Error.Code != -32000 || !strings.Contains(cryptoResult.Error.Message, "NOT_IMPLEMENTED") {
		t.Fatalf("expected NOT_IMPLEMENTED (-32000) error, got: %v", cryptoResult.Error)
	}
	t.Logf("  -> Verified: Cryptographic stub returned explicit NOT_IMPLEMENTED (-32000).")

	_ = node2Port
	t.Log("✅ ALL 13 INTEGRATION TESTS PASSED (3 verifiers, 3 coordinators, 15 nodes, peer auth, replay protection, fail-closed, stubs)!")
}
