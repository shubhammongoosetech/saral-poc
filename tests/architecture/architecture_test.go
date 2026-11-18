package architecture_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	verifierBin := filepath.Join(projectRoot, "services/verifier/bin/verifier")
	coordBin := filepath.Join(projectRoot, "services/coordinator/bin/coordinator")
	nodeBin := filepath.Join(projectRoot, "services/saral-node/bin/saral-node")

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

	// 2. Generate RSA Keypair & JWT for Auth
	t.Log("[STEP 2] Setting up Auth Server RSA keypair and issuing RS256 JWT...")
	authPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&authPrivKey.PublicKey)
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
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	validToken, err := tokenObj.SignedString(authPrivKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	// 3. Launch Verifier
	t.Log("[STEP 3] Launching Verifier on port 8115...")
	verifierPort := 8115
	verifierCmd := exec.Command(verifierBin,
		"-domain", "FOUNDATION",
		"-port", fmt.Sprintf("%d", verifierPort),
		"-pubkey", pubKeyPath,
	)
	if err := verifierCmd.Start(); err != nil {
		t.Fatalf("failed to start verifier: %v", err)
	}
	defer verifierCmd.Process.Kill()

	if err := waitForHealthy(fmt.Sprintf("http://localhost:%d/health", verifierPort), 5*time.Second); err != nil {
		t.Fatalf("verifier failed to become healthy: %v", err)
	}

	// Test Verifier token verification
	vClient := &http.Client{Timeout: 3 * time.Second}
	vReqBody, _ := json.Marshal(map[string]string{"token": validToken})
	vResp, err := vClient.Post(fmt.Sprintf("http://localhost:%d/verify", verifierPort), "application/json", bytes.NewReader(vReqBody))
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
	vBadResp, err := vClient.Post(fmt.Sprintf("http://localhost:%d/verify", verifierPort), "application/json", bytes.NewReader(vBadBody))
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
	t.Log("  -> Verifier successfully validated valid token and rejected forged token.")

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
		}
	}
	t.Logf("  -> All 15 nodes active, healthy, and verified with 15 unique Ed25519 identities.")

	// 5. Test Node Identity Persistence after Restart
	t.Log("[STEP 5] Testing Node identity persistence across restarts...")
	node1Vault := filepath.Join(tmpDir, "vault_foundation_1")
	node1OrigKey := ""
	for k, v := range uniquePubKeys {
		if v == "saral-foundation-1" {
			node1OrigKey = k
			break
		}
	}

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

	// 6. Launch 3 Coordinators
	t.Log("[STEP 6] Launching 3 Coordinators (Foundation: 8011, Public: 8012, Private: 8013)...")
	coordFPort := 8011
	coordPPort := 8012
	coordRPort := 8013

	coordFCmd := exec.Command(coordBin,
		"-domain", "FOUNDATION",
		"-port", fmt.Sprintf("%d", coordFPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPort),
		"-nodes", "5",
		"-base-node-port", "19100",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordPPort, coordRPort),
	)
	if err := coordFCmd.Start(); err != nil {
		t.Fatalf("failed to start foundation coordinator: %v", err)
	}
	defer coordFCmd.Process.Kill()

	coordPCmd := exec.Command(coordBin,
		"-domain", "PUBLIC",
		"-port", fmt.Sprintf("%d", coordPPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPort),
		"-nodes", "5",
		"-base-node-port", "19110",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordFPort, coordRPort),
	)
	if err := coordPCmd.Start(); err != nil {
		t.Fatalf("failed to start public coordinator: %v", err)
	}
	defer coordPCmd.Process.Kill()

	coordRCmd := exec.Command(coordBin,
		"-domain", "PRIVATE",
		"-port", fmt.Sprintf("%d", coordRPort),
		"-verifier", fmt.Sprintf("http://localhost:%d", verifierPort),
		"-nodes", "5",
		"-base-node-port", "19120",
		"-peers", fmt.Sprintf("http://localhost:%d,http://localhost:%d", coordFPort, coordPPort),
	)
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

	// 7. Test Coordinator JSON-RPC saral_getDomainStatus
	t.Log("[STEP 7] Calling saral_getDomainStatus on Foundation Coordinator...")
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

	// 8. Test Cross-Domain Aggregated Network Status: saral_getNetworkStatus
	t.Log("[STEP 8] Calling saral_getNetworkStatus with RS256 JWT...")
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

	// 9. Test Network Probe: saral_probeNetwork
	t.Log("[STEP 9] Calling saral_probeNetwork to orchestrate real process-to-process probes...")
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
	t.Logf("  -> Probe %s successfully acknowledged by all 15 nodes (Avg Latency: %d ms).",
		probeResult.Result.ProbeID, probeResult.Result.AverageLatencyMs)

	// 10. Test Cryptographic Stubs return explicit NOT_IMPLEMENTED
	t.Log("[STEP 10] Testing Section 8 Compliance: Cryptographic stubs return NOT_IMPLEMENTED...")
	cryptoReqBody := []byte(`{"jsonrpc":"2.0","id":4,"method":"saral_signTransaction","params":{}}`)
	cryptoResp, err := client.Post(fmt.Sprintf("http://localhost:%d/rpc", coordFPort), "application/json", bytes.NewReader(cryptoReqBody))
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

	t.Log("✅ FULL ARCHITECTURE RUNTIME VERIFICATION PASSED (All 15 nodes, 3 coordinators, verifier, auth verified)!")
}
