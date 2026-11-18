package avss_test

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// simulatedNetwork routes relay messages between Engine instances in memory
type simulatedNetwork struct {
	nodes map[string]*avss.Engine
	mu    sync.RWMutex
}

func newSimulatedNetwork() *simulatedNetwork {
	return &simulatedNetwork{nodes: make(map[string]*avss.Engine)}
}

func (n *simulatedNetwork) register(nodeID string, engine *avss.Engine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nodes[nodeID] = engine
}

func (n *simulatedNetwork) SendToNode(targetNode, targetDomain, msgType string, payload []byte) error {
	n.mu.RLock()
	destEngine, exists := n.nodes[targetNode]
	n.mu.RUnlock()

	if !exists {
		return fmt.Errorf("target node %s not found in simulated network", targetNode)
	}

	go func() {
		switch msgType {
		case avss.MessageTypeSend:
			var msg avss.SendMessage
			if err := json.Unmarshal(payload, &msg); err == nil {
				_ = destEngine.HandleSendMessage(&msg)
			}
		case avss.MessageTypeEcho:
			var msg avss.EchoMessage
			if err := json.Unmarshal(payload, &msg); err == nil {
				_ = destEngine.HandleEchoMessage(&msg)
			}
		case avss.MessageTypeReady:
			var msg avss.ReadyMessage
			if err := json.Unmarshal(payload, &msg); err == nil {
				_ = destEngine.HandleReadyMessage(&msg)
			}
		}
	}()
	return nil
}

func TestAVSS15NodeEngineNetwork(t *testing.T) {
	// 15 nodes: Configuration A: n=15, k=5, t=4
	tempDir, err := os.MkdirTemp("", "saral-avss-integration-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	net := newSimulatedNetwork()
	committee := make([]string, 15)
	engines := make(map[string]*avss.Engine)

	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("saral-node-%d", i+1)
		committee[i] = id

		nodeVault := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(nodeVault, 0700)
		shareStore, _ := vault.NewShareStore(nodeVault, []byte("node-ident-"+id))

		engine := avss.NewEngine(id, "FOUNDATION", nodeVault, shareStore, net)
		engines[id] = engine
		net.register(id, engine)
	}

	// Pre-create sessions on all 15 nodes
	sessionID := "avss-session-integ-15"
	dealerID := "saral-node-1"
	for _, id := range committee {
		_, err := engines[id].CreateSession(sessionID, "committee-15", dealerID, 1, 15, 5, 4, committee)
		if err != nil {
			t.Fatalf("failed to create session on %s: %v", id, err)
		}
	}

	// Dealer starts sharing
	secret := cryptography.NewFieldElement(999888777)
	dealerEngine := engines[dealerID]
	pkg, err := dealerEngine.StartDealerSharing(sessionID, "committee-15", committee, 5, secret, nil)
	if err != nil {
		t.Fatalf("failed to start dealer sharing: %v", err)
	}
	_ = pkg

	// Wait for asynchronous protocol convergence
	deadline := time.Now().Add(5 * time.Second)
	allCompleted := false
	for time.Now().Before(deadline) {
		completedCount := 0
		for _, id := range committee {
			sess, err := engines[id].GetSession(sessionID)
			if err == nil && sess.State == avss.StateSharingCompleted {
				completedCount++
			}
		}
		if completedCount == 15 {
			allCompleted = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if !allCompleted {
		t.Fatalf("not all 15 nodes completed AVSS within deadline")
	}

	// Test authorized reconstruction with exactly k=5 shares
	reconShares := make([]*avss.ReconstructionShare, 5)
	chosenIndices := []int{2, 5, 8, 11, 14}
	for idx, sIdx := range chosenIndices {
		id := fmt.Sprintf("saral-node-%d", sIdx)
		sess, _ := engines[id].GetSession(sessionID)
		reconShares[idx] = &avss.ReconstructionShare{
			NodeID:     id,
			NodeIndex:  sIdx,
			Share:      sess.Share,
			BlindShare: sess.BlindShare,
		}
	}

	reconResult, err := dealerEngine.ExecuteTestReconstruction(sessionID, reconShares)
	if err != nil {
		t.Fatalf("test reconstruction failed: %v", err)
	}

	if !reconResult.Secret.Equal(secret) {
		t.Fatalf("reconstructed secret mismatch: got %s, want %s", reconResult.Secret.Hex(), secret.Hex())
	}

	// Test reconstruction with fewer than k=5 shares fails
	_, err = dealerEngine.ExecuteTestReconstruction(sessionID, reconShares[:4])
	if err == nil {
		t.Fatalf("expected error for insufficient reconstruction shares")
	}

	// Verify share was persisted in vault for each node
	for _, id := range committee {
		meta, share, _, err := engines[id].ShareStore.LoadShare("committee-15", 1, 1)
		if err != nil {
			t.Fatalf("node %s failed to load persisted share from vault: %v", id, err)
		}
		if meta.State != "ACTIVE" {
			t.Fatalf("expected ACTIVE state in vault metadata")
		}
		if share == nil || share.IsZero() {
			t.Fatalf("invalid share loaded from vault")
		}
	}
}

func TestConcurrentAVSSSessions(t *testing.T) {
	// Runs 3 distinct AVSS sessions concurrently on the same network to verify session isolation
	tempDir, err := os.MkdirTemp("", "saral-avss-concurrent-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	net := newSimulatedNetwork()
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	engines := make(map[string]*avss.Engine)

	for _, id := range committee {
		nodeVault := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(nodeVault, 0700)
		shareStore, _ := vault.NewShareStore(nodeVault, []byte("ident-"+id))
		engine := avss.NewEngine(id, "PUBLIC", nodeVault, shareStore, net)
		engines[id] = engine
		net.register(id, engine)
	}

	sessionIDs := []string{"concurrent-sess-1", "concurrent-sess-2", "concurrent-sess-3"}
	secrets := []*cryptography.FieldElement{
		cryptography.NewFieldElement(111111),
		cryptography.NewFieldElement(222222),
		cryptography.NewFieldElement(333333),
	}

	var wg sync.WaitGroup
	for sIdx, sID := range sessionIDs {
		wg.Add(1)
		go func(sessID string, sec *cryptography.FieldElement) {
			defer wg.Done()
			for _, id := range committee {
				_, _ = engines[id].CreateSession(sessID, "comm-concurrent", "node-1", 1, 5, 2, 1, committee)
			}
			_, err := engines["node-1"].StartDealerSharing(sessID, "comm-concurrent", committee, 2, sec, nil)
			if err != nil {
				t.Errorf("failed concurrent sharing %s: %v", sessID, err)
			}
		}(sID, secrets[sIdx])
	}
	wg.Wait()

	// Wait for convergence of all 3 sessions
	deadline := time.Now().Add(5 * time.Second)
	allDone := false
	for time.Now().Before(deadline) {
		doneCount := 0
		for _, sID := range sessionIDs {
			sessDone := true
			for _, id := range committee {
				sess, err := engines[id].GetSession(sID)
				if err != nil || sess.State != avss.StateSharingCompleted {
					sessDone = false
					break
				}
			}
			if sessDone {
				doneCount++
			}
		}
		if doneCount == 3 {
			allDone = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !allDone {
		t.Fatalf("not all concurrent AVSS sessions completed")
	}

	// Verify each session reconstructed its own independent secret
	for sIdx, sID := range sessionIDs {
		sh1, _ := engines["node-1"].GetSession(sID)
		sh2, _ := engines["node-2"].GetSession(sID)
		reconShares := []*avss.ReconstructionShare{
			{NodeID: "node-1", NodeIndex: 1, Share: sh1.Share, BlindShare: sh1.BlindShare},
			{NodeID: "node-2", NodeIndex: 2, Share: sh2.Share, BlindShare: sh2.BlindShare},
		}
		res, err := engines["node-1"].ExecuteTestReconstruction(sID, reconShares)
		if err != nil {
			t.Fatalf("reconstruction failed for %s: %v", sID, err)
		}
		if !res.Secret.Equal(secrets[sIdx]) {
			t.Fatalf("secret mismatch for %s: got %s, want %s", sID, res.Secret.Hex(), secrets[sIdx].Hex())
		}
	}
}
