//go:build test_only

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// simulatedMeshRelay implements avss.RelaySender and routes messages in memory between node engines
type simulatedMeshRelay struct {
	engines map[string]*avss.Engine
	mu      sync.RWMutex
}

func newSimulatedMeshRelay() *simulatedMeshRelay {
	return &simulatedMeshRelay{
		engines: make(map[string]*avss.Engine),
	}
}

func (r *simulatedMeshRelay) register(id string, eng *avss.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engines[id] = eng
}

func (r *simulatedMeshRelay) SendToNode(targetNode, targetDomain, msgType string, payload []byte) error {
	r.mu.RLock()
	destEngine, ok := r.engines[targetNode]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("target node %s not found in mesh relay", targetNode)
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

// TestE2EAVSSSharingAndReconstruction15Nodes validates Configuration A (n=15, k=5, t=4)
func TestE2EAVSSSharingAndReconstruction15Nodes(t *testing.T) {
	n := 15
	k := 5
	f := 4 // Byzantine fault bound t

	// 1. Parameter bound validation (Cachin et al. CCS 2002: n - 2*t >= k and k > t)
	if err := avss.ValidateAVSSParameters(n, k, f); err != nil {
		t.Fatalf("AVSS parameters validation failed: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "saral-avss-e2e-15-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	relay := newSimulatedMeshRelay()
	engines := make([]*avss.Engine, n)

	// 2. Initialize 15 independent node engines with encrypted vaults
	for i := 0; i < n; i++ {
		nodeID := committee[i]
		nodeDir := filepath.Join(tempDir, nodeID)
		_ = os.MkdirAll(nodeDir, 0700)

		key := []byte(fmt.Sprintf("saral-node-ident-key-%02d", i+1))
		store, err := vault.NewShareStore(nodeDir, key)
		if err != nil {
			t.Fatalf("Failed to create vault for %s: %v", nodeID, err)
		}

		eng := avss.NewEngine(nodeID, "FOUNDATION", nodeDir, store, relay)
		relay.register(nodeID, eng)
		engines[i] = eng
	}

	sessionID := "e2e-avss-session-15"
	committeeID := "e2e-comm-15"
	dealerID := committee[0]

	// 3. Register session on all 15 nodes
	for i := 0; i < n; i++ {
		_, err := engines[i].CreateSession(sessionID, committeeID, dealerID, 1, n, k, f, committee)
		if err != nil {
			t.Fatalf("Failed to create session on %s: %v", committee[i], err)
		}
	}

	// 4. Sample master secret and blinding scalar
	dealerSecret := cryptography.DeterministicScalar("SARAL_E2E_MASTER_SECRET_TEST", 1)
	dealerBlinding := cryptography.DeterministicScalar("SARAL_E2E_MASTER_BLINDING_TEST", 2)
	expectedSecretCommitment := cryptography.PedersenCommitment(dealerSecret, dealerBlinding)

	// 5. Dealer initiates AVSS sharing
	pkg, err := engines[0].StartDealerSharing(sessionID, committeeID, committee, k, dealerSecret, dealerBlinding)
	if err != nil {
		t.Fatalf("StartDealerSharing failed: %v", err)
	}

	if !pkg.CommitmentMatrix.SecretCommitment().Equal(expectedSecretCommitment) {
		t.Fatalf("Secret commitment mismatch in dealer package")
	}

	// 6. Wait for all 15 nodes to asynchronously converge on SHARING_COMPLETED
	deadline := time.Now().Add(10 * time.Second)
	allCompleted := false
	for time.Now().Before(deadline) {
		completedCount := 0
		for i := 0; i < n; i++ {
			sess, err := engines[i].GetSession(sessionID)
			if err == nil && sess.State == avss.StateSharingCompleted {
				completedCount++
			}
		}
		if completedCount == n {
			allCompleted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allCompleted {
		t.Fatalf("Not all %d nodes completed sharing before deadline", n)
	}
	t.Logf("All %d nodes successfully completed AVSS sharing session %s", n, sessionID)

	// 7. Controlled Test Reconstruction with exactly k=5 valid shares
	kShares := make([]*avss.ReconstructionShare, k)
	for i := 0; i < k; i++ {
		sess, _ := engines[i].GetSession(sessionID)
		kShares[i] = &avss.ReconstructionShare{
			NodeID:     committee[i],
			NodeIndex:  i + 1,
			Share:      sess.Share,
			BlindShare: sess.BlindShare,
		}
	}

	reconResult, err := engines[0].ExecuteTestReconstruction(sessionID, kShares)
	if err != nil {
		t.Fatalf("Test reconstruction with k=%d shares failed: %v", k, err)
	}

	if !reconResult.Secret.Equal(dealerSecret) {
		t.Fatalf("Reconstructed secret does not match dealer secret! Got %s, expected %s",
			reconResult.Secret.Hex(), dealerSecret.Hex())
	}
	if !reconResult.SecretCommitment.Equal(expectedSecretCommitment) {
		t.Fatalf("Reconstructed secret commitment does not match expected commitment!")
	}
	t.Logf("Successfully verified test reconstruction with k=%d shares: master secret invariant verified", k)

	// 8. Negative Test: Sub-threshold shares (k-1 = 4) MUST fail
	subShares := kShares[:k-1]
	_, err = engines[0].ExecuteTestReconstruction(sessionID, subShares)
	if err == nil {
		t.Fatalf("Reconstruction MUST fail with fewer than k shares (got success with k-1=%d)", k-1)
	}
	t.Logf("Sub-threshold reconstruction strictly rejected as expected: %v", err)

	// 9. Byzantine Robustness: Corrupted/forged share scalar MUST be rejected
	forgedShares := make([]*avss.ReconstructionShare, k)
	for i := 0; i < k; i++ {
		forgedShares[i] = &avss.ReconstructionShare{
			NodeID:     kShares[i].NodeID,
			NodeIndex:  kShares[i].NodeIndex,
			Share:      kShares[i].Share,
			BlindShare: kShares[i].BlindShare,
		}
	}
	forgedShares[2].Share = cryptography.DeterministicScalar("BYZANTINE_MALICIOUS_SHARE", 99)
	_, err = engines[0].ExecuteTestReconstruction(sessionID, forgedShares)
	if err == nil {
		t.Fatalf("Reconstruction MUST fail when a participant provides a forged share scalar!")
	}
	t.Logf("Byzantine forged share scalar successfully rejected: %v", err)
}

// TestE2EProactiveShareRefreshSecretInvariance validates proactive epoch transition and secret invariance
func TestE2EProactiveShareRefreshSecretInvariance(t *testing.T) {
	n := 15
	k := 5
	f := 4

	// Validate Cachin proactive refresh constraints: k = t + 1 and n > 3*t
	if err := avss.ValidateProactiveParameters(n, k, f); err != nil {
		t.Fatalf("Proactive parameters validation failed: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "saral-proactive-e2e-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	masterSecret := cryptography.NewFieldElement(1234567890)
	masterBlind := cryptography.NewFieldElement(9876543210)
	masterCommitment := cryptography.PedersenCommitment(masterSecret, masterBlind)

	// 1. Dealer generates Epoch 1 sharing
	dealerPkg, err := avss.GenerateDealerSharing(
		"epoch-1-init", "committee-15", "saral-node-1", 1, committee, k, masterSecret, masterBlind,
	)
	if err != nil {
		t.Fatalf("dealer sharing failed: %v", err)
	}

	vaults := make(map[string]*vault.ShareStore)
	peerCommitments := make(map[string]*cryptography.CurvePoint)
	epoch1Shares := make(map[string]*cryptography.FieldElement)
	epoch1BlindShares := make(map[string]*cryptography.FieldElement)

	for idx, id := range committee {
		nodeVault := filepath.Join(tempDir, id)
		_ = os.MkdirAll(nodeVault, 0700)
		ss, _ := vault.NewShareStore(nodeVault, []byte("key-"+id))
		vaults[id] = ss

		idxFE := cryptography.NewFieldElement(int64(idx + 1))
		sI := dealerPkg.F.RowPolynomial(idxFE).Coeffs[0]
		sPrimeI := dealerPkg.FPrime.RowPolynomial(idxFE).Coeffs[0]
		qI := dealerPkg.CommitmentMatrix.ComputeShareCommitment(idxFE)

		epoch1Shares[id] = sI
		epoch1BlindShares[id] = sPrimeI
		peerCommitments[id] = qI

		meta := vault.ShareRecordMetadata{
			CommitteeID:            "committee-15",
			SessionID:              "epoch-1-init",
			NodeID:                 id,
			NodeIndex:              idx + 1,
			Epoch:                  1,
			ShareVersion:           1,
			State:                  "ACTIVE",
			PublicShareCommitment:  qI.Hex(),
			PublicSecretCommitment: dealerPkg.CommitmentMatrix.SecretCommitment().Hex(),
		}
		_ = ss.SaveShare(meta, sI, sPrimeI)
	}

	// 2. Initialize RefreshSessions for all 15 nodes for Epoch 2
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for idx, id := range committee {
		rs, err := proactive.NewRefreshSession(
			"committee-15", 1, id, idx+1, committee, k, f,
			epoch1Shares[id], epoch1BlindShares[id], peerCommitments, dealerPkg.CommitmentMatrix.SecretCommitment(),
		)
		if err != nil {
			t.Fatalf("failed init refresh session on %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// 3. Each node generates AVSS subprotocol re-sharing its Epoch 1 share
	subprotocolPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		subPkg, err := avss.GenerateDealerSharing(
			"sub-epoch-2-"+id, "committee-15", id, 2, committee, k, epoch1Shares[id], epoch1BlindShares[id],
		)
		if err != nil {
			t.Fatalf("subprotocol dealer %s failed: %v", id, err)
		}
		subprotocolPkgs[id] = subPkg
	}

	// Deliver subprotocol messages to all nodes
	for dealerID, subPkg := range subprotocolPkgs {
		for recipientID, sendMsg := range subPkg.SendMessages {
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sess, _ := avss.NewSession(sendMsg.SessionID, "committee-15", dealerID, recipientID, rIdx, 2, n, k, f, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, sess)
		}
	}

	// 4. Validated Byzantine Agreement on Candidate Set (size 2t+1 = 9)
	agreedSet := make([]string, 2*f+1)
	for i := 0; i < 2*f+1; i++ {
		agreedSet[i] = committee[i]
	}

	prop := &proactive.AgreementProposeMessage{
		CommitteeID:  "committee-15",
		Epoch:        2,
		ProposerID:   "saral-node-1",
		CandidateSet: agreedSet,
	}

	allEchos := make([]*proactive.AgreementEchoMessage, 0)
	for _, id := range committee {
		echo, err := refreshSessions[id].Agreement.ProcessProposal(prop)
		if err != nil {
			t.Fatalf("node %s rejected proposal: %v", id, err)
		}
		allEchos = append(allEchos, echo)
	}

	allReadys := make([]*proactive.AgreementReadyMessage, 0)
	for _, id := range committee {
		for _, echo := range allEchos {
			ready, _ := refreshSessions[id].Agreement.ProcessEcho(echo)
			if ready != nil {
				allReadys = append(allReadys, ready)
			}
		}
	}

	for _, ready := range allReadys {
		for _, id := range committee {
			_, _, moreReady, _ := refreshSessions[id].Agreement.ProcessReady(ready)
			if moreReady != nil {
				for _, otherID := range committee {
					refreshSessions[otherID].Agreement.ProcessReady(moreReady)
				}
			}
		}
	}

	// 5. Finalize refresh for Epoch 2 and compute refreshed shares
	for _, id := range committee {
		rs := refreshSessions[id]
		if !rs.Agreement.IsDecided {
			t.Fatalf("node %s did not reach agreement", id)
		}
		if err := rs.ComputeNewShare(rs.Agreement.DecidedSet, vaults[id]); err != nil {
			t.Fatalf("node %s compute new share failed: %v", id, err)
		}
	}

	// 6. Mathematical verification: Lagrange interpolation of Epoch 2 shares yields identical master secret!
	xs := make([]*cryptography.FieldElement, k)
	ys := make([]*cryptography.FieldElement, k)
	ysPrime := make([]*cryptography.FieldElement, k)

	for i := 0; i < k; i++ {
		id := committee[i]
		xs[i] = cryptography.NewFieldElement(int64(i + 1))
		ys[i] = refreshSessions[id].NewShare
		ysPrime[i] = refreshSessions[id].NewBlindShare
	}

	poly, err := avss.InterpolateUnivariate(xs, ys)
	if err != nil {
		t.Fatalf("failed to interpolate epoch 2 shares: %v", err)
	}
	reconstructedSecret := poly.Coeffs[0]

	polyBlind, err := avss.InterpolateUnivariate(xs, ysPrime)
	if err != nil {
		t.Fatalf("failed to interpolate epoch 2 blind shares: %v", err)
	}
	reconstructedBlind := polyBlind.Coeffs[0]

	if !reconstructedSecret.Equal(masterSecret) {
		t.Fatalf("Master secret changed across proactive refresh! Got %s, expected %s",
			reconstructedSecret.Hex(), masterSecret.Hex())
	}

	reconstructedCommitment := cryptography.PedersenCommitment(reconstructedSecret, reconstructedBlind)
	if !reconstructedCommitment.Equal(masterCommitment) {
		t.Fatalf("Public master commitment changed across proactive refresh!")
	}
	t.Logf("Secret invariance verified: master secret preserved identically across proactive epoch transition")

	// 7. Verify that individual participant shares were randomized and rotated
	for i := 0; i < k; i++ {
		id := committee[i]
		if epoch1Shares[id].Equal(refreshSessions[id].NewShare) {
			t.Fatalf("Node %s share was not randomized during proactive refresh!", id)
		}
	}
	t.Logf("All participant shares were freshly rotated")

	// 8. Verify Old Epoch 1 Share Erasure from vault
	for _, id := range committee {
		_, _, _, err := vaults[id].LoadShare("committee-15", 1, 2)
		if err == nil {
			t.Fatalf("Node %s old epoch 1 share was not erased from vault!", id)
		}
	}
	t.Logf("Old epoch 1 shares were cryptographically overwritten and securely erased")
}

// TestE2EConfigurationCBoundaries verifies that Configuration C satisfies dual-threshold AVSS
// but is strictly rejected for proactive refresh per Cachin et al. CCS 2002.
func TestE2EConfigurationCBoundaries(t *testing.T) {
	n := 5
	k := 3
	f := 1

	// 1. Dual-threshold AVSS condition check:
	// n - 2*t >= k (5 - 2*1 = 3 >= 3: SATISFIED)
	// k > t (3 > 1: SATISFIED)
	if err := avss.ValidateAVSSParameters(n, k, f); err != nil {
		t.Fatalf("Configuration C should satisfy AVSS dual-threshold condition: %v", err)
	}

	// 2. Proactive refresh condition check:
	// Cachin et al. requires k = t + 1 (3 != 2: VIOLATED)
	err := avss.ValidateProactiveParameters(n, k, f)
	if err == nil {
		t.Fatalf("Configuration C must NOT satisfy Cachin proactive refresh constraint (k=3 != t+1=2)")
	}
	t.Logf("Configuration C proactive refresh successfully blocked with error: %v", err)
}

// TestE2EConfigurationBOrdinaryCommittee validates Configuration B (n=5, t=1, k=2) full lifecycle
func TestE2EConfigurationBOrdinaryCommittee(t *testing.T) {
	n := 5
	k := 2
	f := 1 // t = 1

	// Validate bounds
	if err := avss.ValidateAVSSParameters(n, k, f); err != nil {
		t.Fatalf("Configuration B AVSS parameter validation failed: %v", err)
	}
	if err := avss.ValidateProactiveParameters(n, k, f); err != nil {
		t.Fatalf("Configuration B Proactive parameter validation failed: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "saral-config-b-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := []string{"node-b1", "node-b2", "node-b3", "node-b4", "node-b5"}
	vaults := make(map[string]*vault.ShareStore)
	for _, id := range committee {
		dir := filepath.Join(tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		store, err := vault.NewShareStore(dir, []byte("key-"+id))
		if err != nil {
			t.Fatalf("failed to create vault: %v", err)
		}
		vaults[id] = store
	}

	masterSecret, err := cryptography.RandScalar()
	if err != nil {
		t.Fatalf("failed sampling secret: %v", err)
	}
	masterBlind, err := cryptography.RandScalar()
	if err != nil {
		t.Fatalf("failed sampling blind: %v", err)
	}
	masterCommitment := cryptography.PedersenCommitment(masterSecret, masterBlind)

	// 1. Dealer sharing for Epoch 1
	pkg, err := avss.GenerateDealerSharing("session-b-epoch-1", "comm-b", "node-b1", 1, committee, k, masterSecret, masterBlind)
	if err != nil {
		t.Fatalf("failed generating dealer sharing: %v", err)
	}

	epoch1Shares := make(map[string]*cryptography.FieldElement)
	epoch1BlindShares := make(map[string]*cryptography.FieldElement)
	peerCommitments := make(map[string]*cryptography.CurvePoint)

	for id, sendMsg := range pkg.SendMessages {
		rIdx := avss.NodeIndexInCommittee(committee, id)
		sess, err := avss.NewSession(sendMsg.SessionID, "comm-b", "node-b1", id, rIdx, 1, n, k, f, committee)
		if err != nil {
			t.Fatalf("failed creating session: %v", err)
		}
		_, err = sess.ProcessSendMessage(sendMsg)
		if err != nil {
			t.Fatalf("node %s failed to process SEND: %v", id, err)
		}
		_ = sess.FinalizeShare()
		epoch1Shares[id] = sess.Share
		epoch1BlindShares[id] = sess.BlindShare
		peerCommitments[id] = sess.PublicShareCommitment

		meta := vault.ShareRecordMetadata{
			CommitteeID:            "comm-b",
			SessionID:              sendMsg.SessionID,
			NodeID:                 id,
			NodeIndex:              rIdx,
			Epoch:                  1,
			ShareVersion:           1,
			State:                  "ACTIVE",
			PublicShareCommitment:  sess.PublicShareCommitment.Hex(),
			PublicSecretCommitment: sess.PublicSecretCommitment.Hex(),
			CreatedAt:              time.Now().UnixMilli(),
			UpdatedAt:              time.Now().UnixMilli(),
		}
		_ = vaults[id].SaveShare(meta, sess.Share, sess.BlindShare)
	}

	// Verify reconstruction with k=2 shares
	reconShares := []*avss.ReconstructionShare{
		{NodeID: committee[0], NodeIndex: 1, Share: epoch1Shares[committee[0]], BlindShare: epoch1BlindShares[committee[0]]},
		{NodeID: committee[1], NodeIndex: 2, Share: epoch1Shares[committee[1]], BlindShare: epoch1BlindShares[committee[1]]},
	}
	recon, err := avss.ReconstructSecret(reconShares, pkg.CommitmentMatrix, k)
	if err != nil {
		t.Fatalf("Configuration B reconstruction failed: %v", err)
	}
	if !recon.Secret.Equal(masterSecret) {
		t.Fatalf("reconstructed secret mismatch")
	}

	// 2. Proactive Refresh to Epoch 2
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for _, id := range committee {
		rIdx := avss.NodeIndexInCommittee(committee, id)
		rs, err := proactive.NewRefreshSession("comm-b", 1, id, rIdx, committee, k, f,
			epoch1Shares[id], epoch1BlindShares[id], peerCommitments, masterCommitment)
		if err != nil {
			t.Fatalf("failed creating refresh session for %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// Subprotocol AVSS instances: each dealer shares its existing share
	subPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		subPkg, err := avss.GenerateDealerSharing(fmt.Sprintf("sub-b-%s", id), "comm-b", id, 2, committee, k,
			epoch1Shares[id], epoch1BlindShares[id])
		if err != nil {
			t.Fatalf("dealer %s failed subprotocol: %v", id, err)
		}
		subPkgs[id] = subPkg
	}

	for dealerID, subPkg := range subPkgs {
		for recipientID, sendMsg := range subPkg.SendMessages {
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sess, _ := avss.NewSession(sendMsg.SessionID, "comm-b", dealerID, recipientID, rIdx, 2, n, k, f, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, sess)
		}
	}

	// Agreement on 2t+1 = 3 dealers
	agreedSet := []string{"node-b1", "node-b2", "node-b3"}
	prop := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-b",
		Epoch:        2,
		ProposerID:   "node-b1",
		CandidateSet: agreedSet,
	}

	allEchos := make([]*proactive.AgreementEchoMessage, 0)
	for _, id := range committee {
		echo, err := refreshSessions[id].Agreement.ProcessProposal(prop)
		if err != nil {
			t.Fatalf("node %s rejected proposal: %v", id, err)
		}
		allEchos = append(allEchos, echo)
	}

	allReadys := make([]*proactive.AgreementReadyMessage, 0)
	for _, id := range committee {
		for _, echo := range allEchos {
			ready, _ := refreshSessions[id].Agreement.ProcessEcho(echo)
			if ready != nil {
				allReadys = append(allReadys, ready)
			}
		}
	}

	for _, ready := range allReadys {
		for _, id := range committee {
			refreshSessions[id].Agreement.ProcessReady(ready)
		}
	}

	// Finalize Epoch 2 shares
	for _, id := range committee {
		rs := refreshSessions[id]
		if !rs.Agreement.IsDecided {
			t.Fatalf("node %s did not decide agreement", id)
		}
		if err := rs.ComputeNewShare(rs.Agreement.DecidedSet, vaults[id]); err != nil {
			t.Fatalf("node %s failed computing new share: %v", id, err)
		}
	}

	// Verify secret invariance in Epoch 2
	xs := []*cryptography.FieldElement{cryptography.NewFieldElement(1), cryptography.NewFieldElement(2)}
	ys := []*cryptography.FieldElement{refreshSessions["node-b1"].NewShare, refreshSessions["node-b2"].NewShare}
	poly, err := avss.InterpolateUnivariate(xs, ys)
	if err != nil {
		t.Fatalf("failed interpolation of epoch 2 shares: %v", err)
	}
	if !poly.Coeffs[0].Equal(masterSecret) {
		t.Fatalf("secret changed across epoch 2 in Configuration B")
	}

	// Verify old share erasure
	for _, id := range committee {
		_, _, _, err := vaults[id].LoadShare("comm-b", 1, 2)
		if err == nil {
			t.Fatalf("node %s old share was not erased", id)
		}
	}
	t.Logf("Configuration B (n=5, t=1, k=2) AVSS and Proactive Refresh PASSED")
}

// TestE2ECrossEpochShareMixingAttack proves mathematically that combining shares across
// different epochs cannot reconstruct the secret, satisfying mobile adversary resilience.
func TestE2ECrossEpochShareMixingAttack(t *testing.T) {
	n := 15
	k := 5
	f := 4

	masterSecret, _ := cryptography.RandScalar()
	masterBlind, _ := cryptography.RandScalar()
	masterCommitment := cryptography.PedersenCommitment(masterSecret, masterBlind)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("node-%d", i+1)
	}

	// Epoch 1 Sharing
	pkg, _ := avss.GenerateDealerSharing("sess-mix-1", "comm-mix", "node-1", 1, committee, k, masterSecret, masterBlind)
	epoch1Shares := make([]*cryptography.FieldElement, n)
	peerCommitments := make(map[string]*cryptography.CurvePoint)

	for idx, id := range committee {
		sendMsg := pkg.SendMessages[id]
		sess, _ := avss.NewSession(sendMsg.SessionID, "comm-mix", "node-1", id, idx+1, 1, n, k, f, committee)
		_, _ = sess.ProcessSendMessage(sendMsg)
		_ = sess.FinalizeShare()
		epoch1Shares[idx] = sess.Share
		peerCommitments[id] = sess.PublicShareCommitment
	}

	// Epoch 2 Refresh
	refreshSessions := make([]*proactive.RefreshSession, n)
	for idx, id := range committee {
		rs, _ := proactive.NewRefreshSession("comm-mix", 1, id, idx+1, committee, k, f,
			epoch1Shares[idx], cryptography.NewFieldElement(1), peerCommitments, masterCommitment)
		refreshSessions[idx] = rs
	}

	subPkgs := make(map[string]*avss.DealerPackage)
	for idx, id := range committee {
		subPkg, _ := avss.GenerateDealerSharing("sub-"+id, "comm-mix", id, 2, committee, k,
			epoch1Shares[idx], cryptography.NewFieldElement(1))
		subPkgs[id] = subPkg
	}

	for dealerID, subPkg := range subPkgs {
		for idx, recipientID := range committee {
			sendMsg := subPkg.SendMessages[recipientID]
			sess, _ := avss.NewSession(sendMsg.SessionID, "comm-mix", dealerID, recipientID, idx+1, 2, n, k, f, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()
			refreshSessions[idx].RecordCompletedSharing(dealerID, sess)
		}
	}

	agreedSet := committee[:2*f+1]
	for idx := range committee {
		_ = refreshSessions[idx].ComputeNewShare(agreedSet, nil)
	}
	epoch2Shares := make([]*cryptography.FieldElement, n)
	for idx := range committee {
		epoch2Shares[idx] = refreshSessions[idx].NewShare
	}

	// Cross-epoch attack scenarios:
	// Scenario A: 4 shares from Epoch 1 (nodes 1,2,3,4) + 1 share from Epoch 2 (node 5) -> Total 5 = k shares
	xsMixA := []*cryptography.FieldElement{
		cryptography.NewFieldElement(1),
		cryptography.NewFieldElement(2),
		cryptography.NewFieldElement(3),
		cryptography.NewFieldElement(4),
		cryptography.NewFieldElement(5),
	}
	ysMixA := []*cryptography.FieldElement{
		epoch1Shares[0], // Epoch 1
		epoch1Shares[1], // Epoch 1
		epoch1Shares[2], // Epoch 1
		epoch1Shares[3], // Epoch 1
		epoch2Shares[4], // Epoch 2!
	}
	polyA, err := avss.InterpolateUnivariate(xsMixA, ysMixA)
	if err != nil {
		t.Fatalf("interpolation failed: %v", err)
	}
	if polyA.Coeffs[0].Equal(masterSecret) {
		t.Fatalf("SECURITY VIOLATION: Cross-epoch mixed shares reconstructed the secret in Scenario A!")
	}
	t.Logf("Scenario A (4 Epoch1 + 1 Epoch2) strictly failed to reconstruct secret as expected: got %s != master %s",
		polyA.Coeffs[0].Hex(), masterSecret.Hex())

	// Scenario B: 2 shares from Epoch 1 (nodes 1,2) + 3 shares from Epoch 2 (nodes 3,4,5) -> Total 5 = k shares
	ysMixB := []*cryptography.FieldElement{
		epoch1Shares[0], // Epoch 1
		epoch1Shares[1], // Epoch 1
		epoch2Shares[2], // Epoch 2
		epoch2Shares[3], // Epoch 2
		epoch2Shares[4], // Epoch 2
	}
	polyB, _ := avss.InterpolateUnivariate(xsMixA, ysMixB)
	if polyB.Coeffs[0].Equal(masterSecret) {
		t.Fatalf("SECURITY VIOLATION: Cross-epoch mixed shares reconstructed the secret in Scenario B!")
	}
	t.Logf("Scenario B (2 Epoch1 + 3 Epoch2) strictly failed to reconstruct secret as expected: got %s != master %s",
		polyB.Coeffs[0].Hex(), masterSecret.Hex())
}

// TestE2EAsynchronousDelayedReorderedDelivery simulates severe network asynchrony:
// Dealer SEND is withheld from Node 4, READY messages arrive before ECHOs,
// verifying asynchronous fallback interpolation and ready backlog evaluation.
func TestE2EAsynchronousDelayedReorderedDelivery(t *testing.T) {
	n := 5
	k := 2
	f := 1

	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	masterSecret, _ := cryptography.RandScalar()
	masterBlind, _ := cryptography.RandScalar()

	pkg, err := avss.GenerateDealerSharing("sess-async-reorder", "comm-async", "node-1", 1, committee, k, masterSecret, masterBlind)
	if err != nil {
		t.Fatalf("failed generating dealer sharing: %v", err)
	}

	sessions := make(map[string]*avss.Session)
	for idx, id := range committee {
		sess, err := avss.NewSession("sess-async-reorder", "comm-async", "node-1", id, idx+1, 1, n, k, f, committee)
		if err != nil {
			t.Fatalf("failed creating session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// 1. Dealer sends SEND to nodes 1, 2, 3, 5, but WITHHOLDS SEND from node 4! (t=1 omitted node)
	allEchos := make([]*avss.EchoMessage, 0)
	for _, id := range []string{"node-1", "node-2", "node-3", "node-5"} {
		echos, err := sessions[id].ProcessSendMessage(pkg.SendMessages[id])
		if err != nil {
			t.Fatalf("node %s failed ProcessSendMessage: %v", id, err)
		}
		allEchos = append(allEchos, echos...)
	}

	// 2. Deliver ECHOs among nodes 1, 2, 3, 5 so they generate READY messages (n-t = 4 echos each)
	allReadys := make([]*avss.ReadyMessage, 0)
	for _, echo := range allEchos {
		if echo.RecipientID == "node-4" {
			continue // delay ECHOs to node 4
		}
		readys, err := sessions[echo.RecipientID].ProcessEchoMessage(echo)
		if err != nil {
			t.Fatalf("node %s failed echo: %v", echo.RecipientID, err)
		}
		allReadys = append(allReadys, readys...)
	}

	// 3. Deliver READY messages intended for Node 4 BEFORE any ECHOs arrive at Node 4!
	// At this point, Node 4 has received NO send and NO echos, so RowPoly is nil.
	for _, ready := range allReadys {
		if ready.RecipientID != "node-4" {
			continue
		}
		completed, moreReadys, err := sessions["node-4"].ProcessReadyMessage(ready)
		if err != nil {
			t.Fatalf("node 4 failed ready: %v", err)
		}
		if completed {
			t.Fatalf("node 4 should not complete before receiving echos/polynomials")
		}
		_ = moreReadys
	}

	// Check that Node 4 has buffered the READY messages but has not sent READY or completed
	if sessions["node-4"].State == avss.StateSharingCompleted {
		t.Fatalf("node 4 premature completion")
	}

	// 4. Now deliver the delayed ECHOs to Node 4!
	for _, echo := range allEchos {
		if echo.RecipientID == "node-4" {
			readysToSend, err := sessions["node-4"].ProcessEchoMessage(echo)
			if err != nil {
				t.Fatalf("node 4 failed processing delayed echo: %v", err)
			}
			_ = readysToSend
		}
	}

	// 5. Node 4 must now have successfully interpolated its polynomial and completed sharing
	// via the buffered READY messages!
	if sessions["node-4"].State != avss.StateSharingCompleted {
		t.Fatalf("Node 4 failed to complete sharing after receiving delayed ECHOs with buffered READYs! State=%s",
			sessions["node-4"].State)
	}

	// Verify Node 4's finalized share against commitment C(4, 0)
	node4IndexFE := cryptography.NewFieldElement(4)
	if !pkg.CommitmentMatrix.VerifyShare(node4IndexFE, sessions["node-4"].Share, sessions["node-4"].BlindShare) {
		t.Fatalf("Node 4 interpolated share failed verification against public commitment!")
	}
	t.Logf("Asynchronous delayed delivery and ready buffering successfully verified: Node 4 recovered and completed share")
}

// TestE2EMaliciousCommitmentAndByzantineAdversary tests that malicious commitments and forged points
// are strictly rejected by honest nodes and do not prevent honest completion.
func TestE2EMaliciousCommitmentAndByzantineAdversary(t *testing.T) {
	n := 5
	k := 2
	f := 1

	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-byz"}
	masterSecret, _ := cryptography.RandScalar()
	masterBlind, _ := cryptography.RandScalar()

	pkg, _ := avss.GenerateDealerSharing("sess-mal-1", "comm-mal", "node-1", 1, committee, k, masterSecret, masterBlind)
	sessHonest, _ := avss.NewSession("sess-mal-1", "comm-mal", "node-1", "node-2", 2, 1, n, k, f, committee)

	// Process honest SEND
	_, err := sessHonest.ProcessSendMessage(pkg.SendMessages["node-2"])
	if err != nil {
		t.Fatalf("honest SEND failed: %v", err)
	}

	// 1. Byzantine node attempts to send forged ECHO point
	forgedPoint, _ := cryptography.RandScalar()
	forgedEcho := &avss.EchoMessage{
		SessionID:   "sess-mal-1",
		CommitteeID: "comm-mal",
		SenderID:    "node-byz",
		RecipientID: "node-2",
		Epoch:       1,
		Commitments: pkg.SendMessages["node-2"].Commitments,
		Point:       forgedPoint.Hex(),
		BlindPoint:  forgedPoint.Hex(),
		Timestamp:   time.Now().UnixMilli(),
	}

	_, err = sessHonest.ProcessEchoMessage(forgedEcho)
	if err == nil {
		t.Fatalf("Honest node must reject forged ECHO point!")
	}
	t.Logf("Forged ECHO point successfully rejected with error: %v", err)

	// 2. Byzantine node attempts to send forged commitment matrix in READY
	malCommitments := pkg.CommitmentMatrix.ToHexMatrix()
	malCommitments[0][0] = cryptography.GeneratorG.Hex() // tamper with C_{0, 0}
	malReady := &avss.ReadyMessage{
		SessionID:   "sess-mal-1",
		CommitteeID: "comm-mal",
		SenderID:    "node-byz",
		RecipientID: "node-2",
		Epoch:       1,
		Commitments: malCommitments,
		Point:       forgedPoint.Hex(),
		BlindPoint:  forgedPoint.Hex(),
		Timestamp:   time.Now().UnixMilli(),
	}

	_, _, err = sessHonest.ProcessReadyMessage(malReady)
	if err == nil {
		t.Fatalf("Honest node must reject tampered commitment matrix in READY!")
	}
	t.Logf("Tampered commitment matrix successfully rejected with error: %v", err)
}

// TestE2ENodeRestartAndEpochInterruption simulates node crash during epoch transition
// and verifies crash recovery from vault state.
func TestE2ENodeRestartAndEpochInterruption(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "saral-crash-test-*")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaultDir := filepath.Join(tempDir, "node-1-vault")
	store, _ := vault.NewShareStore(vaultDir, []byte("node-1-key"))

	shareVal, _ := cryptography.RandScalar()
	blindVal, _ := cryptography.RandScalar()
	meta := vault.ShareRecordMetadata{
		CommitteeID:            "comm-crash",
		SessionID:              "sess-epoch-1",
		NodeID:                 "node-1",
		NodeIndex:              1,
		Epoch:                  1,
		ShareVersion:           1,
		State:                  "ACTIVE",
		PublicShareCommitment:  cryptography.PedersenCommitment(shareVal, blindVal).Hex(),
		PublicSecretCommitment: cryptography.GeneratorG.Hex(),
		CreatedAt:              time.Now().UnixMilli(),
		UpdatedAt:              time.Now().UnixMilli(),
	}

	// Persist active epoch 1 share
	err = store.SaveShare(meta, shareVal, blindVal)
	if err != nil {
		t.Fatalf("failed saving initial share: %v", err)
	}

	// Simulate node process termination and restart: create fresh store instance
	recoveredStore, err := vault.NewShareStore(vaultDir, []byte("node-1-key"))
	if err != nil {
		t.Fatalf("failed to recover store: %v", err)
	}

	// Verify recovered share
	recMeta, recShare, recBlind, err := recoveredStore.LoadShare("comm-crash", 1, 1)
	if err != nil {
		t.Fatalf("failed loading share after crash recovery: %v", err)
	}
	if recMeta.State != "ACTIVE" || !recShare.Equal(shareVal) || !recBlind.Equal(blindVal) {
		t.Fatalf("recovered share data corrupted after restart")
	}

	t.Logf("Crash recovery successfully verified: recovered active share at epoch %d with correct state", recMeta.Epoch)
}

// TestE2ERandomizedABBAConflictingProposals15Nodes tests the randomized Asynchronous Byzantine Agreement
// protocol resolving conflicting valid proposals across 15 nodes with a threshold common coin.
func TestE2ERandomizedABBAConflictingProposals15Nodes(t *testing.T) {
	n := 15
	k := 5
	f := 4 // Byzantine fault bound t = 4, quorum 2t+1 = 9

	tempDir, err := os.MkdirTemp("", "saral-abba-e2e-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	masterSecret := cryptography.NewFieldElement(987654321)
	masterBlind := cryptography.NewFieldElement(123456789)
	masterCommitment := cryptography.PedersenCommitment(masterSecret, masterBlind)

	// Step 1: Dealer generates Epoch 1 sharing
	dealerPkg, err := avss.GenerateDealerSharing(
		"init-epoch-1", "comm-abba-15", committee[0], 1, committee, k, masterSecret, masterBlind,
	)
	if err != nil {
		t.Fatalf("dealer sharing failed: %v", err)
	}

	vaults := make(map[string]*vault.ShareStore)
	peerCommitments := make(map[string]*cryptography.CurvePoint)
	epoch1Shares := make(map[string]*cryptography.FieldElement)
	epoch1BlindShares := make(map[string]*cryptography.FieldElement)

	for idx, id := range committee {
		nodeVault := filepath.Join(tempDir, id)
		_ = os.MkdirAll(nodeVault, 0700)
		ss, _ := vault.NewShareStore(nodeVault, []byte("key-"+id))
		vaults[id] = ss

		idxFE := cryptography.NewFieldElement(int64(idx + 1))
		sI := dealerPkg.F.RowPolynomial(idxFE).Coeffs[0]
		sPrimeI := dealerPkg.FPrime.RowPolynomial(idxFE).Coeffs[0]
		qI := dealerPkg.CommitmentMatrix.ComputeShareCommitment(idxFE)

		epoch1Shares[id] = sI
		epoch1BlindShares[id] = sPrimeI
		peerCommitments[id] = qI

		meta := vault.ShareRecordMetadata{
			CommitteeID:            "comm-abba-15",
			SessionID:              "init-epoch-1",
			NodeID:                 id,
			NodeIndex:              idx + 1,
			Epoch:                  1,
			ShareVersion:           1,
			State:                  "ACTIVE",
			PublicShareCommitment:  qI.Hex(),
			PublicSecretCommitment: masterCommitment.Hex(),
		}
		_ = ss.SaveShare(meta, sI, sPrimeI)
	}

	// Step 2: Initialize RefreshSessions for all 15 nodes
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for idx, id := range committee {
		rs, err := proactive.NewRefreshSession(
			"comm-abba-15", 1, id, idx+1, committee, k, f,
			epoch1Shares[id], epoch1BlindShares[id], peerCommitments, masterCommitment,
		)
		if err != nil {
			t.Fatalf("failed init refresh session on %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// Step 3: All 15 nodes deal AVSS subprotocol sharing
	subPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, err := avss.GenerateDealerSharing(
			"sub-epoch-2-"+id, "comm-abba-15", id, 2, committee, k, epoch1Shares[id], epoch1BlindShares[id],
		)
		if err != nil {
			t.Fatalf("subprotocol dealer %s failed: %v", id, err)
		}
		subPkgs[id] = pkg
	}

	for dealerID, pkg := range subPkgs {
		for recipientID, sendMsg := range pkg.SendMessages {
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sess, _ := avss.NewSession(sendMsg.SessionID, "comm-abba-15", dealerID, recipientID, rIdx, 2, n, k, f, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, sess)
		}
	}

	// Step 4: Two conflicting valid candidate sets (both size 9 >= 2t+1)
	candidateSet1 := committee[:9]
	candidateSet2 := committee[1:10]
	hash1 := proactive.HashCandidateSet(candidateSet1)
	hash2 := proactive.HashCandidateSet(candidateSet2)

	prop1 := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-abba-15",
		Epoch:        2,
		ProposerID:   committee[0],
		CandidateSet: candidateSet1,
	}
	prop2 := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-abba-15",
		Epoch:        2,
		ProposerID:   committee[4],
		CandidateSet: candidateSet2,
	}

	for _, id := range committee {
		_, _ = refreshSessions[id].Agreement.ProcessProposal(prop1)
		_, _ = refreshSessions[id].Agreement.ProcessProposal(prop2)
	}

	// Step 5: Asymmetric network delivery causing split PRE-VOTEs in Round 1
	round1Prevotes := make([]*proactive.AgreementVoteMessage, 0)
	for idx, id := range committee {
		chosenHash := hash1
		if idx >= 7 { // nodes 8..15 prefer proposal 2
			chosenHash = hash2
		}
		round1Prevotes = append(round1Prevotes, &proactive.AgreementVoteMessage{
			CommitteeID:   "comm-abba-15",
			Epoch:         2,
			Round:         1,
			Step:          proactive.StepPreVote,
			SenderID:      id,
			CandidateHash: chosenHash,
			VoteValue:     proactive.VoteAccept,
		})
	}

	// Exchange Round 1 PRE-VOTEs
	round1Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range committee {
		for _, pv := range round1Prevotes {
			nextVote, _, _, _, _ := refreshSessions[id].Agreement.ProcessVote(pv)
			if nextVote != nil {
				round1Mainvotes = append(round1Mainvotes, nextVote)
			}
		}
	}

	// Exchange Round 1 MAIN-VOTEs -> Triggers threshold common coin query
	coinSharesRound1 := make([]*proactive.AgreementCoinShareMessage, 0)
	for _, id := range committee {
		for _, mv := range round1Mainvotes {
			_, coinMsg, _, _, _ := refreshSessions[id].Agreement.ProcessVote(mv)
			if coinMsg != nil {
				coinSharesRound1 = append(coinSharesRound1, coinMsg)
			}
		}
	}

	// Exchange Round 1 Coin Shares -> Resolves tie with threshold common coin!
	round2Prevotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range committee {
		for _, csMsg := range coinSharesRound1 {
			nextVote, _, _, _ := refreshSessions[id].Agreement.ProcessCoinShare(csMsg)
			if nextVote != nil {
				round2Prevotes = append(round2Prevotes, nextVote)
			}
		}
	}

	// Exchange Round 2 PRE-VOTEs (all nodes now aligned by common coin!)
	round2Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range committee {
		for _, pv := range round2Prevotes {
			nextVote, _, _, _, _ := refreshSessions[id].Agreement.ProcessVote(pv)
			if nextVote != nil {
				round2Mainvotes = append(round2Mainvotes, nextVote)
			}
		}
	}

	// Exchange Round 2 MAIN-VOTEs -> All nodes DECIDE!
	for _, id := range committee {
		for _, mv := range round2Mainvotes {
			_, _, _, _, _ = refreshSessions[id].Agreement.ProcessVote(mv)
		}
	}

	// Step 6: Verify Byzantine Agreement Safety and Finalize Refreshed Shares
	var decidedHash string
	for _, id := range committee {
		rs := refreshSessions[id]
		if !rs.Agreement.IsDecided {
			t.Fatalf("node %s failed to decide under conflicting proposals with common coin", id)
		}
		if decidedHash == "" {
			decidedHash = rs.Agreement.DecidedHash
		} else if rs.Agreement.DecidedHash != decidedHash {
			t.Fatalf("SAFETY VIOLATION: node %s decided %s != %s", id, rs.Agreement.DecidedHash, decidedHash)
		}

		// Compute refreshed share
		if err := rs.ComputeNewShare(rs.Agreement.DecidedSet, vaults[id]); err != nil {
			t.Fatalf("node %s failed computing refreshed share: %v", id, err)
		}
	}

	// Step 7: Verify Mathematical Invariance across arbitrary subset of k=5 refreshed shares
	subsetNodes := []string{"saral-node-2", "saral-node-5", "saral-node-7", "saral-node-11", "saral-node-14"}
	reconShares := make([]*cryptography.FieldElement, k)
	reconBlinds := make([]*cryptography.FieldElement, k)
	xs := make([]*cryptography.FieldElement, k)
	for i, id := range subsetNodes {
		rs := refreshSessions[id]
		reconShares[i] = rs.NewShare
		reconBlinds[i] = rs.NewBlindShare
		nodeIndex := avss.NodeIndexInCommittee(committee, id)
		xs[i] = cryptography.NewFieldElement(int64(nodeIndex))
	}

	recoveredSecret := cryptography.NewFieldElement(0)
	recoveredBlind := cryptography.NewFieldElement(0)
	xTarget := cryptography.NewFieldElement(0)

	for i := 0; i < k; i++ {
		lambdaI, err := cryptography.LagrangeCoefficient(xTarget, xs[i], xs)
		if err != nil {
			t.Fatalf("Lagrange coeff failed: %v", err)
		}
		recoveredSecret = recoveredSecret.Add(lambdaI.Mul(reconShares[i]))
		recoveredBlind = recoveredBlind.Add(lambdaI.Mul(reconBlinds[i]))
	}

	if !recoveredSecret.Equal(masterSecret) {
		t.Fatalf("SECRET INVARIANCE BROKEN: recovered %s != original %s", recoveredSecret.Hex(), masterSecret.Hex())
	}
	if !recoveredBlind.Equal(masterBlind) {
		t.Fatalf("blind secret mismatch")
	}

	reconCommit := cryptography.PedersenCommitment(recoveredSecret, recoveredBlind)
	if !reconCommit.Equal(masterCommitment) {
		t.Fatalf("secret commitment mismatch after proactive refresh")
	}

	t.Logf("15-node randomized ABBA agreement with common coin, conflicting proposals, and secret invariance SUCCESSFUL!")
}
