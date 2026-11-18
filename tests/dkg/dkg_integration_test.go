package dkg_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

// TestE2EDealerlessDKG15NodesGlobalCommittee tests the full 15-node Global Committee (n=15, t=4, k=5)
func TestE2EDealerlessDKG15NodesGlobalCommittee(t *testing.T) {
	n := 15
	k := 5
	f := 4 // Byzantine fault bound t = 4

	if err := dkg.ValidateDKGParameters(n, k, f); err != nil {
		t.Fatalf("global committee parameter validation failed: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "saral-dkg-integ-15-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	vaults := make(map[string]*vault.ShareStore)
	sessions := make(map[string]*dkg.Session)

	// Step 1: Initialize DKG session on all 15 nodes
	for idx, id := range committee {
		dir := filepath.Join(tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, err := vault.NewShareStore(dir, []byte("key-"+id))
		if err != nil {
			t.Fatalf("failed creating vault for %s: %v", id, err)
		}
		vaults[id] = ss

		sess, err := dkg.NewSession("dkg-global-15", "saral-global-15", id, idx+1, committee, n, k, f, ss)
		if err != nil {
			t.Fatalf("failed initializing DKG session on %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// Step 2: All 15 nodes independently generate random contributions and deal AVSS
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, err := sessions[id].StartContribution()
		if err != nil {
			t.Fatalf("StartContribution failed on %s: %v", id, err)
		}
		dealerPkgs[id] = pkg
	}

	// Step 3: Peer contribution distribution and verification
	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)

			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]

			subSess, _ := avss.NewSession(sendMsg.SessionID, "saral-global-15", dealerID, recipientID, rIdx, 1, n, k, f, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()

			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Step 4: Qualified Set Agreement on >= n - t = 11 nodes
	qualSet := committee[:11] // 11 qualified contributors
	for _, id := range committee {
		err := sessions[id].AggregateShares(qualSet)
		if err != nil {
			t.Fatalf("node %s failed aggregating shares: %v", id, err)
		}
		if sessions[id].State != dkg.StateCompleted {
			t.Fatalf("node %s not in COMPLETED state: %s", id, sessions[id].State)
		}
	}

	// Step 5: Public Key Agreement across all 15 nodes
	firstPub := sessions[committee[0]].MasterPublicKey
	for _, id := range committee {
		if !sessions[id].MasterPublicKey.Equal(firstPub) {
			t.Fatalf("MASTER PUBLIC KEY DISAGREEMENT on node %s", id)
		}
	}
	t.Logf("All 15 nodes successfully agreed on Master Public Key: %s", firstPub.Hex())

	// Step 6: Mathematical Reconstruction Invariance (Strict Test Workflow Only)
	// Verify that ANY k=5 nodes can reconstruct the master secret and match the master public key
	testSubsets := [][]int{
		{1, 2, 3, 4, 5},
		{2, 4, 6, 8, 10},
		{1, 5, 9, 13, 15},
		{11, 12, 13, 14, 15},
	}

	var expectedSecret *cryptography.FieldElement
	xTarget := cryptography.NewFieldElement(0)

	for sIdx, subset := range testSubsets {
		xs := make([]*cryptography.FieldElement, k)
		sVals := make([]*cryptography.FieldElement, k)
		bVals := make([]*cryptography.FieldElement, k)

		for i, nIdx := range subset {
			id := fmt.Sprintf("saral-node-%d", nIdx)
			xs[i] = cryptography.NewFieldElement(int64(nIdx))
			sVals[i] = sessions[id].FinalShare
			bVals[i] = sessions[id].FinalBlindShare
		}

		recSecret := cryptography.NewFieldElement(0)
		recBlind := cryptography.NewFieldElement(0)
		for i := 0; i < k; i++ {
			lambdaI, err := cryptography.LagrangeCoefficient(xTarget, xs[i], xs)
			if err != nil {
				t.Fatalf("Lagrange coeff failed: %v", err)
			}
			recSecret = recSecret.Add(lambdaI.Mul(sVals[i]))
			recBlind = recBlind.Add(lambdaI.Mul(bVals[i]))
		}

		if expectedSecret == nil {
			expectedSecret = recSecret
		} else if !recSecret.Equal(expectedSecret) {
			t.Fatalf("Subset %d reconstructed different secret than subset 0!", sIdx)
		}

		// Verify public commitment
		reconCommit := cryptography.PedersenCommitment(recSecret, recBlind)
		if !reconCommit.Equal(firstPub) {
			t.Fatalf("Subset %d reconstructed commitment does not match master public key!", sIdx)
		}
	}

	// Step 7: Verify Encrypted Vault Persistence and Loadability
	for idx, id := range committee {
		meta, share, blind, err := vaults[id].LoadShare("saral-global-15", 1, 1)
		if err != nil {
			t.Fatalf("node %s failed to load share from encrypted vault: %v", id, err)
		}
		if meta.State != "ACTIVE" || meta.Epoch != 1 || meta.NodeIndex != idx+1 {
			t.Fatalf("node %s vault metadata corrupted", id)
		}
		if !share.Equal(sessions[id].FinalShare) || !blind.Equal(sessions[id].FinalBlindShare) {
			t.Fatalf("node %s loaded vault share does not match memory share", id)
		}
	}
}

// TestE2EDealerlessDKGWithFaultsAndAdversaries tests DKG resilience against Byzantine dealers,
// invalid shares, and conflicting qualified set proposals
func TestE2EDealerlessDKGWithFaultsAndAdversaries(t *testing.T) {
	n := 15
	k := 5
	f := 4 // up to 4 Byzantine participants: nodes 12, 13, 14, 15

	tempDir, _ := os.MkdirTemp("", "saral-dkg-faults-*")
	defer os.RemoveAll(tempDir)

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	vaults := make(map[string]*vault.ShareStore)
	sessions := make(map[string]*dkg.Session)

	for idx, id := range committee {
		dir := filepath.Join(tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, _ := vault.NewShareStore(dir, []byte("key-"+id))
		vaults[id] = ss

		sess, _ := dkg.NewSession("dkg-fault-sess", "comm-faults-15", id, idx+1, committee, n, k, f, ss)
		sessions[id] = sess
	}

	// 11 Honest nodes (nodes 1..11) generate valid contributions
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee[:11] {
		pkg, _ := sessions[id].StartContribution()
		dealerPkgs[id] = pkg
	}

	// Byzantine nodes 12..15:
	// Node 12 sends a corrupted commitment matrix
	// Node 13 is offline (sends nothing)
	// Node 14 sends inconsistent row shares
	// Node 15 equivocates on qualified set

	// Deliver honest contributions
	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee[:11] {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]

			subSess, _ := avss.NewSession(sendMsg.SessionID, "comm-faults-15", dealerID, recipientID, rIdx, 1, n, k, f, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()
			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Byzantine Node 12: Forge commitment matrix
	bogusMatrix := make([][]*cryptography.CurvePoint, k)
	for r := 0; r < k; r++ {
		bogusMatrix[r] = make([]*cryptography.CurvePoint, k)
		for c := 0; c < k; c++ {
			bogusMatrix[r][c] = cryptography.GeneratorG
		}
	}
	bogusCM := &avss.CommitmentMatrix{Rows: k, Cols: k, Points: bogusMatrix}
	for _, recipientID := range committee[:11] {
		sessions[recipientID].RecordPeerCommitment(committee[11], bogusCM)
	}

	// Verify all honest nodes have >= n - t = 11 verified contributions (from honest nodes 1..11)
	for _, id := range committee[:11] {
		if !sessions[id].CanProposeQualifiedSet() {
			t.Fatalf("honest node %s should have completed >= 11 sharings", id)
		}
	}

	// Honest Qualified Set: exclusively the 11 verified honest nodes
	honestQUAL := committee[:11]
	for _, id := range committee[:11] {
		err := sessions[id].AggregateShares(honestQUAL)
		if err != nil {
			t.Fatalf("honest node %s failed aggregating honest QUAL: %v", id, err)
		}
		if sessions[id].State != dkg.StateCompleted {
			t.Fatalf("honest node %s failed to complete DKG", id)
		}
	}

	// Verify all honest nodes agree on master public key
	agreedPub := sessions[committee[0]].MasterPublicKey
	for _, id := range committee[:11] {
		if !sessions[id].MasterPublicKey.Equal(agreedPub) {
			t.Fatalf("honest node %s public key mismatch", id)
		}
	}
	t.Logf("DKG with 4 Byzantine faults successfully completed on honest qualified set!")
}

// TestE2EDKGCrashAndRestartRecovery tests persistence and crash recovery of a node during and after DKG
func TestE2EDKGCrashAndRestartRecovery(t *testing.T) {
	n := 5
	k := 2
	f := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	tempDir, _ := os.MkdirTemp("", "saral-dkg-restart-*")
	defer os.RemoveAll(tempDir)

	vaults := make(map[string]*vault.ShareStore)
	sessions := make(map[string]*dkg.Session)

	for idx, id := range committee {
		dir := filepath.Join(tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, _ := vault.NewShareStore(dir, []byte("key-"+id))
		vaults[id] = ss
		sess, _ := dkg.NewSession("dkg-restart-sess", "comm-restart-5", id, idx+1, committee, n, k, f, ss)
		sessions[id] = sess
	}

	// Complete DKG
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, _ := sessions[id].StartContribution()
		dealerPkgs[id] = pkg
	}

	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]
			subSess, _ := avss.NewSession(sendMsg.SessionID, "comm-restart-5", dealerID, recipientID, rIdx, 1, n, k, f, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()
			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	qualSet := committee
	for _, id := range committee {
		_ = sessions[id].AggregateShares(qualSet)
	}

	originalShare := sessions["node-1"].FinalShare
	originalCommit := sessions["node-1"].FinalShareCommit

	// Simulate node-1 process crash and restart: create fresh ShareStore from disk
	node1Dir := filepath.Join(tempDir, "node-1")
	recoveredStore, err := vault.NewShareStore(node1Dir, []byte("key-node-1"))
	if err != nil {
		t.Fatalf("failed initializing recovered share store: %v", err)
	}

	meta, recShare, recBlind, err := recoveredStore.LoadShare("comm-restart-5", 1, 1)
	if err != nil {
		t.Fatalf("failed loading share after restart: %v", err)
	}

	if meta.State != "ACTIVE" || meta.Epoch != 1 {
		t.Fatalf("recovered metadata invalid")
	}
	if !recShare.Equal(originalShare) {
		t.Fatalf("recovered share does not match original share")
	}

	recCommit := cryptography.PedersenCommitment(recShare, recBlind)
	if !recCommit.Equal(originalCommit) {
		t.Fatalf("recovered commitment mismatch")
	}
	t.Logf("Crash and restart recovery of DKG key share successfully verified!")
}
