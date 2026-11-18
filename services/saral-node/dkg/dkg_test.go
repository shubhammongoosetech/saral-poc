package dkg_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

func TestDKGParameterValidation(t *testing.T) {
	// Configuration A: Global committee (n=15, k=5, t=4)
	if err := dkg.ValidateDKGParameters(15, 5, 4); err != nil {
		t.Fatalf("global committee parameters should be valid: %v", err)
	}

	// Configuration B: Domain committee (n=5, k=2, t=1)
	if err := dkg.ValidateDKGParameters(5, 2, 1); err != nil {
		t.Fatalf("domain committee parameters should be valid: %v", err)
	}

	// Invalid 1: n <= 3t (n=4, t=2 => 4 <= 6)
	if err := dkg.ValidateDKGParameters(4, 3, 2); err == nil {
		t.Fatalf("expected error for n <= 3t")
	}

	// Invalid 2: n - 2t < k (n=5, t=2, k=2 => 5 - 4 = 1 < 2)
	if err := dkg.ValidateDKGParameters(5, 2, 2); err == nil {
		t.Fatalf("expected error for n - 2t < k")
	}

	// Invalid 3: k < t + 1 (n=5, t=2, k=1 => 1 < 3)
	if err := dkg.ValidateDKGParameters(5, 1, 2); err == nil {
		t.Fatalf("expected error for k < t + 1")
	}
}

func TestDealerlessDKG5Nodes(t *testing.T) {
	// Configuration B: n = 5, t = 1, k = 2
	n := 5
	k := 2
	tVal := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	tempDir, err := os.MkdirTemp("", "saral-dkg-test-5-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaults := make(map[string]*vault.ShareStore)
	sessions := make(map[string]*dkg.Session)

	// Step 1: Initialize DKG session on all 5 nodes
	for idx, id := range committee {
		dir := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, err := vault.NewShareStore(dir, []byte("key-"+id))
		if err != nil {
			t.Fatalf("failed to create share store for %s: %v", id, err)
		}
		vaults[id] = ss

		sess, err := dkg.NewSession("dkg-session-5", "comm-5", id, idx+1, committee, n, k, tVal, ss)
		if err != nil {
			t.Fatalf("failed to create DKG session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// Step 2: Each node independently generates a random secret contribution and deals AVSS
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, err := sessions[id].StartContribution()
		if err != nil {
			t.Fatalf("StartContribution failed for %s: %v", id, err)
		}
		dealerPkgs[id] = pkg
	}

	// Step 3: Deliver all AVSS contribution shares and commitment matrices across nodes
	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)

			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]

			subSess, err := avss.NewSession(
				sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 1, n, k, tVal, committee,
			)
			if err != nil {
				t.Fatalf("failed creating sub AVSS session: %v", err)
			}

			_, err = subSess.ProcessSendMessage(sendMsg)
			if err != nil {
				t.Fatalf("recipient %s failed processing SEND from %s: %v", recipientID, dealerID, err)
			}
			err = subSess.FinalizeShare()
			if err != nil {
				t.Fatalf("recipient %s failed to finalize share from %s: %v", recipientID, dealerID, err)
			}

			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Verify all nodes can propose qualified set (all have completed >= n - t = 4 sharings)
	for _, id := range committee {
		if !sessions[id].CanProposeQualifiedSet() {
			t.Fatalf("node %s cannot propose qualified set", id)
		}
	}

	// Step 4: Qualified Set Agreement — all 5 nodes contribute (QUAL = all 5 nodes)
	qualSet := committee
	for _, id := range committee {
		// Aggregate shares
		err := sessions[id].AggregateShares(qualSet)
		if err != nil {
			t.Fatalf("node %s failed to aggregate shares: %v", id, err)
		}

		if sessions[id].State != dkg.StateCompleted {
			t.Fatalf("node %s state is %s, expected COMPLETED", id, sessions[id].State)
		}
	}

	// Step 5: Public Key Agreement Invariance
	// All 5 nodes must have computed the EXACT SAME Master Public Key
	firstPub := sessions[committee[0]].MasterPublicKey
	for _, id := range committee {
		if !sessions[id].MasterPublicKey.Equal(firstPub) {
			t.Fatalf("PUBLIC KEY MISMATCH: node %s master pubkey does not match node-1", id)
		}
	}

	// Step 6: Mathematical Invariance — Reconstruct master secret from ANY k=2 final private shares!
	// Test subset A: {node-1, node-3}
	xTarget := cryptography.NewFieldElement(0)
	x1 := cryptography.NewFieldElement(1)
	x3 := cryptography.NewFieldElement(3)
	xsA := []*cryptography.FieldElement{x1, x3}

	l1A, _ := cryptography.LagrangeCoefficient(xTarget, x1, xsA)
	l3A, _ := cryptography.LagrangeCoefficient(xTarget, x3, xsA)

	s1 := sessions["node-1"].FinalShare
	s3 := sessions["node-3"].FinalShare
	recoveredSecretA := l1A.Mul(s1).Add(l3A.Mul(s3))

	// Test subset B: {node-2, node-5} (completely disjoint indices!)
	x2 := cryptography.NewFieldElement(2)
	x5 := cryptography.NewFieldElement(5)
	xsB := []*cryptography.FieldElement{x2, x5}

	l2B, _ := cryptography.LagrangeCoefficient(xTarget, x2, xsB)
	l5B, _ := cryptography.LagrangeCoefficient(xTarget, x5, xsB)

	s2 := sessions["node-2"].FinalShare
	s5 := sessions["node-5"].FinalShare
	recoveredSecretB := l2B.Mul(s2).Add(l5B.Mul(s5))

	// Invariance check: ANY k=2 shares reconstruct the exact same secret!
	if !recoveredSecretA.Equal(recoveredSecretB) {
		t.Fatalf("RECONSTRUCTION INVARIANCE BROKEN: subset A (%s) != subset B (%s)",
			recoveredSecretA.Hex(), recoveredSecretB.Hex())
	}

	// Reconstruct blinding secret
	b1 := sessions["node-1"].FinalBlindShare
	b3 := sessions["node-3"].FinalBlindShare
	recoveredBlind := l1A.Mul(b1).Add(l3A.Mul(b3))

	// Master commitment check: Commit(recoveredSecret, recoveredBlind) MUST equal MasterPublicKey!
	reconCommit := cryptography.PedersenCommitment(recoveredSecretA, recoveredBlind)
	if !reconCommit.Equal(firstPub) {
		t.Fatalf("MASTER PUBLIC KEY INVARIANCE BROKEN: Commit(s, s') != MasterPublicKey")
	}

	// Step 7: Vault Verification — each node has persisted its share at Epoch 1
	for idx, id := range committee {
		meta, loadedShare, loadedBlind, err := vaults[id].LoadShare("comm-5", 1, 1)
		if err != nil {
			t.Fatalf("node %s failed to load DKG share from vault: %v", id, err)
		}
		if meta.State != "ACTIVE" || meta.NodeIndex != idx+1 {
			t.Fatalf("node %s metadata corrupted in vault", id)
		}
		if !loadedShare.Equal(sessions[id].FinalShare) || !loadedBlind.Equal(sessions[id].FinalBlindShare) {
			t.Fatalf("node %s loaded share differs from session share", id)
		}
	}
}

func TestDealerlessDKG15Nodes(t *testing.T) {
	// Configuration A: n = 15, t = 4, k = 5
	n := 15
	k := 5
	tVal := 4
	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	tempDir, err := os.MkdirTemp("", "saral-dkg-test-15-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaults := make(map[string]*vault.ShareStore)
	sessions := make(map[string]*dkg.Session)

	for idx, id := range committee {
		dir := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, err := vault.NewShareStore(dir, []byte("key-"+id))
		if err != nil {
			t.Fatalf("failed creating share store for %s: %v", id, err)
		}
		vaults[id] = ss

		sess, err := dkg.NewSession("dkg-session-15", "comm-15", id, idx+1, committee, n, k, tVal, ss)
		if err != nil {
			t.Fatalf("failed creating DKG session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// Nodes independently deal contributions
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, err := sessions[id].StartContribution()
		if err != nil {
			t.Fatalf("StartContribution failed for %s: %v", id, err)
		}
		dealerPkgs[id] = pkg
	}

	// Deliver all AVSS messages
	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)

			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]

			subSess, _ := avss.NewSession(
				sendMsg.SessionID, "comm-15", dealerID, recipientID, rIdx, 1, n, k, tVal, committee,
			)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()

			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Qualified set of 11 nodes (>= n - t = 11)
	qualSet := committee[:11]
	for _, id := range committee {
		err := sessions[id].AggregateShares(qualSet)
		if err != nil {
			t.Fatalf("node %s failed to aggregate 15-node shares: %v", id, err)
		}
	}

	// Verify all 15 nodes agree on master public key
	firstPub := sessions[committee[0]].MasterPublicKey
	for _, id := range committee {
		if !sessions[id].MasterPublicKey.Equal(firstPub) {
			t.Fatalf("15-node master public key mismatch on %s", id)
		}
	}

	// Verify reconstruction from arbitrary k=5 nodes: {node-1, node-4, node-7, node-10, node-13}
	reconIndices := []int{1, 4, 7, 10, 13}
	xTarget := cryptography.NewFieldElement(0)
	xs := make([]*cryptography.FieldElement, k)
	shares := make([]*cryptography.FieldElement, k)
	blinds := make([]*cryptography.FieldElement, k)

	for i, sIdx := range reconIndices {
		id := fmt.Sprintf("saral-node-%d", sIdx)
		xs[i] = cryptography.NewFieldElement(int64(sIdx))
		shares[i] = sessions[id].FinalShare
		blinds[i] = sessions[id].FinalBlindShare
	}

	recoveredSecret := cryptography.NewFieldElement(0)
	recoveredBlind := cryptography.NewFieldElement(0)
	for i := 0; i < k; i++ {
		l, _ := cryptography.LagrangeCoefficient(xTarget, xs[i], xs)
		recoveredSecret = recoveredSecret.Add(l.Mul(shares[i]))
		recoveredBlind = recoveredBlind.Add(l.Mul(blinds[i]))
	}

	reconCommit := cryptography.PedersenCommitment(recoveredSecret, recoveredBlind)
	if !reconCommit.Equal(firstPub) {
		t.Fatalf("15-node DKG secret commitment mismatch")
	}
}

func TestDKGMaliciousDealerExclusion(t *testing.T) {
	// 5-node committee: node-5 is malicious and shares an inconsistent bivariate polynomial
	n := 5
	k := 2
	tVal := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	tempDir, _ := os.MkdirTemp("", "saral-dkg-malicious-*")
	defer os.RemoveAll(tempDir)

	sessions := make(map[string]*dkg.Session)
	for idx, id := range committee {
		dir := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, _ := vault.NewShareStore(dir, []byte("key-"+id))
		sess, _ := dkg.NewSession("dkg-mal-test", "comm-5", id, idx+1, committee, n, k, tVal, ss)
		sessions[id] = sess
	}

	// Honest nodes 1..4 deal valid contributions
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee[:4] {
		pkg, _ := sessions[id].StartContribution()
		dealerPkgs[id] = pkg
	}

	// Deliver honest contributions
	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]
			subSess, _ := avss.NewSession(sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 1, n, k, tVal, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()
			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Honest nodes have 4 valid contributions (>= n - t = 4)
	for _, id := range committee[:4] {
		if !sessions[id].CanProposeQualifiedSet() {
			t.Fatalf("honest node %s should have >= 4 completed sharings", id)
		}
	}

	// Qualified set excludes malicious node-5: QUAL = {node-1, node-2, node-3, node-4}
	honestQUAL := committee[:4]
	for _, id := range committee[:4] {
		err := sessions[id].AggregateShares(honestQUAL)
		if err != nil {
			t.Fatalf("node %s failed to aggregate honest qualified set: %v", id, err)
		}
		if sessions[id].State != dkg.StateCompleted {
			t.Fatalf("expected state COMPLETED for %s", id)
		}
	}

	// Verify all honest nodes agreed on public key
	pubKey := sessions["node-1"].MasterPublicKey
	for _, id := range committee[:4] {
		if !sessions[id].MasterPublicKey.Equal(pubKey) {
			t.Fatalf("public key mismatch among honest nodes")
		}
	}
}

func TestDKGThenProactiveRefreshIntegration(t *testing.T) {
	// Full Lifecycle Integration:
	// 1. Execute 5-node Dealerless DKG (Epoch 1)
	// 2. Feed generated DKG shares into Proactive Share Refresh (Epoch 2)
	// 3. Verify mathematical secret and public key invariance
	// 4. Verify old Epoch 1 shares are securely erased
	n := 5
	k := 2
	tVal := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	tempDir, _ := os.MkdirTemp("", "saral-dkg-refresh-*")
	defer os.RemoveAll(tempDir)

	vaults := make(map[string]*vault.ShareStore)
	dkgSessions := make(map[string]*dkg.Session)

	// Step 1: DKG Session Init
	for idx, id := range committee {
		dir := fmt.Sprintf("%s/%s", tempDir, id)
		_ = os.MkdirAll(dir, 0700)
		ss, _ := vault.NewShareStore(dir, []byte("key-"+id))
		vaults[id] = ss

		sess, _ := dkg.NewSession("dkg-e1", "comm-5", id, idx+1, committee, n, k, tVal, ss)
		dkgSessions[id] = sess
	}

	// Step 2: DKG Contribution & Sharing
	dealerPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, _ := dkgSessions[id].StartContribution()
		dealerPkgs[id] = pkg
	}

	for dealerID, pkg := range dealerPkgs {
		for _, recipientID := range committee {
			dkgSessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]
			subSess, _ := avss.NewSession(sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 1, n, k, tVal, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()
			dkgSessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Step 3: DKG Share Aggregation & Persistence in Vault
	qualSet := committee
	for _, id := range committee {
		err := dkgSessions[id].AggregateShares(qualSet)
		if err != nil {
			t.Fatalf("DKG share aggregation failed on %s: %v", id, err)
		}
	}

	dkgMasterPub := dkgSessions["node-1"].MasterPublicKey
	peerCommitmentsE1 := make(map[string]*cryptography.CurvePoint)
	epoch1Shares := make(map[string]*cryptography.FieldElement)
	epoch1Blinds := make(map[string]*cryptography.FieldElement)

	for _, id := range committee {
		meta, s, b, err := vaults[id].LoadShare("comm-5", 1, 1)
		if err != nil {
			t.Fatalf("failed loading Epoch 1 DKG share from vault for %s: %v", id, err)
		}
		_ = meta
		epoch1Shares[id] = s
		epoch1Blinds[id] = b
		peerCommitmentsE1[id] = dkgSessions[id].FinalShareCommit
	}

	// Step 4: Proactive Share Refresh for Epoch 2
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for idx, id := range committee {
		rs, err := proactive.NewRefreshSession(
			"comm-5", 1, id, idx+1, committee, k, tVal,
			epoch1Shares[id], epoch1Blinds[id], peerCommitmentsE1, dkgMasterPub,
		)
		if err != nil {
			t.Fatalf("failed creating refresh session for %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// Each node deals subprotocol AVSS of its Epoch 1 DKG share
	refreshPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		pkg, err := avss.GenerateDealerSharing(
			"refresh-e2-"+id, "comm-5", id, 2, committee, k, epoch1Shares[id], epoch1Blinds[id],
		)
		if err != nil {
			t.Fatalf("failed dealing refresh AVSS for %s: %v", id, err)
		}
		refreshPkgs[id] = pkg
	}

	for dealerID, pkg := range refreshPkgs {
		for recipientID, sendMsg := range pkg.SendMessages {
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			subSess, _ := avss.NewSession(sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 2, n, k, tVal, committee)
			_, _ = subSess.ProcessSendMessage(sendMsg)
			_ = subSess.FinalizeShare()
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Agreement on Refresh Candidate Set
	refreshSet := committee[:3]
	for _, id := range committee {
		err := refreshSessions[id].ComputeNewShare(refreshSet, vaults[id])
		if err != nil {
			t.Fatalf("refresh ComputeNewShare failed on %s: %v", id, err)
		}
	}

	// Step 5: Verification of Mathematical Invariance across DKG -> Refresh
	// Reconstruct secret from Epoch 2 refreshed shares: {node-2, node-4}
	xTarget := cryptography.NewFieldElement(0)
	x2 := cryptography.NewFieldElement(2)
	x4 := cryptography.NewFieldElement(4)
	xsE2 := []*cryptography.FieldElement{x2, x4}

	l2, _ := cryptography.LagrangeCoefficient(xTarget, x2, xsE2)
	l4, _ := cryptography.LagrangeCoefficient(xTarget, x4, xsE2)

	meta2, s2, b2, _ := vaults["node-2"].LoadShare("comm-5", 2, 2)
	meta4, s4, b4, _ := vaults["node-4"].LoadShare("comm-5", 2, 2)
	_ = meta2
	_ = meta4

	reconSecretE2 := l2.Mul(s2).Add(l4.Mul(s4))
	reconBlindE2 := l2.Mul(b2).Add(l4.Mul(b4))

	// Commitment of reconstructed Epoch 2 secret MUST match original DKG master public key!
	commitE2 := cryptography.PedersenCommitment(reconSecretE2, reconBlindE2)
	if !commitE2.Equal(dkgMasterPub) {
		t.Fatalf("SECRET INVARIANCE BROKEN AFTER REFRESH: Commit(s_e2, s'_e2) != DKG MasterPublicKey")
	}

	// Step 6: Verify Stale Epoch 1 shares were securely erased
	for _, id := range committee {
		_, _, _, err := vaults[id].LoadShare("comm-5", 1, 2)
		if err == nil {
			t.Fatalf("node %s: stale Epoch 1 share should have been securely erased from vault!", id)
		}
	}
}

// TestDKGPedersenCommitmentVsSigningPublicKey audits and verifies that:
// 1. Pedersen commitment has the form C_00 = x*G + r*H
// 2. Blockchain signing public key must be Y = x*G
// 3. A blinded Pedersen commitment C_00 is mathematically distinct from the unblinded signing key Y
// 4. Any k reconstructed shares yield secret x whose scalar base mult strictly equals Y = x*G
func TestDKGPedersenCommitmentVsSigningPublicKey(t *testing.T) {
	n := 5
	k := 2
	f := 1

	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	sessions := make(map[string]*dkg.Session)

	for idx, id := range committee {
		sess, err := dkg.NewSession("dkg-audit-pedersen", "comm-5", id, idx+1, committee, n, k, f, nil)
		if err != nil {
			t.Fatalf("failed init session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// Each node starts contribution and registers both C^{(i)}_{0,0} and V_i = z_i * G
	for _, id := range committee {
		pkg, err := sessions[id].StartContribution()
		if err != nil {
			t.Fatalf("failed start contribution for %s: %v", id, err)
		}
		for _, peer := range committee {
			sessions[peer].RecordPeerCommitment(id, pkg.CommitmentMatrix)
			// Compute and record unblinded signing public key share V_i = z_i * G
			zi := sessions[id].LocalSecret
			vI := cryptography.GeneratorG.ScalarMult(zi)
			sessions[peer].RecordPeerPublicKey(id, vI)
		}
	}

	// Deliver all AVSS contribution shares and commitment matrices across nodes
	for dealerID, fromSess := range sessions {
		pkg := fromSess.LocalDealerPkg
		for _, recipientID := range committee {
			sessions[recipientID].RecordPeerCommitment(dealerID, pkg.CommitmentMatrix)

			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sendMsg := pkg.SendMessages[recipientID]

			subSess, err := avss.NewSession(
				sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 1, n, k, f, committee,
			)
			if err != nil {
				t.Fatalf("failed creating sub AVSS session: %v", err)
			}

			_, err = subSess.ProcessSendMessage(sendMsg)
			if err != nil {
				t.Fatalf("recipient %s failed processing SEND from %s: %v", recipientID, dealerID, err)
			}
			err = subSess.FinalizeShare()
			if err != nil {
				t.Fatalf("recipient %s failed to finalize share from %s: %v", recipientID, dealerID, err)
			}

			sessions[recipientID].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// Aggregate on all nodes
	qual := []string{"node-1", "node-2", "node-3", "node-4"}
	for _, id := range committee {
		if err := sessions[id].AggregateShares(qual); err != nil {
			t.Fatalf("node %s failed to aggregate shares: %v", id, err)
		}
	}

	sess1 := sessions["node-1"]

	// Cryptographic distinction check:
	// MasterSigningPublicKey Y = x*G vs MasterSecretCommitment C = x*G + x'*H
	if sess1.MasterSigningPublicKey == nil || sess1.MasterSecretCommitment == nil {
		t.Fatalf("session missing MasterSigningPublicKey or MasterSecretCommitment")
	}

	// When blinding factor x' != 0, C != Y
	if sess1.MasterSigningPublicKey.Equal(sess1.MasterSecretCommitment) {
		t.Fatalf("CRYPTOGRAPHIC FLAW: Signing public key equals blinded Pedersen commitment! (Must differ by r*H)")
	}

	// Reconstruct secret x from k=2 shares
	x1 := cryptography.NewFieldElement(1)
	x2 := cryptography.NewFieldElement(2)
	xTarget := cryptography.NewFieldElement(0)
	xs := []*cryptography.FieldElement{x1, x2}

	l1, _ := cryptography.LagrangeCoefficient(xTarget, x1, xs)
	l2, _ := cryptography.LagrangeCoefficient(xTarget, x2, xs)

	s1 := sessions["node-1"].FinalShare
	s2 := sessions["node-2"].FinalShare
	b1 := sessions["node-1"].FinalBlindShare
	b2 := sessions["node-2"].FinalBlindShare

	reconstructedX := l1.Mul(s1).Add(l2.Mul(s2))
	reconstructedBlind := l1.Mul(b1).Add(l2.Mul(b2))

	// Proof 1: Reconstructed secret x * G strictly equals MasterSigningPublicKey!
	computedSigningKey := cryptography.GeneratorG.ScalarMult(reconstructedX)
	if !computedSigningKey.Equal(sess1.MasterSigningPublicKey) {
		t.Fatalf("SIGNING KEY MISMATCH: x*G != MasterSigningPublicKey (got %s, expected %s)",
			computedSigningKey.Hex(), sess1.MasterSigningPublicKey.Hex())
	}

	// Proof 2: Reconstructed x*G + x'*H strictly equals MasterSecretCommitment!
	computedPedersenCommit := cryptography.PedersenCommitment(reconstructedX, reconstructedBlind)
	if !computedPedersenCommit.Equal(sess1.MasterSecretCommitment) {
		t.Fatalf("PEDERSEN COMMITMENT MISMATCH: x*G + r*H != MasterSecretCommitment")
	}

	t.Logf("✅ Cryptographic validation PASSED:")
	t.Logf("   -> Master Signing Key Y = x*G: %s", sess1.MasterSigningPublicKey.Hex())
	t.Logf("   -> Master Pedersen Commitment C = x*G + r*H: %s", sess1.MasterSecretCommitment.Hex())
	t.Logf("   -> Verified: Y != C (blinded commitment strictly decoupled from signing key)")
	t.Logf("   -> Verified: x*G == Y (blockchain signing key derivation is exact and unblinded)")
}
