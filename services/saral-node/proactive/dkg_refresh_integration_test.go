//go:build test_only

package proactive_test

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
