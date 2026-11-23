//go:build test_only

package proactive_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/proactive"
	"github.com/saral-protocol/saral-poc/services/saral-node/vault"
)

func TestValidatedByzantineAgreement(t *testing.T) {
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	n := 5
	tVal := 1
	quorum := 2*tVal + 1 // 3

	// External predicate: candidate set must contain at least quorum and elements must be in committee
	predicate := func(candidates []string) bool {
		if len(candidates) < quorum {
			return false
		}
		for _, c := range candidates {
			if avss.NodeIndexInCommittee(committee, c) == -1 {
				return false
			}
		}
		return true
	}

	instances := make(map[string]*proactive.ValidatedAgreementInstance)
	for _, id := range committee {
		instances[id] = proactive.NewValidatedAgreementInstance("comm", 2, id, committee, n, tVal, quorum, predicate)
	}

	// 1. Valid proposal from n1: candidate set of 3 nodes: [n1, n2, n3]
	prop1 := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm",
		Epoch:        2,
		ProposerID:   "n1",
		CandidateSet: []string{"n1", "n2", "n3"},
	}

	allEchos := make([]*proactive.AgreementEchoMessage, 0)
	for _, id := range committee {
		echo, err := instances[id].ProcessProposal(prop1)
		if err != nil {
			t.Fatalf("node %s rejected valid proposal: %v", id, err)
		}
		if echo != nil {
			allEchos = append(allEchos, echo)
		}
	}

	// 2. Exchange ECHOs (need >= n - t = 4 ECHOs to send READY)
	allReadys := make([]*proactive.AgreementReadyMessage, 0)
	for _, echo := range allEchos {
		for _, id := range committee {
			ready, _ := instances[id].ProcessEcho(echo)
			if ready != nil {
				allReadys = append(allReadys, ready)
			}
		}
	}

	// 3. Exchange READYs (need >= 2t + 1 = 3 READYs to decide)
	decidedCount := 0
	for _, ready := range allReadys {
		for _, id := range committee {
			decidedSet, decided, moreReady, _ := instances[id].ProcessReady(ready)
			if decided {
				decidedCount++
				if len(decidedSet) != 3 {
					t.Fatalf("node %s decided on wrong set: %v", id, decidedSet)
				}
			}
			if moreReady != nil {
				for _, otherID := range committee {
					instances[otherID].ProcessReady(moreReady)
				}
			}
		}
	}

	// All 5 nodes must have decided on the exact same proposal hash
	for _, id := range committee {
		if !instances[id].IsDecided {
			t.Fatalf("node %s failed to decide in agreement", id)
		}
		if instances[id].DecidedHash != proactive.HashCandidateSet(prop1.CandidateSet) {
			t.Fatalf("node %s decided on different hash: %s", id, instances[id].DecidedHash)
		}
	}

	// 4. Adversarial Test: Invalid proposal with < quorum must fail predicate
	badProp := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm",
		Epoch:        2,
		ProposerID:   "n4",
		CandidateSet: []string{"n1"}, // only 1 node, < 3!
	}
	newInst := proactive.NewValidatedAgreementInstance("comm", 2, "n5", committee, n, tVal, quorum, predicate)
	_, err := newInst.ProcessProposal(badProp)
	if err == nil {
		t.Fatalf("expected rejection for candidate set with < quorum")
	}
}

func TestRandomizedAgreementConflictingProposals(t *testing.T) {
	// n=5, t=1 committee with 2 conflicting valid proposals S1 and S2
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	n := 5
	tVal := 1
	quorum := 2*tVal + 1 // 3

	predicate := func(candidates []string) bool {
		return len(candidates) >= quorum
	}

	instances := make(map[string]*proactive.ValidatedAgreementInstance)
	for _, id := range committee {
		instances[id] = proactive.NewValidatedAgreementInstance("comm-conflict", 2, id, committee, n, tVal, quorum, predicate)
	}

	// Two conflicting valid proposals
	set1 := []string{"n1", "n2", "n3"}
	set2 := []string{"n2", "n3", "n4"}
	hash1 := proactive.HashCandidateSet(set1)
	hash2 := proactive.HashCandidateSet(set2)

	if hash1 == hash2 {
		t.Fatalf("conflicting sets must produce different hashes")
	}

	prop1 := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-conflict",
		Epoch:        2,
		ProposerID:   "n1",
		CandidateSet: set1,
	}
	prop2 := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-conflict",
		Epoch:        2,
		ProposerID:   "n4",
		CandidateSet: set2,
	}

	// Register proposals on all nodes
	for _, id := range committee {
		_, _ = instances[id].ProcessProposal(prop1)
		_, _ = instances[id].ProcessProposal(prop2)
	}

	// Simulate asymmetric network scheduling: n1, n2 vote for prop1; n3, n4, n5 vote for prop2
	round1Prevotes := make([]*proactive.AgreementVoteMessage, 0)
	for idx, id := range committee {
		cand := hash1
		if idx >= 2 {
			cand = hash2
		}
		vote := &proactive.AgreementVoteMessage{
			CommitteeID:   "comm-conflict",
			Epoch:         2,
			Round:         1,
			Step:          proactive.StepPreVote,
			SenderID:      id,
			CandidateHash: cand,
			VoteValue:     proactive.VoteAccept,
		}
		round1Prevotes = append(round1Prevotes, vote)
	}

	// Exchange Step 1 PRE-VOTEs across all nodes
	round1Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range committee {
		for _, pv := range round1Prevotes {
			nextVote, _, _, _, err := instances[id].ProcessVote(pv)
			if err != nil {
				t.Fatalf("node %s ProcessVote error: %v", id, err)
			}
			if nextVote != nil {
				round1Mainvotes = append(round1Mainvotes, nextVote)
			}
		}
	}

	// Exchange Step 2 MAIN-VOTEs across all nodes
	coinSharesRound1 := make([]*proactive.AgreementCoinShareMessage, 0)
	decidedCount := 0
	for _, id := range committee {
		for _, mv := range round1Mainvotes {
			nextVote, coinShareMsg, decided, _, err := instances[id].ProcessVote(mv)
			if err != nil {
				t.Fatalf("node %s ProcessVote error: %v", id, err)
			}
			if decided {
				decidedCount++
			}
			if coinShareMsg != nil {
				coinSharesRound1 = append(coinSharesRound1, coinShareMsg)
			}
			_ = nextVote
		}
	}

	// If not decided in round 1 due to split vote, exchange threshold coin shares
	if decidedCount < n {
		round2Prevotes := make([]*proactive.AgreementVoteMessage, 0)
		for _, id := range committee {
			for _, csMsg := range coinSharesRound1 {
				nextVote, decided, _, err := instances[id].ProcessCoinShare(csMsg)
				if err != nil {
					t.Fatalf("node %s ProcessCoinShare error: %v", id, err)
				}
				if decided {
					decidedCount++
				}
				if nextVote != nil {
					round2Prevotes = append(round2Prevotes, nextVote)
				}
			}
		}

		// Process Round 2 PRE-VOTEs
		round2Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
		for _, id := range committee {
			for _, pv := range round2Prevotes {
				nextVote, _, decided, _, err := instances[id].ProcessVote(pv)
				if err != nil {
					t.Fatalf("node %s ProcessVote error: %v", id, err)
				}
				if decided {
					decidedCount++
				}
				if nextVote != nil {
					round2Mainvotes = append(round2Mainvotes, nextVote)
				}
			}
		}

		// Process Round 2 MAIN-VOTEs
		for _, id := range committee {
			for _, mv := range round2Mainvotes {
				_, _, decided, _, err := instances[id].ProcessVote(mv)
				if err != nil {
					t.Fatalf("node %s ProcessVote error: %v", id, err)
				}
				if decided {
					decidedCount++
				}
			}
		}
	}

	// Verify Byzantine Agreement invariant: ALL nodes must reach decision on the exact same hash
	firstDecidedHash := ""
	for _, id := range committee {
		inst := instances[id]
		if !inst.IsDecided {
			t.Fatalf("node %s failed to decide under conflicting proposals", id)
		}
		if firstDecidedHash == "" {
			firstDecidedHash = inst.DecidedHash
		} else if inst.DecidedHash != firstDecidedHash {
			t.Fatalf("CONSENSUS SAFETY VIOLATED: node %s decided on %s, expected %s",
				id, inst.DecidedHash, firstDecidedHash)
		}
		if !predicate(inst.DecidedSet) {
			t.Fatalf("decided set failed validity predicate")
		}
	}
}

func TestByzantineEquivocationDefense(t *testing.T) {
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	n := 5
	tVal := 1
	quorum := 3

	inst := proactive.NewValidatedAgreementInstance("comm-eq", 2, "n1", committee, n, tVal, quorum, func([]string) bool { return true })

	// Honest vote from n2
	vote1 := &proactive.AgreementVoteMessage{
		CommitteeID:   "comm-eq",
		Epoch:         2,
		Round:         1,
		Step:          proactive.StepPreVote,
		SenderID:      "n2",
		CandidateHash: "hash-alpha",
		VoteValue:     proactive.VoteAccept,
	}
	_, _, _, _, err := inst.ProcessVote(vote1)
	if err != nil {
		t.Fatalf("honest vote rejected: %v", err)
	}

	// Byzantine n2 attempts to equivocate with a conflicting vote in the same round and step
	equivocatingVote := &proactive.AgreementVoteMessage{
		CommitteeID:   "comm-eq",
		Epoch:         2,
		Round:         1,
		Step:          proactive.StepPreVote,
		SenderID:      "n2",
		CandidateHash: "hash-beta", // CONFLICTING CANDIDATE!
		VoteValue:     proactive.VoteAccept,
	}
	_, _, _, _, err = inst.ProcessVote(equivocatingVote)
	if err == nil {
		t.Fatalf("expected error detecting Byzantine equivocation")
	}

	// Duplicate identical vote from n2: should be safely ignored without error
	_, _, _, _, err = inst.ProcessVote(vote1)
	if err != nil {
		t.Fatalf("duplicate identical vote should be silently ignored: %v", err)
	}
}

func TestByzantineCorruptedCoinShareDefense(t *testing.T) {
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	n := 5
	tVal := 1
	quorum := 3

	inst := proactive.NewValidatedAgreementInstance("comm-bad-coin", 2, "n1", committee, n, tVal, quorum, func([]string) bool { return true })

	// Valid coin share from n2
	validShare, err := inst.CoinKeyShare.GenerateShare(1, inst.SessionTag)
	if err != nil {
		t.Fatalf("GenerateShare failed: %v", err)
	}
	validMsg := &proactive.AgreementCoinShareMessage{
		CommitteeID: "comm-bad-coin",
		Epoch:       2,
		Round:       1,
		SenderID:    "n1",
		CoinShare:   validShare,
	}
	_, _, _, err = inst.ProcessCoinShare(validMsg)
	if err != nil {
		t.Fatalf("valid coin share failed: %v", err)
	}

	// Byzantine corrupted coin share from n3 (tampered challenge in DLEQ proof)
	corruptedShare := &cryptography.CoinShare{
		CommitteeID: validShare.CommitteeID,
		NodeID:      "n3",
		NodeIndex:   3,
		Round:       1,
		Tag:         validShare.Tag,
		SharePoint:  validShare.SharePoint,
		Proof: &cryptography.DLEQProof{
			Challenge: validShare.Proof.Challenge.Add(cryptography.NewFieldElement(1)), // TAMPERED!
			Response:  validShare.Proof.Response,
		},
	}
	corruptedMsg := &proactive.AgreementCoinShareMessage{
		CommitteeID: "comm-bad-coin",
		Epoch:       2,
		Round:       1,
		SenderID:    "n3",
		CoinShare:   corruptedShare,
	}
	_, _, _, err = inst.ProcessCoinShare(corruptedMsg)
	if err != proactive.ErrInvalidCoinShare {
		t.Fatalf("expected ErrInvalidCoinShare for tampered DLEQ proof, got: %v", err)
	}
}

func TestCompleteProactiveShareRefresh5Nodes(t *testing.T) {
	// Configuration B: n = 5, t = 1, k = 2 (k = t+1)
	tempDir, err := os.MkdirTemp("", "saral-refresh-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	n := 5
	k := 2
	tVal := 1

	masterSecret := cryptography.NewFieldElement(777888999)
	masterBlind := cryptography.NewFieldElement(111222333)

	// Step 1: Initial AVSS sharing for Epoch 1
	dealerPkg, err := avss.GenerateDealerSharing(
		"init-epoch-1", "comm-5", "node-1", 1, committee, k, masterSecret, masterBlind,
	)
	if err != nil {
		t.Fatalf("initial AVSS sharing failed: %v", err)
	}

	// Setup nodes with initial shares in vault
	vaults := make(map[string]*vault.ShareStore)
	peerCommitments := make(map[string]*cryptography.CurvePoint)
	epoch1Shares := make(map[string]*cryptography.FieldElement)
	epoch1BlindShares := make(map[string]*cryptography.FieldElement)

	for idx, id := range committee {
		nodeVault := fmt.Sprintf("%s/%s", tempDir, id)
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
			CommitteeID:            "comm-5",
			SessionID:              "init-epoch-1",
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

	// Step 2: Initialize RefreshSession on each node for Epoch 2
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for idx, id := range committee {
		rs, err := proactive.NewRefreshSession(
			"comm-5", 1, id, idx+1, committee, k, tVal,
			epoch1Shares[id], epoch1BlindShares[id], peerCommitments, dealerPkg.CommitmentMatrix.SecretCommitment(),
		)
		if err != nil {
			t.Fatalf("failed to init refresh session on %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// Step 3: Each node deals an AVSS sharing of its Epoch 1 share!
	subprotocolPkgs := make(map[string]*avss.DealerPackage)
	for _, id := range committee {
		subSessionID := fmt.Sprintf("sub-avss-dealer-%s", id)
		subPkg, err := avss.GenerateDealerSharing(
			subSessionID, "comm-5", id, 2, committee, k, epoch1Shares[id], epoch1BlindShares[id],
		)
		if err != nil {
			t.Fatalf("subprotocol AVSS failed for dealer %s: %v", id, err)
		}
		subprotocolPkgs[id] = subPkg
	}

	// Deliver all subprotocol sharings to all nodes
	for dealerID, subPkg := range subprotocolPkgs {
		for recipientID, sendMsg := range subPkg.SendMessages {
			// Recipient executes local AVSS session for dealerID's share
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sess, _ := avss.NewSession(sendMsg.SessionID, "comm-5", dealerID, recipientID, rIdx, 2, n, k, tVal, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()

			// Register completed subprotocol sharing into recipient's refresh session
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, sess)
		}
	}

	// Step 4: Validated Byzantine Agreement on Candidate Set of Completed Sharings
	agreedSet := []string{"node-1", "node-2", "node-3"}
	prop := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-5",
		Epoch:        2,
		ProposerID:   "node-1",
		CandidateSet: agreedSet,
	}

	allEchos := make([]*proactive.AgreementEchoMessage, 0)
	for _, id := range committee {
		echo, err := refreshSessions[id].Agreement.ProcessProposal(prop)
		if err != nil {
			t.Fatalf("node %s rejected proposal: %v", id, err)
		}
		if echo != nil {
			allEchos = append(allEchos, echo)
		}
	}

	allReadys := make([]*proactive.AgreementReadyMessage, 0)
	for _, echo := range allEchos {
		for _, id := range committee {
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

	// Step 5: Compute New Refreshed Shares for Epoch 2 on all nodes
	epoch2Shares := make(map[string]*cryptography.FieldElement)
	epoch2BlindShares := make(map[string]*cryptography.FieldElement)

	for _, id := range committee {
		rs := refreshSessions[id]
		if !rs.Agreement.IsDecided {
			t.Fatalf("node %s did not reach agreement", id)
		}
		err := rs.ComputeNewShare(rs.Agreement.DecidedSet, vaults[id])
		if err != nil {
			t.Fatalf("node %s failed to compute new share: %v", id, err)
		}

		epoch2Shares[id] = rs.NewShare
		epoch2BlindShares[id] = rs.NewBlindShare

		// Property 1: New share != Old share
		if rs.NewShare.Equal(epoch1Shares[id]) {
			t.Fatalf("node %s: newly refreshed share identical to old share!", id)
		}

		// Property 2: Old share in memory is zeroed out
		if rs.OldShare != nil {
			t.Fatalf("node %s: old share was not erased from memory", id)
		}

		// Property 3: Stale Epoch 1 share cannot be loaded from vault
		_, _, _, err = vaults[id].LoadShare("comm-5", 1, 2)
		if err == nil {
			t.Fatalf("node %s: loading stale epoch 1 share should be rejected!", id)
		}
	}

	// Step 6: Mathematical Invariance Proof — Reconstruct secret from Epoch 2 shares!
	// Take any k=2 shares from Epoch 2 (e.g. node-3 and node-5)
	reconSharesEpoch2 := []*avss.ReconstructionShare{
		{
			NodeID:     "node-3",
			NodeIndex:  3,
			Share:      epoch2Shares["node-3"],
			BlindShare: epoch2BlindShares["node-3"],
		},
		{
			NodeID:     "node-5",
			NodeIndex:  5,
			Share:      epoch2Shares["node-5"],
			BlindShare: epoch2BlindShares["node-5"],
		},
	}
	_ = reconSharesEpoch2

	// Compute Lagrange reconstruction of secret from Epoch 2 shares
	xTarget := cryptography.NewFieldElement(0)
	x3 := cryptography.NewFieldElement(3)
	x5 := cryptography.NewFieldElement(5)
	allX := []*cryptography.FieldElement{x3, x5}

	l3, _ := cryptography.LagrangeCoefficient(xTarget, x3, allX)
	l5, _ := cryptography.LagrangeCoefficient(xTarget, x5, allX)

	recoveredSecret := l3.Mul(epoch2Shares["node-3"]).Add(l5.Mul(epoch2Shares["node-5"]))
	recoveredBlind := l3.Mul(epoch2BlindShares["node-3"]).Add(l5.Mul(epoch2BlindShares["node-5"]))

	// The reconstructed secret MUST EXACTLY EQUAL the original master secret!
	if !recoveredSecret.Equal(masterSecret) {
		t.Fatalf("REFRESH MATHEMATICAL INVARIANCE BROKEN: recovered %s, want original %s",
			recoveredSecret.Hex(), masterSecret.Hex())
	}
	if !recoveredBlind.Equal(masterBlind) {
		t.Fatalf("recovered blind secret mismatch")
	}

	// Verify public commitment invariance: Commit(s, s') == C_{0, 0}
	reconCommit := cryptography.PedersenCommitment(recoveredSecret, recoveredBlind)
	if !reconCommit.Equal(dealerPkg.CommitmentMatrix.SecretCommitment()) {
		t.Fatalf("public secret commitment changed after refresh!")
	}
}
