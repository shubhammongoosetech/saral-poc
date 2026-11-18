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

func TestProactiveRefresh15NodeCommittee(t *testing.T) {
	// Configuration A: n = 15, t = 4, k = 5 (k = t+1, n > 3t)
	tempDir, err := os.MkdirTemp("", "saral-proactive-15-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	committee := make([]string, 15)
	for i := 0; i < 15; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}
	n := 15
	k := 5
	tVal := 4

	masterSecret := cryptography.NewFieldElement(1234567890)
	masterBlind := cryptography.NewFieldElement(9876543210)

	// Step 1: Dealer shares secret for Epoch 1
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

	// Step 2: Initialize RefreshSessions for all 15 nodes for Epoch 2
	refreshSessions := make(map[string]*proactive.RefreshSession)
	for idx, id := range committee {
		rs, err := proactive.NewRefreshSession(
			"committee-15", 1, id, idx+1, committee, k, tVal,
			epoch1Shares[id], epoch1BlindShares[id], peerCommitments, dealerPkg.CommitmentMatrix.SecretCommitment(),
		)
		if err != nil {
			t.Fatalf("failed init refresh session on %s: %v", id, err)
		}
		refreshSessions[id] = rs
	}

	// Step 3: Each of the 15 nodes deals an AVSS subprotocol sharing its Epoch 1 share
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

	// Deliver all subprotocol messages to all nodes
	for dealerID, subPkg := range subprotocolPkgs {
		for recipientID, sendMsg := range subPkg.SendMessages {
			rIdx := avss.NodeIndexInCommittee(committee, recipientID)
			sess, _ := avss.NewSession(sendMsg.SessionID, "committee-15", dealerID, recipientID, rIdx, 2, n, k, tVal, committee)
			_, _ = sess.ProcessSendMessage(sendMsg)
			_ = sess.FinalizeShare()
			refreshSessions[recipientID].RecordCompletedSharing(dealerID, sess)
		}
	}

	// Step 4: Validated Byzantine Agreement on Candidate Set
	// Candidate set of size 2t + 1 = 9 nodes
	agreedSet := make([]string, 2*tVal+1)
	for i := 0; i < 2*tVal+1; i++ {
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

	// Step 5: Compute New Refreshed Shares for Epoch 2 on all 15 nodes
	epoch2Shares := make(map[string]*cryptography.FieldElement)
	epoch2BlindShares := make(map[string]*cryptography.FieldElement)

	for _, id := range committee {
		rs := refreshSessions[id]
		if !rs.Agreement.IsDecided {
			t.Fatalf("node %s did not reach agreement", id)
		}
		if err := rs.ComputeNewShare(rs.Agreement.DecidedSet, vaults[id]); err != nil {
			t.Fatalf("node %s failed computing new share: %v", id, err)
		}

		epoch2Shares[id] = rs.NewShare
		epoch2BlindShares[id] = rs.NewBlindShare

		// 1. New share != Old share
		if rs.NewShare.Equal(epoch1Shares[id]) {
			t.Fatalf("node %s refreshed share identical to old share", id)
		}

		// 2. Stale epoch 1 share rejected
		_, _, _, err = vaults[id].LoadShare("committee-15", 1, 2)
		if err == nil {
			t.Fatalf("node %s loaded stale epoch 1 share", id)
		}
	}

	// Step 6: Mathematical Invariance Test — Reconstruct secret using arbitrary k=5 nodes from Epoch 2
	reconIndices := []int{1, 4, 7, 10, 13}
	xTarget := cryptography.NewFieldElement(0)
	xCoords := make([]*cryptography.FieldElement, k)
	yShares := make([]*cryptography.FieldElement, k)
	yBlinds := make([]*cryptography.FieldElement, k)

	for idx, sIdx := range reconIndices {
		id := fmt.Sprintf("saral-node-%d", sIdx)
		xCoords[idx] = cryptography.NewFieldElement(int64(sIdx))
		yShares[idx] = epoch2Shares[id]
		yBlinds[idx] = epoch2BlindShares[id]
	}

	recoveredSecret := cryptography.NewFieldElement(0)
	recoveredBlind := cryptography.NewFieldElement(0)
	for i := 0; i < k; i++ {
		lambda, err := cryptography.LagrangeCoefficient(xTarget, xCoords[i], xCoords)
		if err != nil {
			t.Fatalf("failed lagrange coeff: %v", err)
		}
		recoveredSecret = recoveredSecret.Add(lambda.Mul(yShares[i]))
		recoveredBlind = recoveredBlind.Add(lambda.Mul(yBlinds[i]))
	}

	// Mathematical Invariance Assertion:
	if !recoveredSecret.Equal(masterSecret) {
		t.Fatalf("15-node refresh failed: recovered %s != original %s",
			recoveredSecret.Hex(), masterSecret.Hex())
	}
	if !recoveredBlind.Equal(masterBlind) {
		t.Fatalf("recovered blind secret mismatch")
	}

	// Verify public commitment invariance
	reconCommit := cryptography.PedersenCommitment(recoveredSecret, recoveredBlind)
	if !reconCommit.Equal(dealerPkg.CommitmentMatrix.SecretCommitment()) {
		t.Fatalf("master public commitment changed across proactive refresh")
	}
}

func TestAdversarialMaliciousRefreshDealer(t *testing.T) {
	// Adversarial test: Malicious participant shares a bogus secret instead of its true share
	// The external validity predicate of Validated Agreement MUST detect the mismatch and REJECT it!
	committee := []string{"n1", "n2", "n3", "n4", "n5"}
	k := 2
	tVal := 1

	trueShare := cryptography.NewFieldElement(55555)
	trueBlind := cryptography.NewFieldElement(11111)
	trueQ := cryptography.PedersenCommitment(trueShare, trueBlind)

	peerCommitments := map[string]*cryptography.CurvePoint{
		"n1": trueQ,
	}

	rs, _ := proactive.NewRefreshSession(
		"comm", 1, "n2", 2, committee, k, tVal,
		cryptography.NewFieldElement(666), cryptography.NewFieldElement(777),
		peerCommitments, cryptography.PedersenCommitment(cryptography.NewFieldElement(1), cryptography.NewFieldElement(2)),
	)

	// Malicious dealer n1 shares a BOGUS secret: 99999 != 55555
	bogusSecret := cryptography.NewFieldElement(99999)
	bogusPkg, _ := avss.GenerateDealerSharing("sub-bogus", "comm", "n1", 2, committee, k, bogusSecret, trueBlind)

	// Node n2 processes the sharing
	sess, _ := avss.NewSession("sub-bogus", "comm", "n1", "n2", 2, 2, 5, 2, 1, committee)
	_, _ = sess.ProcessSendMessage(bogusPkg.SendMessages["n2"])
	_ = sess.FinalizeShare()

	// Register in refresh session
	rs.RecordCompletedSharing("n1", sess)

	// Attempt agreement proposal containing malicious dealer n1
	prop := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm",
		Epoch:        2,
		ProposerID:   "n1",
		CandidateSet: []string{"n1", "n2", "n3"},
	}

	// The predicate check MUST FAIL because C^{(n1)}_{0,0} = Commit(99999) != trueQ = Commit(55555)!
	_, err := rs.Agreement.ProcessProposal(prop)
	if err == nil {
		t.Fatalf("adversarial proposal with forged share should have failed predicate verification!")
	}
}

func TestRandomizedAgreement15NodesWithConflictingProposalsAndByzantineFaults(t *testing.T) {
	n := 15
	tVal := 4 // up to 4 Byzantine participants
	quorum := 2*tVal + 1 // 9

	committee := make([]string, n)
	for i := 0; i < n; i++ {
		committee[i] = fmt.Sprintf("saral-node-%d", i+1)
	}

	predicate := func(candidates []string) bool {
		return len(candidates) >= quorum
	}

	instances := make(map[string]*proactive.ValidatedAgreementInstance)
	for _, id := range committee {
		instances[id] = proactive.NewValidatedAgreementInstance("comm-15-integ", 2, id, committee, n, tVal, quorum, predicate)
	}

	// Honest Proposal A from saral-node-1 (size 9: nodes 1..9)
	setA := committee[:9]
	hashA := proactive.HashCandidateSet(setA)
	propA := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-15-integ",
		Epoch:        2,
		ProposerID:   committee[0],
		CandidateSet: setA,
	}

	// Honest Proposal B from saral-node-5 (size 9: nodes 2..10)
	setB := committee[1:10]
	hashB := proactive.HashCandidateSet(setB)
	propB := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-15-integ",
		Epoch:        2,
		ProposerID:   committee[4],
		CandidateSet: setB,
	}

	// Malicious Proposal from Byzantine saral-node-12 (< quorum 9)
	setBad := committee[:5]
	propBad := &proactive.AgreementProposeMessage{
		CommitteeID:  "comm-15-integ",
		Epoch:        2,
		ProposerID:   committee[11],
		CandidateSet: setBad,
	}

	// 1. Verify honest nodes strictly reject the undersized Byzantine proposal
	_, err := instances[committee[0]].ProcessProposal(propBad)
	if err == nil {
		t.Fatalf("honest node accepted invalid proposal from Byzantine participant")
	}

	// 2. Deliver valid proposals A and B to honest nodes
	honestNodes := committee[:11] // 11 honest nodes (n - t = 15 - 4 = 11)
	for _, id := range honestNodes {
		_, _ = instances[id].ProcessProposal(propA)
		_, _ = instances[id].ProcessProposal(propB)
	}

	// 3. Round 1: Asymmetric PRE-VOTEs (honest nodes split: 5 vote for A, 6 vote for B)
	round1Prevotes := make([]*proactive.AgreementVoteMessage, 0)
	for idx, id := range honestNodes {
		cand := hashA
		if idx >= 5 {
			cand = hashB
		}
		round1Prevotes = append(round1Prevotes, &proactive.AgreementVoteMessage{
			CommitteeID:   "comm-15-integ",
			Epoch:         2,
			Round:         1,
			Step:          proactive.StepPreVote,
			SenderID:      id,
			CandidateHash: cand,
			VoteValue:     proactive.VoteAccept,
		})
	}

	// 4. Exchange Round 1 PRE-VOTEs among honest nodes
	round1Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range honestNodes {
		for _, pv := range round1Prevotes {
			nextVote, _, _, _, err := instances[id].ProcessVote(pv)
			if err != nil {
				t.Fatalf("honest node %s failed processing PRE-VOTE: %v", id, err)
			}
			if nextVote != nil {
				round1Mainvotes = append(round1Mainvotes, nextVote)
			}
		}
	}

	// 5. Exchange Round 1 MAIN-VOTEs among honest nodes (split -> generates coin shares)
	coinSharesRound1 := make([]*proactive.AgreementCoinShareMessage, 0)
	for _, id := range honestNodes {
		for _, mv := range round1Mainvotes {
			_, coinMsg, decided, _, err := instances[id].ProcessVote(mv)
			if err != nil {
				t.Fatalf("honest node %s failed processing MAIN-VOTE: %v", id, err)
			}
			if decided {
				// decided in round 1
			}
			if coinMsg != nil {
				coinSharesRound1 = append(coinSharesRound1, coinMsg)
			}
		}
	}

	// Byzantine nodes 12..15 inject corrupted coin shares
	for bIdx := 11; bIdx < 15; bIdx++ {
		bID := committee[bIdx]
		badShare := &cryptography.CoinShare{
			CommitteeID: "comm-15-integ",
			NodeID:      bID,
			NodeIndex:   bIdx + 1,
			Round:       1,
			Tag:         instances[committee[0]].SessionTag + ":round:1",
			SharePoint:  cryptography.GeneratorG, // BOGUS POINT!
			Proof: &cryptography.DLEQProof{
				Challenge: cryptography.NewFieldElement(123),
				Response:  cryptography.NewFieldElement(456),
			},
		}
		coinSharesRound1 = append(coinSharesRound1, &proactive.AgreementCoinShareMessage{
			CommitteeID: "comm-15-integ",
			Epoch:       2,
			Round:       1,
			SenderID:    bID,
			CoinShare:   badShare,
		})
	}

	// 6. Process coin shares across honest nodes (corrupted shares dropped, honest shares combined)
	round2Prevotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range honestNodes {
		for _, csMsg := range coinSharesRound1 {
			nextVote, _, _, err := instances[id].ProcessCoinShare(csMsg)
			if err != nil && err != proactive.ErrInvalidCoinShare {
				t.Fatalf("unexpected error processing coin share: %v", err)
			}
			if nextVote != nil {
				round2Prevotes = append(round2Prevotes, nextVote)
			}
		}
	}

	// 7. Process Round 2 PRE-VOTEs (all honest nodes now aligned by common coin!)
	round2Mainvotes := make([]*proactive.AgreementVoteMessage, 0)
	for _, id := range honestNodes {
		for _, pv := range round2Prevotes {
			nextVote, _, _, _, err := instances[id].ProcessVote(pv)
			if err != nil {
				t.Fatalf("honest node %s failed processing Round 2 PRE-VOTE: %v", id, err)
			}
			if nextVote != nil {
				round2Mainvotes = append(round2Mainvotes, nextVote)
			}
		}
	}

	// 8. Process Round 2 MAIN-VOTEs -> All honest nodes DECIDE!
	for _, id := range honestNodes {
		for _, mv := range round2Mainvotes {
			_, _, _, _, err := instances[id].ProcessVote(mv)
			if err != nil {
				t.Fatalf("honest node %s failed processing Round 2 MAIN-VOTE: %v", id, err)
			}
		}
	}

	// 9. Verify Byzantine Agreement Safety across ALL 11 honest nodes
	var agreedHash string
	for _, id := range honestNodes {
		inst := instances[id]
		if !inst.IsDecided {
			t.Fatalf("honest node %s failed to decide after common coin resolution in 15-node committee", id)
		}
		if agreedHash == "" {
			agreedHash = inst.DecidedHash
		} else if inst.DecidedHash != agreedHash {
			t.Fatalf("SAFETY VIOLATION in 15-node committee: node %s decided %s != %s",
				id, inst.DecidedHash, agreedHash)
		}
		if !predicate(inst.DecidedSet) {
			t.Fatalf("decided set failed validity predicate")
		}
	}
	t.Logf("15-node Byzantine Agreement successfully decided on proposal %s across all 11 honest nodes!", agreedHash)
}


