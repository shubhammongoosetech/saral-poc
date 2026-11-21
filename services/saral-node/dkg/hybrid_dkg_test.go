package dkg_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
)

func TestHybridDKG_OptimisticPhaseAndKeyCombination(t *testing.T) {
	// Setup 5 nodes (n=5, k=3, t=1, f=0)
	n := 5
	k := 3
	tVal := 1
	fVal := 0
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	privKeys := make(map[string]ed25519.PrivateKey)
	pubKeys := make(map[string]string)

	for _, id := range committee {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		privKeys[id] = priv
		pubKeys[id] = hex.EncodeToString(pub)
	}

	instances := make(map[string]*dkg.HybridDKGInstance)
	sessionID := "test-hybrid-dkg-session-1"
	committeeID := "committee-foundation"

	for idx, id := range committee {
		inst := dkg.NewHybridDKGInstance(
			sessionID, committeeID, id, idx+1,
			committee, n, k, tVal, fVal,
			privKeys[id], pubKeys,
		)
		instances[id] = inst
	}

	// Step 1: Simulate completed HybridVSS for dealers
	dealers := []string{"node-1", "node-2", "node-3", "node-4"}
	vssSessions := make(map[string]map[string]*avss.Session) // nodeID -> dealerID -> Session
	commitMatrices := make(map[string]*avss.CommitmentMatrix)
	peerCommits := make(map[string]*cryptography.CurvePoint)
	peerPublicKeys := make(map[string]*cryptography.CurvePoint)
	dealerSecrets := make(map[string]*cryptography.FieldElement)

	for _, dID := range dealers {
		sec, _ := cryptography.RandScalar()
		dealerSecrets[dID] = sec
		blind, _ := cryptography.RandScalar()

		pkg, err := avss.GenerateDealerSharing(
			"vss-"+dID, committeeID, dID, 1, committee, k, sec, blind,
		)
		if err != nil {
			t.Fatalf("failed generating dealer sharing: %v", err)
		}
		commitMatrices[dID] = pkg.CommitmentMatrix
		peerCommits[dID] = pkg.CommitmentMatrix.SecretCommitment()
		peerPublicKeys[dID] = cryptography.GeneratorG.ScalarMult(sec)

		for idx, nID := range committee {
			if vssSessions[nID] == nil {
				vssSessions[nID] = make(map[string]*avss.Session)
			}
			sess, _ := avss.NewSession("vss-"+dID, committeeID, dID, nID, idx+1, 1, n, k, tVal, committee)
			msg := pkg.SendMessages[nID]
			sess.ProcessSendMessage(msg)
			sess.Share = sess.RowPoly.Coeffs[0]
			sess.BlindShare = sess.RowBlindPoly.Coeffs[0]
			sess.State = avss.StateSharingCompleted
			vssSessions[nID][dID] = sess

			// Generate ValidityCertificate for dealer dID
			commitHash := avss.HashCommitments(msg.Commitments)
			cert, err := instances[nID].GenerateCompletionCertificate(dID, commitHash, 1)
			if err != nil {
				t.Fatalf("failed to generate cert: %v", err)
			}

			// Broadcast cert to all peers
			for _, peerID := range committee {
				_ = instances[peerID].RecordCompletionCertificate(cert)
			}
		}
	}

	// Step 2: Leader (node-1) proposes Qualified Set Q
	leaderID := instances["node-1"].CurrentLeader
	if leaderID != "node-1" {
		t.Fatalf("expected node-1 to be round 1 leader, got %s", leaderID)
	}

	if !instances["node-1"].CanPropose() {
		t.Fatalf("leader node-1 should be ready to propose")
	}

	prop, err := instances["node-1"].CreateProposal()
	if err != nil {
		t.Fatalf("leader failed to create proposal: %v", err)
	}

	// Verify proposal signature and validity
	if !prop.Verify() {
		t.Fatalf("proposal signature verification failed")
	}

	// Step 3: All nodes process proposal and broadcast ECHOs
	echos := make(map[string]*dkg.ProposalEchoMessage)
	for _, nID := range committee {
		echo, err := instances[nID].ProcessProposal(prop)
		if err != nil {
			t.Fatalf("node %s failed to process proposal: %v", nID, err)
		}
		echos[nID] = echo
	}

	// Step 4: Disseminate ECHOs, gather READY messages
	readys := make(map[string]*dkg.ProposalReadyMessage)
	for senderID, echo := range echos {
		for _, recipientID := range committee {
			readyMsg, err := instances[recipientID].ProcessProposalEcho(echo)
			if err != nil && err != dkg.ErrDuplicateVoteFromPeer {
				t.Fatalf("node %s failed to process echo from %s: %v", recipientID, senderID, err)
			}
			if readyMsg != nil && readys[recipientID] == nil {
				readys[recipientID] = readyMsg
			}
		}
	}

	// Step 5: Disseminate READY messages and verify consensus decision
	var decidedQUAL []string
	for senderID, ready := range readys {
		for _, recipientID := range committee {
			qual, decided, _, err := instances[recipientID].ProcessProposalReady(ready)
			if err != nil && err != dkg.ErrDuplicateVoteFromPeer {
				t.Fatalf("node %s failed to process ready from %s: %v", recipientID, senderID, err)
			}
			if decided {
				decidedQUAL = qual
			}
		}
	}

	if len(decidedQUAL) < n-tVal-fVal {
		t.Fatalf("agreement on qualified set failed: got %v", decidedQUAL)
	}

	// Step 6: Section 5.3 Key Combination on all nodes
	results := make(map[string]*dkg.HybridDKGResult)
	for _, nID := range committee {
		res, err := instances[nID].CombineDKGShares(
			decidedQUAL,
			vssSessions[nID],
			peerCommits,
			commitMatrices,
			peerPublicKeys,
		)
		if err != nil {
			t.Fatalf("node %s failed combining DKG shares: %v", nID, err)
		}
		results[nID] = res
	}

	// Step 7: Cryptographic Proof of Correctness
	masterPub := results["node-1"].MasterSigningPublicKey
	for _, nID := range committee {
		if !results[nID].MasterSigningPublicKey.Equal(masterPub) {
			t.Fatalf("signing public key mismatch between node-1 and %s", nID)
		}
	}

	// Sum actual dealer secrets to prove Master Secret Invariant: x = sum_{d \in QUAL} s_d
	expectedSecret := cryptography.NewFieldElement(0)
	for _, dID := range decidedQUAL {
		expectedSecret = expectedSecret.Add(dealerSecrets[dID])
	}
	expectedMasterPub := cryptography.GeneratorG.ScalarMult(expectedSecret)
	if !expectedMasterPub.Equal(masterPub) {
		t.Fatalf("CRYPTOGRAPHIC PROOF FAILED: x*G != MasterSigningPublicKey")
	}

	// 3-of-5 Threshold Reconstruction Invariance: any 3 shares reconstruct x
	subset := []string{"node-1", "node-3", "node-5"}
	xs := make([]*cryptography.FieldElement, 3)
	ys := make([]*cryptography.FieldElement, 3)
	for idx, id := range subset {
		xs[idx] = cryptography.NewFieldElement(int64(instances[id].SelfIndex))
		ys[idx] = results[id].CombinedShare
	}
	reconstructedPoly, err := avss.InterpolateUnivariate(xs, ys)
	if err != nil {
		t.Fatalf("failed interpolation: %v", err)
	}
	reconstructedX := reconstructedPoly.Evaluate(cryptography.NewFieldElement(0))
	if !reconstructedX.Equal(expectedSecret) {
		t.Fatalf("3-of-5 threshold secret reconstruction failed: got %s, expected %s",
			reconstructedX.Hex(), expectedSecret.Hex())
	}

	t.Logf("✅ HybridDKG Optimistic Agreement and Key Combination SUCCESSFUL!")
	t.Logf("   -> Master Signing Key Y = x*G: %s", masterPub.Hex())
	t.Logf("   -> Reconstructed Secret Matches: %s == %s", reconstructedX.Hex()[:16], expectedSecret.Hex()[:16])
}

func TestHybridDKG_PessimisticPhase_FaultyLeaderChange(t *testing.T) {
	n := 5
	k := 3
	tVal := 1
	fVal := 0
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	privKeys := make(map[string]ed25519.PrivateKey)
	pubKeys := make(map[string]string)

	for _, id := range committee {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privKeys[id] = priv
		pubKeys[id] = hex.EncodeToString(pub)
	}

	instances := make(map[string]*dkg.HybridDKGInstance)
	sessionID := "test-leader-change-session"
	committeeID := "committee-foundation"

	for idx, id := range committee {
		inst := dkg.NewHybridDKGInstance(
			sessionID, committeeID, id, idx+1,
			committee, n, k, tVal, fVal,
			privKeys[id], pubKeys,
		)
		instances[id] = inst
	}

	// Round 1 leader is node-1
	if instances["node-2"].CurrentLeader != "node-1" {
		t.Fatalf("round 1 leader should be node-1")
	}

	// Simulate node-1 failing to propose (timeout occurs on honest nodes)
	// Nodes 2, 3, 4, 5 suspect node-1
	suspects := []string{"node-2", "node-3", "node-4"}
	var leaderChanges []*dkg.LeaderChangeMessage

	for _, id := range suspects {
		lc, err := instances[id].SuspectLeader("timeout: leader silent")
		if err != nil {
			t.Fatalf("node %s failed to suspect leader: %v", id, err)
		}
		leaderChanges = append(leaderChanges, lc)
	}

	// Disseminate leader change messages
	var rotatedToRound int
	var newLeader string

	for _, lc := range leaderChanges {
		for _, recipientID := range committee {
			r, l, changed, _, err := instances[recipientID].ProcessLeaderChange(lc)
			if err != nil && err != dkg.ErrDuplicateVoteFromPeer {
				t.Fatalf("node %s error processing leader change: %v", recipientID, err)
			}
			if changed {
				rotatedToRound = r
				newLeader = l
			}
		}
	}

	if rotatedToRound != 2 {
		t.Fatalf("expected rotation to round 2, got %d", rotatedToRound)
	}
	if newLeader != "node-2" {
		t.Fatalf("expected new leader pi(2) to be node-2, got %s", newLeader)
	}

	t.Logf("✅ HybridDKG Pessimistic Leader Change SUCCESSFUL!")
	t.Logf("   -> Faulty leader node-1 deposed. Advanced to Round %d with new Leader: %s", rotatedToRound, newLeader)
}
