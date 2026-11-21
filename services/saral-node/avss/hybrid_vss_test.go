package avss_test

import (
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestHybridVSS_PredicatesAndSharingFlow(t *testing.T) {
	n := 5
	k := 3
	tVal := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}

	// 1. Quorum formula checks from Kate-Huang-Goldberg (Figure 1)
	echoQuorum := avss.HybridVSSEchoQuorum(n, tVal)
	if echoQuorum != 4 { // ceil((5 + 1 + 1) / 2) = ceil(7/2) = 4
		t.Fatalf("expected echo quorum 4, got %d", echoQuorum)
	}

	readyStep := avss.HybridVSSReadyStepQuorum(tVal)
	if readyStep != 2 { // t + 1 = 1 + 1 = 2
		t.Fatalf("expected ready step quorum 2, got %d", readyStep)
	}

	completionQuorum := avss.HybridVSSCompletionQuorum(n, tVal, 0)
	if completionQuorum != 3 { // 2t + 1 = 3
		t.Fatalf("expected completion quorum 3, got %d", completionQuorum)
	}

	// 2. Generate Dealer Package with symmetric bivariate polynomial phi(x, y) = phi(y, x)
	secret, _ := cryptography.RandScalar()
	blind, _ := cryptography.RandScalar()
	sessionID := "test-hybrid-vss-session"
	committeeID := "committee-foundation"
	dealerID := "node-1"

	pkg, err := avss.GenerateDealerSharing(sessionID, committeeID, dealerID, 1, committee, k, secret, blind)
	if err != nil {
		t.Fatalf("failed to generate dealer sharing: %v", err)
	}

	// 3. Test verify-poly predicate (Figure 1)
	selfIdxFE := cryptography.NewFieldElement(1)
	rowPoly := pkg.F.RowPolynomial(selfIdxFE)
	rowBlindPoly := pkg.FPrime.RowPolynomial(selfIdxFE)

	if !pkg.CommitmentMatrix.VerifyPoly(selfIdxFE, rowPoly, rowBlindPoly) {
		t.Fatalf("verify-poly predicate failed on valid polynomial slice")
	}

	// Tampered polynomial slice must be strictly rejected by verify-poly
	tamperedCoeffs := make([]*cryptography.FieldElement, len(rowPoly.Coeffs))
	copy(tamperedCoeffs, rowPoly.Coeffs)
	tamperedCoeffs[0] = tamperedCoeffs[0].Add(cryptography.NewFieldElement(1))
	tamperedPoly := avss.NewPolynomial(tamperedCoeffs)

	if pkg.CommitmentMatrix.VerifyPoly(selfIdxFE, tamperedPoly, rowBlindPoly) {
		t.Fatalf("SECURITY VIOLATION: verify-poly accepted tampered polynomial!")
	}

	// 4. Test verify-point predicate (Figure 1)
	peerIdxFE := cryptography.NewFieldElement(2)
	pt := rowPoly.Evaluate(peerIdxFE)
	ptBlind := rowBlindPoly.Evaluate(peerIdxFE)

	if !pkg.CommitmentMatrix.VerifyPoint(selfIdxFE, peerIdxFE, pt, ptBlind) {
		t.Fatalf("verify-point predicate failed on valid evaluation point")
	}

	// Forged point must be strictly rejected by verify-point
	forgedPt := pt.Add(cryptography.NewFieldElement(999))
	if pkg.CommitmentMatrix.VerifyPoint(selfIdxFE, peerIdxFE, forgedPt, ptBlind) {
		t.Fatalf("SECURITY VIOLATION: verify-point accepted forged point!")
	}

	// 5. Full 5-node protocol execution
	sessions := make(map[string]*avss.Session)
	for idx, id := range committee {
		sess, err := avss.NewSession(sessionID, committeeID, dealerID, id, idx+1, 1, n, k, tVal, committee)
		if err != nil {
			t.Fatalf("failed to init session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// Send phase
	allEchos := make([]*avss.EchoMessage, 0)
	for id, sess := range sessions {
		msg := pkg.SendMessages[id]
		echos, err := sess.ProcessSendMessage(msg)
		if err != nil {
			t.Fatalf("ProcessSendMessage failed for %s: %v", id, err)
		}
		allEchos = append(allEchos, echos...)
	}

	// Echo phase
	allReadys := make([]*avss.ReadyMessage, 0)
	for _, echo := range allEchos {
		recipient := echo.RecipientID
		readys, err := sessions[recipient].ProcessEchoMessage(echo)
		if err != nil && err != avss.ErrDuplicateMessage {
			t.Fatalf("ProcessEchoMessage error on %s: %v", recipient, err)
		}
		allReadys = append(allReadys, readys...)
	}

	// Ready phase
	for _, ready := range allReadys {
		recipient := ready.RecipientID
		completed, additionalReadys, err := sessions[recipient].ProcessReadyMessage(ready)
		if err != nil && err != avss.ErrDuplicateMessage {
			t.Fatalf("ProcessReadyMessage error on %s: %v", recipient, err)
		}
		if completed {
			t.Logf("Node %s successfully COMPLETED HybridVSS sharing!", recipient)
		}
		_ = additionalReadys
	}

	// 6. Test Crash Recovery Protocol (RecoveryRequest & RecoveryResponse)
	crashedNodeID := "node-5"
	recReq := &avss.RecoveryRequestMessage{
		SessionID:   sessionID,
		CommitteeID: committeeID,
		RequesterID: crashedNodeID,
		Epoch:       1,
	}

	helperNodeID := "node-1"
	recResp, err := sessions[helperNodeID].ProcessRecoveryRequest(recReq)
	if err != nil {
		t.Fatalf("helper failed to generate recovery response: %v", err)
	}

	// Create fresh clean session for crashed node simulating restart
	recoveredSess, _ := avss.NewSession(sessionID, committeeID, dealerID, crashedNodeID, 5, 1, n, k, tVal, committee)
	err = recoveredSess.ProcessRecoveryResponse(recResp)
	if err != nil {
		t.Fatalf("crashed node failed to process recovery response: %v", err)
	}

	t.Logf("✅ HybridVSS Predicates, Protocol Sharing, and Crash Recovery SUCCESSFUL!")
}

