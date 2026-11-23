//go:build test_only

package avss_test

import (
	"fmt"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestParameterValidation(t *testing.T) {
	// Configuration A: n = 15, t = 4, k = 5 -> n - 2t = 7 >= 5 > 4 (PASS)
	if err := avss.ValidateSecurityParameters(15, 5, 4); err != nil {
		t.Fatalf("Config A should be valid: %v", err)
	}

	// Configuration B: n = 5, t = 1, k = 2 -> n - 2t = 3 >= 2 > 1 (PASS)
	if err := avss.ValidateSecurityParameters(5, 2, 1); err != nil {
		t.Fatalf("Config B should be valid: %v", err)
	}

	// Configuration C: n = 5, t = 1, k = 3 -> n - 2t = 3 >= 3 > 1 (PASS)
	if err := avss.ValidateSecurityParameters(5, 3, 1); err != nil {
		t.Fatalf("Config C should be valid: %v", err)
	}

	// Invalid: k <= t (k=1, t=1)
	if err := avss.ValidateSecurityParameters(5, 1, 1); err == nil {
		t.Fatalf("expected error for k <= t")
	}

	// Invalid: n - 2t < k (n=5, t=2, k=2 -> n - 2t = 1 < 2)
	if err := avss.ValidateSecurityParameters(5, 2, 2); err == nil {
		t.Fatalf("expected error for n - 2t < k")
	}

	// Invalid: negative t
	if err := avss.ValidateSecurityParameters(5, 2, -1); err == nil {
		t.Fatalf("expected error for t < 0")
	}
}

func TestBivariatePolynomialSymmetryAndSlices(t *testing.T) {
	secret := cryptography.NewFieldElement(123456789)
	deg := 2 // k = 3
	F, err := avss.SampleRandomBivariatePolynomial(deg, secret)
	if err != nil {
		t.Fatalf("failed sampling bivariate poly: %v", err)
	}

	// Check secret at (0, 0)
	zero := cryptography.NewFieldElement(0)
	if !F.Evaluate(zero, zero).Equal(secret) {
		t.Fatalf("F(0, 0) != secret")
	}

	// Check symmetry: F(x, y) == F(y, x)
	x := cryptography.NewFieldElement(4)
	y := cryptography.NewFieldElement(9)
	valXY := F.Evaluate(x, y)
	valYX := F.Evaluate(y, x)
	if !valXY.Equal(valYX) {
		t.Fatalf("bivariate symmetry failed: F(x, y)=%s != F(y, x)=%s", valXY.Hex(), valYX.Hex())
	}

	// Check row and column slice properties:
	// a_i(y) = F(i, y), b_j(x) = F(x, j)
	// a_i(j) == b_j(i) == F(i, j)
	iFE := cryptography.NewFieldElement(2)
	jFE := cryptography.NewFieldElement(5)

	rowI := F.RowPolynomial(iFE)
	colJ := F.ColPolynomial(jFE)

	evalRow := rowI.Evaluate(jFE)
	evalCol := colJ.Evaluate(iFE)
	evalDirect := F.Evaluate(iFE, jFE)

	if !evalRow.Equal(evalDirect) || !evalCol.Equal(evalDirect) {
		t.Fatalf("slice evaluation mismatch: row=%s, col=%s, direct=%s",
			evalRow.Hex(), evalCol.Hex(), evalDirect.Hex())
	}
}

func TestCommitmentMatrixVerification(t *testing.T) {
	secret := cryptography.NewFieldElement(987654)
	blindSecret := cryptography.NewFieldElement(112233)
	deg := 1 // k = 2
	F, _ := avss.SampleRandomBivariatePolynomial(deg, secret)
	FPrime, _ := avss.SampleRandomBivariatePolynomial(deg, blindSecret)

	cm, err := avss.ComputeCommitmentMatrix(F, FPrime)
	if err != nil {
		t.Fatalf("failed to compute commitment matrix: %v", err)
	}

	// Verify secret commitment C_{0, 0}
	expectedSecretCommit := cryptography.PedersenCommitment(secret, blindSecret)
	if !cm.SecretCommitment().Equal(expectedSecretCommit) {
		t.Fatalf("C_{0, 0} != Commit(s, s')")
	}

	// Verify row and col polynomials for participant 1
	p1FE := cryptography.NewFieldElement(1)
	row1 := F.RowPolynomial(p1FE)
	row1Blind := FPrime.RowPolynomial(p1FE)
	col1 := F.ColPolynomial(p1FE)
	col1Blind := FPrime.ColPolynomial(p1FE)

	if !cm.VerifyRowPolynomial(p1FE, row1, row1Blind) {
		t.Fatalf("valid row polynomial failed verification")
	}
	if !cm.VerifyColPolynomial(p1FE, col1, col1Blind) {
		t.Fatalf("valid col polynomial failed verification")
	}

	// Adversarial test: Tampered row polynomial coefficient must fail verification
	corruptedRow := avss.NewPolynomial([]*cryptography.FieldElement{
		row1.Coeffs[0].Add(cryptography.NewFieldElement(1)), // corrupted constant term
		row1.Coeffs[1],
	})
	if cm.VerifyRowPolynomial(p1FE, corruptedRow, row1Blind) {
		t.Fatalf("corrupted row polynomial should fail verification!")
	}

	// Verify point commitment at (1, 2)
	p2FE := cryptography.NewFieldElement(2)
	pt12 := F.Evaluate(p1FE, p2FE)
	pt12Blind := FPrime.Evaluate(p1FE, p2FE)
	if !cm.VerifyPoint(p1FE, p2FE, pt12, pt12Blind) {
		t.Fatalf("valid point failed verification")
	}

	// Adversarial test: Tampered point must fail verification
	corruptedPt := pt12.Add(cryptography.NewFieldElement(1))
	if cm.VerifyPoint(p1FE, p2FE, corruptedPt, pt12Blind) {
		t.Fatalf("corrupted point should fail verification!")
	}
}

func TestAVSSProtocolFlow5Nodes(t *testing.T) {
	// Configuration B: n = 5, t = 1, k = 2
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	dealerID := "node-1"
	sessionID := "avss-test-session-5nodes"
	k := 2
	n := 5
	tVal := 1

	secret := cryptography.NewFieldElement(424242)
	blindSecret := cryptography.NewFieldElement(777777)

	// 1. Dealer generates sharing package
	dealerPkg, err := avss.GenerateDealerSharing(sessionID, "committee-5", dealerID, 1, committee, k, secret, blindSecret)
	if err != nil {
		t.Fatalf("failed generating dealer sharing: %v", err)
	}

	// 2. Initialize sessions on all 5 nodes
	sessions := make(map[string]*avss.Session)
	for idx, id := range committee {
		sess, err := avss.NewSession(sessionID, "committee-5", dealerID, id, idx+1, 1, n, k, tVal, committee)
		if err != nil {
			t.Fatalf("failed creating session for %s: %v", id, err)
		}
		sessions[id] = sess
	}

	// 3. Dealer sends SEND messages to all participants
	allEchos := make([]*avss.EchoMessage, 0)
	for nodeID, sendMsg := range dealerPkg.SendMessages {
		sess := sessions[nodeID]
		echos, err := sess.ProcessSendMessage(sendMsg)
		if err != nil {
			t.Fatalf("node %s failed to process SEND: %v", nodeID, err)
		}
		allEchos = append(allEchos, echos...)
	}

	// 4. Exchange ECHOs among all participants
	allReadys := make([]*avss.ReadyMessage, 0)
	for _, echo := range allEchos {
		recipientSess := sessions[echo.RecipientID]
		readys, err := recipientSess.ProcessEchoMessage(echo)
		if err != nil && err != avss.ErrDuplicateMessage {
			t.Fatalf("node %s failed to process ECHO: %v", echo.RecipientID, err)
		}
		if len(readys) > 0 {
			allReadys = append(allReadys, readys...)
		}
	}

	// 5. Exchange READYs among all participants
	completedNodes := 0
	for _, ready := range allReadys {
		recipientSess := sessions[ready.RecipientID]
		completed, moreReadys, err := recipientSess.ProcessReadyMessage(ready)
		if err != nil && err != avss.ErrDuplicateMessage {
			t.Fatalf("node %s failed to process READY: %v", ready.RecipientID, err)
		}
		if completed {
			completedNodes++
		}
		if len(moreReadys) > 0 {
			// Broadcast amplified readys
			for _, ampReady := range moreReadys {
				c2, _, _ := sessions[ampReady.RecipientID].ProcessReadyMessage(ampReady)
				if c2 {
					completedNodes++
				}
			}
		}
	}

	// All 5 nodes must complete successfully
	for _, id := range committee {
		sess := sessions[id]
		if sess.State != avss.StateSharingCompleted {
			t.Fatalf("node %s did not reach SHARING_COMPLETED, state: %s", id, sess.State)
		}
		if sess.Share == nil || sess.BlindShare == nil {
			t.Fatalf("node %s missing finalized share", id)
		}
	}

	// 6. Test isolated reconstruction:
	// Use exactly k=2 shares (node-2 and node-4)
	sharesForRecon := []*avss.ReconstructionShare{
		{
			NodeID:     "node-2",
			NodeIndex:  2,
			Share:      sessions["node-2"].Share,
			BlindShare: sessions["node-2"].BlindShare,
		},
		{
			NodeID:     "node-4",
			NodeIndex:  4,
			Share:      sessions["node-4"].Share,
			BlindShare: sessions["node-4"].BlindShare,
		},
	}

	reconResult, err := avss.ReconstructSecret(sharesForRecon, dealerPkg.CommitmentMatrix, k)
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}

	if !reconResult.Secret.Equal(secret) {
		t.Fatalf("reconstructed secret mismatch: got %s, want %s", reconResult.Secret.Hex(), secret.Hex())
	}
	if !reconResult.BlindSecret.Equal(blindSecret) {
		t.Fatalf("reconstructed blind secret mismatch")
	}

	// 7. Adversarial Test: Reconstruction with < k shares (only 1 share) MUST fail
	_, err = avss.ReconstructSecret(sharesForRecon[:1], dealerPkg.CommitmentMatrix, k)
	if err == nil {
		t.Fatalf("reconstruction with fewer than k shares must fail!")
	}

	// 8. Adversarial Test: Corrupted share must fail verification
	corruptedShare := []*avss.ReconstructionShare{
		{
			NodeID:     "node-2",
			NodeIndex:  2,
			Share:      sessions["node-2"].Share.Add(cryptography.NewFieldElement(1)), // tampered share!
			BlindShare: sessions["node-2"].BlindShare,
		},
		sharesForRecon[1],
	}
	_, err = avss.ReconstructSecret(corruptedShare, dealerPkg.CommitmentMatrix, k)
	if err == nil {
		t.Fatalf("reconstruction with tampered share must fail verification!")
	}
}

func TestAVSSFallbackInterpolation(t *testing.T) {
	// Tests Byzantine dealer scenario: Dealer refuses to send SEND to node-3.
	// Node-3 collects ECHOs from honest peers, interpolates its polynomial, and completes sharing!
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	dealerID := "node-1"
	sessionID := "avss-fallback-test"
	k := 2
	n := 5
	tVal := 1

	secret := cryptography.NewFieldElement(88888)
	blindSecret := cryptography.NewFieldElement(99999)

	dealerPkg, err := avss.GenerateDealerSharing(sessionID, "comm", dealerID, 1, committee, k, secret, blindSecret)
	if err != nil {
		t.Fatalf("dealer generation failed: %v", err)
	}

	sessions := make(map[string]*avss.Session)
	for idx, id := range committee {
		sess, _ := avss.NewSession(sessionID, "comm", dealerID, id, idx+1, 1, n, k, tVal, committee)
		sessions[id] = sess
	}

	// Dealer delivers SEND to nodes 1, 2, 4, 5 — but DROPS node-3!
	allEchos := make([]*avss.EchoMessage, 0)
	for nodeID, sendMsg := range dealerPkg.SendMessages {
		if nodeID == "node-3" {
			continue // Byzantine dealer omit!
		}
		echos, err := sessions[nodeID].ProcessSendMessage(sendMsg)
		if err != nil {
			t.Fatalf("error processing send: %v", err)
		}
		allEchos = append(allEchos, echos...)
	}

	// Nodes exchange ECHOs (including delivering ECHOs to node-3)
	allReadys := make([]*avss.ReadyMessage, 0)
	for _, echo := range allEchos {
		readys, _ := sessions[echo.RecipientID].ProcessEchoMessage(echo)
		if len(readys) > 0 {
			allReadys = append(allReadys, readys...)
		}
	}

	// Deliver READYs to all
	for _, ready := range allReadys {
		c, more, _ := sessions[ready.RecipientID].ProcessReadyMessage(ready)
		if len(more) > 0 {
			for _, mr := range more {
				sessions[mr.RecipientID].ProcessReadyMessage(mr)
			}
		}
		_ = c
	}

	// Node 3 must have recovered its share via Lagrange interpolation from peer ECHOs!
	sess3 := sessions["node-3"]
	if sess3.State != avss.StateSharingCompleted {
		t.Fatalf("node-3 failed to complete via interpolation fallback, state: %s", sess3.State)
	}

	// Verify node 3's recovered share against the dealer's original polynomial!
	expectedShare3 := dealerPkg.F.RowPolynomial(cryptography.NewFieldElement(3)).Coeffs[0]
	if !sess3.Share.Equal(expectedShare3) {
		t.Fatalf("node-3 interpolated share mismatch: got %s, want %s", sess3.Share.Hex(), expectedShare3.Hex())
	}
}

func TestAVSSProtocolFlow15Nodes(t *testing.T) {
	// Configuration A: n = 15, t = 4, k = 5
	committee := make([]string, 15)
	for i := 0; i < 15; i++ {
		committee[i] = fmt.Sprintf("node-%d", i+1)
	}
	dealerID := "node-1"
	sessionID := "avss-test-15nodes"
	k := 5
	n := 15
	tVal := 4

	secret := cryptography.NewFieldElement(15151515)
	blindSecret := cryptography.NewFieldElement(51515151)

	dealerPkg, err := avss.GenerateDealerSharing(sessionID, "global-15", dealerID, 1, committee, k, secret, blindSecret)
	if err != nil {
		t.Fatalf("dealer generation failed: %v", err)
	}

	sessions := make(map[string]*avss.Session)
	for idx, id := range committee {
		sess, err := avss.NewSession(sessionID, "global-15", dealerID, id, idx+1, 1, n, k, tVal, committee)
		if err != nil {
			t.Fatalf("failed creating session: %v", err)
		}
		sessions[id] = sess
	}

	allEchos := make([]*avss.EchoMessage, 0)
	for nodeID, sendMsg := range dealerPkg.SendMessages {
		echos, err := sessions[nodeID].ProcessSendMessage(sendMsg)
		if err != nil {
			t.Fatalf("error processing send: %v", err)
		}
		allEchos = append(allEchos, echos...)
	}

	allReadys := make([]*avss.ReadyMessage, 0)
	for _, echo := range allEchos {
		readys, _ := sessions[echo.RecipientID].ProcessEchoMessage(echo)
		if len(readys) > 0 {
			allReadys = append(allReadys, readys...)
		}
	}

	for _, ready := range allReadys {
		_, more, _ := sessions[ready.RecipientID].ProcessReadyMessage(ready)
		if len(more) > 0 {
			for _, mr := range more {
				sessions[mr.RecipientID].ProcessReadyMessage(mr)
			}
		}
	}

	// All 15 nodes must complete
	for _, id := range committee {
		if sessions[id].State != avss.StateSharingCompleted {
			t.Fatalf("node %s in 15-node committee did not complete sharing, state: %s", id, sessions[id].State)
		}
	}

	// Reconstruct secret using arbitrary k=5 nodes (node-1, node-3, node-7, node-11, node-15)
	selectedIndices := []int{1, 3, 7, 11, 15}
	sharesForRecon := make([]*avss.ReconstructionShare, len(selectedIndices))
	for idx, sIdx := range selectedIndices {
		id := fmt.Sprintf("node-%d", sIdx)
		sharesForRecon[idx] = &avss.ReconstructionShare{
			NodeID:     id,
			NodeIndex:  sIdx,
			Share:      sessions[id].Share,
			BlindShare: sessions[id].BlindShare,
		}
	}

	recon, err := avss.ReconstructSecret(sharesForRecon, dealerPkg.CommitmentMatrix, k)
	if err != nil {
		t.Fatalf("15-node reconstruction failed: %v", err)
	}

	if !recon.Secret.Equal(secret) {
		t.Fatalf("15-node secret mismatch: got %s, want %s", recon.Secret.Hex(), secret.Hex())
	}
}

