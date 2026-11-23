//go:build test_only

package cryptography_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/avss"
	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
	"github.com/saral-protocol/saral-poc/services/saral-node/dkg"
)

// runInProcessDKG runs a 5-node dealerless DKG with k=3 in process for a given curve
func runInProcessDKG(t *testing.T, curve string) ([]*dkg.Session, *cryptography.CurvePoint, []*cryptography.FieldElement) {
	n := 5
	k := 3
	tVal := 1
	committee := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	sessionID := fmt.Sprintf("test-dkg-%s-%d", curve, sha256.Sum256([]byte(curve)))

	sessions := make([]*dkg.Session, n)
	for i := 0; i < n; i++ {
		sess, err := dkg.NewSession(sessionID, "committee-test", committee[i], i+1, committee, n, k, tVal, nil)
		if err != nil {
			t.Fatalf("failed creating session for node %d: %v", i+1, err)
		}
		sess.Curve = curve
		sessions[i] = sess
	}

	// 1. Each node generates its contribution and dealing package
	dealerPkgs := make([]*avss.DealerPackage, n)
	for i := 0; i < n; i++ {
		pkg, err := sessions[i].StartContribution()
		if err != nil {
			t.Fatalf("node %d failed starting contribution: %v", i+1, err)
		}
		dealerPkgs[i] = pkg
	}

	// 2. Distribute commitments and verified sharings among all nodes
	for receiverIdx := 0; receiverIdx < n; receiverIdx++ {
		for dealerIdx := 0; dealerIdx < n; dealerIdx++ {
			dealerID := committee[dealerIdx]
			cm := dealerPkgs[dealerIdx].CommitmentMatrix
			sessions[receiverIdx].RecordPeerCommitment(dealerID, cm)

			// V_i = z_i * G
			gen := cryptography.GetGeneratorG(curve)
			vI := gen.ScalarMult(dealerPkgs[dealerIdx].Secret)
			sessions[receiverIdx].RecordPeerPublicKey(dealerID, vI)

			// Deliver recipient slice to node (1-based index)
			jFE := cryptography.NewFieldElementWithOrder(int64(receiverIdx+1), cryptography.GetCurveOrder(curve))
			rowPoly := dealerPkgs[dealerIdx].F.RowPolynomial(jFE)
			rowBlind := dealerPkgs[dealerIdx].FPrime.RowPolynomial(jFE)

			shareVal := rowPoly.Evaluate(cryptography.NewFieldElementWithOrder(0, cryptography.GetCurveOrder(curve)))
			blindVal := rowBlind.Evaluate(cryptography.NewFieldElementWithOrder(0, cryptography.GetCurveOrder(curve)))

			subSess := &avss.Session{
				SessionID:   fmt.Sprintf("dkg-%s-contrib-%s", sessionID, dealerID),
				CommitteeID: "committee-test",
				DealerID:    dealerID,
				Commitments: cm,
				Share:       shareVal,
				BlindShare:  blindVal,
			}
			sessions[receiverIdx].RecordCompletedSharing(dealerID, subSess)
		}
	}

	// 3. Aggregate shares on all nodes for qualified set (all 5 nodes)
	qualSet := committee
	for i := 0; i < n; i++ {
		if err := sessions[i].AggregateShares(qualSet); err != nil {
			t.Fatalf("node %d failed aggregating shares: %v", i+1, err)
		}
	}

	masterPub := sessions[0].MasterPublicKey
	shares := make([]*cryptography.FieldElement, n)
	for i := 0; i < n; i++ {
		shares[i] = sessions[i].FinalShare
	}

	return sessions, masterPub, shares
}

// interpolateSharesAtZero recovers the constant term (secret) from a subset of participant shares
func interpolateSharesAtZero(indices []int, shares []*cryptography.FieldElement, curve string) *cryptography.FieldElement {
	ord := cryptography.GetCurveOrder(curve)
	xTarget := cryptography.NewFieldElementWithOrder(0, ord)

	xs := make([]*cryptography.FieldElement, len(indices))
	for i, idx := range indices {
		xs[i] = cryptography.NewFieldElementWithOrder(int64(idx), ord)
	}

	acc := cryptography.NewFieldElementWithOrder(0, ord)
	for i := 0; i < len(indices); i++ {
		lambda, _ := cryptography.LagrangeCoefficient(xTarget, xs[i], xs)
		term := lambda.Mul(shares[i])
		acc = acc.Add(term)
	}
	return acc
}

func TestCurveParametricDKG_Secp256k1(t *testing.T) {
	curve := "secp256k1"
	sessions, masterPub, shares := runInProcessDKG(t, curve)

	G := cryptography.GetGeneratorG(curve)

	// Subset 1: {1, 2, 3} (size k=3)
	x123 := interpolateSharesAtZero([]int{1, 2, 3}, []*cryptography.FieldElement{shares[0], shares[1], shares[2]}, curve)
	Y123 := G.ScalarMult(x123)
	if !Y123.Equal(masterPub) {
		t.Fatalf("secp256k1: 3-share subset {1, 2, 3} x*G does not equal master public key Y\ngot:  %s\nwant: %s",
			Y123.Hex(), masterPub.Hex())
	}

	// Subset 2: {2, 4, 5} (different 3-share subset)
	x245 := interpolateSharesAtZero([]int{2, 4, 5}, []*cryptography.FieldElement{shares[1], shares[3], shares[4]}, curve)
	Y245 := G.ScalarMult(x245)
	if !Y245.Equal(masterPub) {
		t.Fatalf("secp256k1: 3-share subset {2, 4, 5} x*G does not equal master public key Y")
	}

	// Subset 3: {1, 3, 4, 5} (size 4 subset)
	x1345 := interpolateSharesAtZero([]int{1, 3, 4, 5}, []*cryptography.FieldElement{shares[0], shares[2], shares[3], shares[4]}, curve)
	Y1345 := G.ScalarMult(x1345)
	if !Y1345.Equal(masterPub) {
		t.Fatalf("secp256k1: 4-share subset {1, 3, 4, 5} x*G does not equal master public key Y")
	}

	// Sub-threshold subset: {1, 2} (size 2 < k=3) must NOT equal Y
	x12 := interpolateSharesAtZero([]int{1, 2}, []*cryptography.FieldElement{shares[0], shares[1]}, curve)
	Y12 := G.ScalarMult(x12)
	if Y12.Equal(masterPub) {
		t.Fatalf("SECURITY VIOLATION: 2 shares must NOT be able to reconstruct the master public key")
	}

	// Public-point interpolation in exponent over node contribution points Y_i = x_i * G:
	pts := []*cryptography.CurvePoint{
		G.ScalarMult(shares[0]),
		G.ScalarMult(shares[1]),
		G.ScalarMult(shares[2]),
	}
	coordInterp, err := cryptography.LagrangeInterpolateInExponent([]int{1, 2, 3}, pts, curve)
	if err != nil {
		t.Fatalf("public point interpolation in exponent failed: %v", err)
	}
	if !coordInterp.Equal(masterPub) {
		t.Fatalf("Lagrange interpolation in exponent does not equal DKG master public key:\ngot:  %s\nwant: %s", coordInterp.Hex(), masterPub.Hex())
	}

	// Engine curve rejection test: asking for wrong curve returns error
	eng := dkg.NewEngine("node-1", "FOUNDATION", t.TempDir(), nil, nil, nil)
	sess := sessions[0]
	eng.CreateSessionWithBinding(sess.SessionID, sess.CommitteeID, "w1", "k1", "u1", "secp256k1", "mst", 5, 3, 1, sess.Committee)
	_, _, _, _, _, err = eng.GetPublicShareContribution("k1", sess.SessionID, sess.CommitteeID, "ed25519", 1)
	if err == nil {
		t.Fatalf("expected error when asking for ed25519 contribution from secp256k1 session")
	}
}

func TestCurveParametricDKG_Ed25519(t *testing.T) {
	curve := "ed25519"
	sessions, masterPub, shares := runInProcessDKG(t, curve)

	B := cryptography.GetGeneratorG(curve)

	// Subset 1: {1, 2, 3} (size k=3)
	x123 := interpolateSharesAtZero([]int{1, 2, 3}, []*cryptography.FieldElement{shares[0], shares[1], shares[2]}, curve)
	Y123 := B.ScalarMult(x123)
	if !Y123.Equal(masterPub) {
		t.Fatalf("ed25519: 3-share subset {1, 2, 3} x*B does not equal master public key Y\ngot:  %s\nwant: %s",
			Y123.Hex(), masterPub.Hex())
	}

	// Subset 2: {2, 3, 5}
	x235 := interpolateSharesAtZero([]int{2, 3, 5}, []*cryptography.FieldElement{shares[1], shares[2], shares[4]}, curve)
	Y235 := B.ScalarMult(x235)
	if !Y235.Equal(masterPub) {
		t.Fatalf("ed25519: 3-share subset {2, 3, 5} x*B does not equal master public key Y")
	}

	// Subset 3: {1, 2, 4, 5} (size 4)
	x1245 := interpolateSharesAtZero([]int{1, 2, 4, 5}, []*cryptography.FieldElement{shares[0], shares[1], shares[3], shares[4]}, curve)
	Y1245 := B.ScalarMult(x1245)
	if !Y1245.Equal(masterPub) {
		t.Fatalf("ed25519: 4-share subset {1, 2, 4, 5} x*B does not equal master public key Y")
	}

	// Sub-threshold: {1, 2}
	x12 := interpolateSharesAtZero([]int{1, 2}, []*cryptography.FieldElement{shares[0], shares[1]}, curve)
	Y12 := B.ScalarMult(x12)
	if Y12.Equal(masterPub) {
		t.Fatalf("SECURITY VIOLATION: 2 shares must NOT be able to reconstruct the master public key on ed25519")
	}

	// Public-point interpolation in exponent on ed25519:
	pts := []*cryptography.CurvePoint{
		B.ScalarMult(shares[0]),
		B.ScalarMult(shares[1]),
		B.ScalarMult(shares[2]),
	}
	coordInterp, err := cryptography.LagrangeInterpolateInExponent([]int{1, 2, 3}, pts, curve)
	if err != nil {
		t.Fatalf("public point interpolation in exponent failed: %v", err)
	}
	if !coordInterp.Equal(masterPub) {
		t.Fatalf("Lagrange interpolation in exponent does not equal DKG master public key on ed25519:\ngot:  %s\nwant: %s", coordInterp.Hex(), masterPub.Hex())
	}

	// Engine curve rejection test: asking for wrong curve returns error
	eng := dkg.NewEngine("node-1", "PUBLIC", t.TempDir(), nil, nil, nil)
	sess := sessions[0]
	eng.CreateSessionWithBinding(sess.SessionID, sess.CommitteeID, "w1", "k1", "u1", "ed25519", "solana", 5, 3, 1, sess.Committee)
	_, _, _, _, _, err = eng.GetPublicShareContribution("k1", sess.SessionID, sess.CommitteeID, "secp256k1", 1)
	if err == nil {
		t.Fatalf("expected error when asking for secp256k1 contribution from ed25519 session")
	}
}

func TestThreeDomainSeparationOfPowers_SecretSumProof(t *testing.T) {
	curves := []string{"secp256k1", "ed25519"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			// Domain 1: Foundation (5 nodes, k=3)
			_, pubF, sharesF := runInProcessDKG(t, curve)
			xF := interpolateSharesAtZero([]int{1, 2, 3}, []*cryptography.FieldElement{sharesF[0], sharesF[1], sharesF[2]}, curve)

			// Domain 2: Public (5 nodes, k=3)
			_, pubP, sharesP := runInProcessDKG(t, curve)
			xP := interpolateSharesAtZero([]int{1, 2, 3}, []*cryptography.FieldElement{sharesP[0], sharesP[1], sharesP[2]}, curve)

			// Domain 3: Private (5 nodes, k=3)
			_, pubR, sharesR := runInProcessDKG(t, curve)
			xR := interpolateSharesAtZero([]int{1, 2, 3}, []*cryptography.FieldElement{sharesR[0], sharesR[1], sharesR[2]}, curve)

			// Sum of domain secrets: x_total = x_F + x_P + x_R
			xTotal := xF.Add(xP).Add(xR)

			// Base generator
			gen := cryptography.GetGeneratorG(curve)

			// Combined public key from secret sum: Y_secret = (x_F + x_P + x_R) * G
			yFromSecretSum := gen.ScalarMult(xTotal)

			// Combined public key from public points: Y_pub = Y_F + Y_P + Y_R
			yFromPointAddition := pubF.Add(pubP).Add(pubR)

			// Strict Cryptographic Invariant Proof: (x_F + x_P + x_R)*G == Y_F + Y_P + Y_R
			if !yFromSecretSum.Equal(yFromPointAddition) {
				t.Fatalf("3-Domain Cryptographic Invariant Failed for curve %s:\n(x_F + x_P + x_R)*G = %s\nY_F + Y_P + Y_R     = %s",
					curve, yFromSecretSum.Hex(), yFromPointAddition.Hex())
			}

			// Verify coordinates match
			if yFromSecretSum.X.Cmp(yFromPointAddition.X) != 0 || yFromSecretSum.Y.Cmp(yFromPointAddition.Y) != 0 {
				t.Fatalf("Coordinate mismatch between secret sum and public point addition on curve %s", curve)
			}
		})
	}
}
