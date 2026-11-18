package cryptography_test

import (
	"math/big"
	"testing"

	"github.com/saral-protocol/saral-poc/services/saral-node/cryptography"
)

func TestFieldElementArithmetic(t *testing.T) {
	// 1. Basic operations
	a := cryptography.NewFieldElement(10)
	b := cryptography.NewFieldElement(25)

	// Addition
	c := a.Add(b)
	expected := cryptography.NewFieldElement(35)
	if !c.Equal(expected) {
		t.Fatalf("expected 10 + 25 = 35, got %s", c.Hex())
	}

	// Subtraction with wrap-around
	d := a.Sub(b)
	// 10 - 25 = -15 = OrderQ - 15
	expectedSub := new(big.Int).Sub(cryptography.OrderQ, big.NewInt(15))
	if d.BigInt().Cmp(expectedSub) != 0 {
		t.Fatalf("expected wrap-around subtraction OrderQ - 15, got %s", d.Hex())
	}

	// Inverse and Division
	invA, err := a.Inv()
	if err != nil {
		t.Fatalf("failed to compute inverse: %v", err)
	}
	prod := a.Mul(invA)
	if !prod.Equal(cryptography.NewFieldElement(1)) {
		t.Fatalf("expected a * a^-1 = 1, got %s", prod.Hex())
	}

	divResult, err := b.Div(a)
	if err != nil {
		t.Fatalf("failed to divide: %v", err)
	}
	recoveredB := divResult.Mul(a)
	if !recoveredB.Equal(b) {
		t.Fatalf("expected (b / a) * a == b, got %s vs %s", recoveredB.Hex(), b.Hex())
	}

	// Division by zero must fail
	zero := cryptography.NewFieldElement(0)
	_, err = zero.Inv()
	if err != cryptography.ErrZeroDivision {
		t.Fatalf("expected ErrZeroDivision, got %v", err)
	}
	_, err = b.Div(zero)
	if err != cryptography.ErrZeroDivision {
		t.Fatalf("expected ErrZeroDivision on b/0, got %v", err)
	}
}

func TestCanonicalScalarEncodingRejection(t *testing.T) {
	// Scalar >= OrderQ must be strictly rejected
	orderBytes := cryptography.OrderQ.Bytes()
	_, err := cryptography.NewFieldElementFromBytes(orderBytes)
	if err == nil {
		t.Fatalf("expected rejection of scalar == OrderQ")
	}

	// OrderQ + 1 must be rejected
	orderPlusOne := new(big.Int).Add(cryptography.OrderQ, big.NewInt(1))
	_, err = cryptography.NewFieldElementFromBytes(orderPlusOne.Bytes())
	if err == nil {
		t.Fatalf("expected rejection of scalar > OrderQ")
	}

	// Invalid length must be rejected
	shortBytes := make([]byte, 31)
	_, err = cryptography.NewFieldElementFromBytes(shortBytes)
	if err == nil {
		t.Fatalf("expected rejection of 31-byte scalar")
	}

	longBytes := make([]byte, 33)
	_, err = cryptography.NewFieldElementFromBytes(longBytes)
	if err == nil {
		t.Fatalf("expected rejection of 33-byte scalar")
	}

	// Max canonical value: OrderQ - 1
	maxValid := new(big.Int).Sub(cryptography.OrderQ, big.NewInt(1))
	maxElem, err := cryptography.NewFieldElementFromBytes(maxValid.Bytes())
	if err != nil {
		t.Fatalf("OrderQ - 1 must be valid, got: %v", err)
	}
	if maxElem.IsZero() {
		t.Fatalf("OrderQ - 1 should not be zero")
	}
}

func TestCurveOperationsAndGeneratorH(t *testing.T) {
	// Check GeneratorG is valid and on curve
	if !cryptography.GeneratorG.IsOnCurve() {
		t.Fatalf("GeneratorG is not on curve")
	}

	// Check GeneratorH is valid and on curve
	if !cryptography.GeneratorH.IsOnCurve() {
		t.Fatalf("GeneratorH is not on curve")
	}

	// Check GeneratorG != GeneratorH
	if cryptography.GeneratorG.Equal(cryptography.GeneratorH) {
		t.Fatalf("GeneratorG and GeneratorH must be distinct")
	}

	// Order check: OrderQ * G == infinity
	qScalar, _ := cryptography.NewFieldElementFromBigInt(cryptography.NewFieldElement(0).BigInt())
	infG := cryptography.GeneratorG.ScalarMult(qScalar)
	if infG.X.Sign() != 0 || infG.Y.Sign() != 0 {
		t.Fatalf("0 * G must be point at infinity, got (%s, %s)", infG.X.String(), infG.Y.String())
	}

	// Test point addition
	pt1 := cryptography.GeneratorG.ScalarMult(cryptography.NewFieldElement(2))
	pt2 := cryptography.GeneratorG.ScalarMult(cryptography.NewFieldElement(3))
	ptSum := pt1.Add(pt2)
	ptExpected := cryptography.GeneratorG.ScalarMult(cryptography.NewFieldElement(5))
	if !ptSum.Equal(ptExpected) {
		t.Fatalf("expected 2*G + 3*G = 5*G")
	}

	// Test point serialization roundtrip
	bytesUncompressed := ptSum.Bytes()
	parsedPt, err := cryptography.ParseCurvePointFromBytes(bytesUncompressed)
	if err != nil {
		t.Fatalf("failed to parse uncompressed point: %v", err)
	}
	if !parsedPt.Equal(ptSum) {
		t.Fatalf("parsed point does not match original")
	}

	// Malformed point rejection
	corrupted := make([]byte, len(bytesUncompressed))
	copy(corrupted, bytesUncompressed)
	corrupted[10] ^= 0xff
	_, err = cryptography.ParseCurvePointFromBytes(corrupted)
	if err == nil {
		t.Fatalf("expected rejection of corrupted point not on curve")
	}
}

func TestPedersenCommitmentHomomorphism(t *testing.T) {
	v1 := cryptography.NewFieldElement(42)
	r1 := cryptography.NewFieldElement(101)
	c1 := cryptography.PedersenCommitment(v1, r1)

	v2 := cryptography.NewFieldElement(58)
	r2 := cryptography.NewFieldElement(202)
	c2 := cryptography.PedersenCommitment(v2, r2)

	// Homomorphic addition: c1 + c2 == Commit(v1+v2, r1+r2)
	cSum := c1.Add(c2)
	vSum := v1.Add(v2) // 42 + 58 = 100
	rSum := r1.Add(r2) // 101 + 202 = 303
	expectedSum := cryptography.PedersenCommitment(vSum, rSum)

	if !cSum.Equal(expectedSum) {
		t.Fatalf("Pedersen addition homomorphism failed:\n got:  %s\n want: %s", cSum.Hex(), expectedSum.Hex())
	}

	// Homomorphic scalar multiplication: k * c1 == Commit(k*v1, k*r1)
	k := cryptography.NewFieldElement(7)
	cScaled := c1.ScalarMult(k)
	vScaled := v1.Mul(k)
	rScaled := r1.Mul(k)
	expectedScaled := cryptography.PedersenCommitment(vScaled, rScaled)

	if !cScaled.Equal(expectedScaled) {
		t.Fatalf("Pedersen scalar multiplication homomorphism failed:\n got:  %s\n want: %s", cScaled.Hex(), expectedScaled.Hex())
	}
}

func TestLagrangeInterpolation(t *testing.T) {
	// Degree 2 polynomial: f(x) = 15 + 7x + 3x^2 (mod q)
	// Secret s = f(0) = 15
	// Evaluate at x = 1, 2, 3
	secret := cryptography.NewFieldElement(15)
	c1 := cryptography.NewFieldElement(7)
	c2 := cryptography.NewFieldElement(3)

	evalPoly := func(x int64) *cryptography.FieldElement {
		feX := cryptography.NewFieldElement(x)
		x2 := feX.Mul(feX)
		// 15 + 7*x + 3*x^2
		res := secret.Add(c1.Mul(feX)).Add(c2.Mul(x2))
		return res
	}

	xPoints := []*cryptography.FieldElement{
		cryptography.NewFieldElement(1),
		cryptography.NewFieldElement(2),
		cryptography.NewFieldElement(3),
	}
	yPoints := []*cryptography.FieldElement{
		evalPoly(1), // 15 + 7(1) + 3(1) = 25
		evalPoly(2), // 15 + 7(2) + 3(4) = 41
		evalPoly(3), // 15 + 7(3) + 3(9) = 63
	}

	// Reconstruct f(0) using Lagrange interpolation
	xTarget := cryptography.NewFieldElement(0)
	reconstructed := cryptography.NewFieldElement(0)

	for i := range xPoints {
		lambda, err := cryptography.LagrangeCoefficient(xTarget, xPoints[i], xPoints)
		if err != nil {
			t.Fatalf("failed to compute Lagrange coefficient for i=%d: %v", i, err)
		}
		term := lambda.Mul(yPoints[i])
		reconstructed = reconstructed.Add(term)
	}

	if !reconstructed.Equal(secret) {
		t.Fatalf("Lagrange interpolation failed: got %s, want %s (15)", reconstructed.Hex(), secret.Hex())
	}
}

func TestRandomnessProperties(t *testing.T) {
	// Test CSPRNG returns valid scalars
	s1, err := cryptography.RandScalar()
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}
	if s1.IsZero() {
		t.Fatalf("RandScalar produced zero")
	}

	s2, err := cryptography.RandScalar()
	if err != nil {
		t.Fatalf("RandScalar failed: %v", err)
	}
	if s1.Equal(s2) {
		t.Fatalf("CSPRNG produced duplicate scalars: %s", s1.Hex())
	}

	// Test DeterministicScalar produces reproducible outputs
	det1 := cryptography.DeterministicScalar("test-seed", 1)
	det2 := cryptography.DeterministicScalar("test-seed", 1)
	if !det1.Equal(det2) {
		t.Fatalf("DeterministicScalar is not deterministic")
	}

	det3 := cryptography.DeterministicScalar("test-seed", 2)
	if det1.Equal(det3) {
		t.Fatalf("DeterministicScalar produced identical output for different indices")
	}
}

func TestNISTP256OrderVsFieldPrime(t *testing.T) {
	// Standard NIST P-256 constants
	expectedOrderHex := "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
	expectedPrimeHex := "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"

	actualOrderHex := cryptography.OrderQ.Text(16)
	actualPrimeHex := cryptography.FieldP.Text(16)

	if actualOrderHex != expectedOrderHex {
		t.Fatalf("NIST P-256 group order N mismatch: got %s, want %s", actualOrderHex, expectedOrderHex)
	}
	if actualPrimeHex != expectedPrimeHex {
		t.Fatalf("NIST P-256 base field prime P mismatch: got %s, want %s", actualPrimeHex, expectedPrimeHex)
	}

	// Verify that P > N
	if cryptography.FieldP.Cmp(cryptography.OrderQ) <= 0 {
		t.Fatalf("base field prime P must be strictly greater than subgroup order N on NIST P-256")
	}

	// Base field prime P must be rejected as scalar (P >= N)
	_, err := cryptography.NewFieldElementFromBigInt(cryptography.FieldP)
	if err == nil {
		t.Fatalf("expected rejection when attempting to use base field prime P as scalar")
	}

	// Order N must be rejected as scalar (N >= N)
	_, err = cryptography.NewFieldElementFromBigInt(cryptography.OrderQ)
	if err == nil {
		t.Fatalf("expected rejection when attempting to use group order N as scalar")
	}

	// N - 1 must be accepted
	nMinus1 := new(big.Int).Sub(cryptography.OrderQ, big.NewInt(1))
	feNMinus1, err := cryptography.NewFieldElementFromBigInt(nMinus1)
	if err != nil {
		t.Fatalf("N - 1 must be accepted as canonical scalar: %v", err)
	}

	// Mathematical self-inverse property: (N - 1)^2 = (-1)^2 = 1 mod N
	prod := feNMinus1.Mul(feNMinus1)
	if !prod.Equal(cryptography.NewFieldElement(1)) {
		t.Fatalf("(N - 1)^2 != 1 mod N: got %s", prod.Hex())
	}

	invNMinus1, err := feNMinus1.Inv()
	if err != nil {
		t.Fatalf("failed to invert N - 1: %v", err)
	}
	if !invNMinus1.Equal(feNMinus1) {
		t.Fatalf("expected (N - 1)^(-1) == N - 1 mod N, got %s", invNMinus1.Hex())
	}
}

func TestHashToCurveProperties(t *testing.T) {
	pt1, err := cryptography.HashToCurve("saral-test-tag-1")
	if err != nil {
		t.Fatalf("HashToCurve failed: %v", err)
	}
	if !pt1.IsOnCurve() {
		t.Fatalf("HashToCurve returned point not on NIST P-256 curve")
	}

	// Subgroup order check: N * pt1 == point at infinity (0, 0)
	infPt := pt1.ScalarMult(cryptography.NewFieldElement(0))
	if infPt.X.Sign() != 0 || infPt.Y.Sign() != 0 {
		t.Fatalf("0 * pt1 must be point at infinity")
	}

	pt2, err := cryptography.HashToCurve("saral-test-tag-2")
	if err != nil {
		t.Fatalf("HashToCurve failed on second tag: %v", err)
	}
	if pt1.Equal(pt2) {
		t.Fatalf("HashToCurve produced identical point for distinct tags")
	}
}
