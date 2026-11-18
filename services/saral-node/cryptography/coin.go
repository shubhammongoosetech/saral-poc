package cryptography

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrInsufficientCoinShares = errors.New("insufficient valid coin shares for threshold reconstruction")
	ErrInvalidCoinProof       = errors.New("invalid discrete log equality proof for coin share")
	ErrDuplicateCoinShare     = errors.New("duplicate coin share from participant")
)

// DLEQProof is a non-interactive zero-knowledge Chaum-Pedersen proof of discrete logarithm equality:
// Proves log_G(PK) == log_H(Sigma) == sk without revealing sk.
type DLEQProof struct {
	Challenge *FieldElement `json:"challenge"`
	Response  *FieldElement `json:"response"`
}

// GenerateDLEQProof generates a Chaum-Pedersen proof that log_G(PK) == log_H(Sigma) = sk.
func GenerateDLEQProof(sk *FieldElement, G, PK, H, Sigma *CurvePoint) (*DLEQProof, error) {
	// 1. Pick random w in [1, q-1]
	w, err := RandScalar()
	if err != nil {
		return nil, err
	}

	// 2. Commitments: R1 = w * G, R2 = w * H
	R1 := G.ScalarMult(w)
	R2 := H.ScalarMult(w)

	// 3. Challenge c = SHA256(G || PK || H || Sigma || R1 || R2) mod q
	h := sha256.New()
	h.Write(G.Bytes())
	h.Write(PK.Bytes())
	h.Write(H.Bytes())
	h.Write(Sigma.Bytes())
	h.Write(R1.Bytes())
	h.Write(R2.Bytes())
	cBig := new(big.Int).SetBytes(h.Sum(nil))
	cBig.Mod(cBig, OrderQ)
	challenge, _ := NewFieldElementFromBigInt(cBig)

	// 4. Response z = w + c * sk mod q
	cSk := challenge.Mul(sk)
	response := w.Add(cSk)

	return &DLEQProof{
		Challenge: challenge,
		Response:  response,
	}, nil
}

// VerifyDLEQProof verifies the Chaum-Pedersen DLEQ proof:
// Checks c == SHA256(G || PK || H || Sigma || z*G - c*PK || z*H - c*Sigma) mod q
func VerifyDLEQProof(proof *DLEQProof, G, PK, H, Sigma *CurvePoint) bool {
	if proof == nil || proof.Challenge == nil || proof.Response == nil {
		return false
	}

	// Compute R1' = z * G - c * PK
	zG := G.ScalarMult(proof.Response)
	cPK := PK.ScalarMult(proof.Challenge)
	// Negate cPK
	negCPK := &CurvePoint{
		X: new(big.Int).Set(cPK.X),
		Y: new(big.Int).Sub(FieldP, cPK.Y),
	}
	negCPK.Y.Mod(negCPK.Y, FieldP)
	R1Prime := zG.Add(negCPK)

	// Compute R2' = z * H - c * Sigma
	zH := H.ScalarMult(proof.Response)
	cSigma := Sigma.ScalarMult(proof.Challenge)
	negCSigma := &CurvePoint{
		X: new(big.Int).Set(cSigma.X),
		Y: new(big.Int).Sub(FieldP, cSigma.Y),
	}
	negCSigma.Y.Mod(negCSigma.Y, FieldP)
	R2Prime := zH.Add(negCSigma)

	// Recompute challenge c'
	h := sha256.New()
	h.Write(G.Bytes())
	h.Write(PK.Bytes())
	h.Write(H.Bytes())
	h.Write(Sigma.Bytes())
	h.Write(R1Prime.Bytes())
	h.Write(R2Prime.Bytes())
	cPrimeBig := new(big.Int).SetBytes(h.Sum(nil))
	cPrimeBig.Mod(cPrimeBig, OrderQ)
	cPrime, _ := NewFieldElementFromBigInt(cPrimeBig)

	return proof.Challenge.Equal(cPrime)
}

// CoinKeyShare represents one node's threshold key share for the verifiable common coin.
type CoinKeyShare struct {
	CommitteeID     string
	NodeID          string
	NodeIndex       int
	SecretShare     *FieldElement
	PublicKeyShare  *CurvePoint
	MasterPublicKey *CurvePoint
	T               int
	N               int
}

// CoinShare represents a node's share of a common coin for a specific round.
type CoinShare struct {
	CommitteeID string     `json:"committeeId"`
	NodeID      string     `json:"nodeId"`
	NodeIndex   int        `json:"nodeIndex"`
	Round       int        `json:"round"`
	Tag         string     `json:"tag"`
	SharePoint  *CurvePoint `json:"sharePoint"`
	Proof       *DLEQProof `json:"proof"`
}

// SetupThresholdCoinKeys generates a (t+1)-of-n Shamir secret sharing of a master coin secret key.
// Used for initializing committee threshold coin keys.
func SetupThresholdCoinKeys(committeeID string, committee []string, t int, masterSeed string) (map[string]*CoinKeyShare, *CurvePoint, error) {
	n := len(committee)
	if t <= 0 || n <= 3*t {
		return nil, nil, fmt.Errorf("invalid threshold parameters for coin setup: n=%d, t=%d (requires n > 3t)", n, t)
	}

	// 1. Master secret key in Z_q
	var masterSK *FieldElement
	if masterSeed != "" {
		masterSK = DeterministicScalar(masterSeed, 0)
	} else {
		var err error
		masterSK, err = RandScalar()
		if err != nil {
			return nil, nil, err
		}
	}
	masterPK := GeneratorG.ScalarMult(masterSK)

	// 2. Generate random polynomial of degree t with P(0) = masterSK
	polyCoeffs := make([]*FieldElement, t+1)
	polyCoeffs[0] = masterSK
	for i := 1; i <= t; i++ {
		if masterSeed != "" {
			polyCoeffs[i] = DeterministicScalar(masterSeed, i)
		} else {
			r, err := RandScalar()
			if err != nil {
				return nil, nil, err
			}
			polyCoeffs[i] = r
		}
	}

	evalPoly := func(x int64) *FieldElement {
		feX := NewFieldElement(x)
		res := polyCoeffs[t]
		for i := t - 1; i >= 0; i-- {
			res = res.Mul(feX).Add(polyCoeffs[i])
		}
		return res
	}

	// 3. Distribute shares to each committee member (using 1-based indices)
	shares := make(map[string]*CoinKeyShare, n)
	for idx, id := range committee {
		nodeIndex := idx + 1
		skI := evalPoly(int64(nodeIndex))
		pkI := GeneratorG.ScalarMult(skI)

		shares[id] = &CoinKeyShare{
			CommitteeID:     committeeID,
			NodeID:          id,
			NodeIndex:       nodeIndex,
			SecretShare:     skI,
			PublicKeyShare:  pkI,
			MasterPublicKey: masterPK,
			T:               t,
			N:               n,
		}
	}

	return shares, masterPK, nil
}

// GenerateShare generates a verifiable coin share for the specified round and session tag.
func (ks *CoinKeyShare) GenerateShare(round int, sessionTag string) (*CoinShare, error) {
	tag := fmt.Sprintf("%s:round:%d", sessionTag, round)
	H, err := HashToCurve(tag)
	if err != nil {
		return nil, fmt.Errorf("failed to derive hash-to-curve for coin: %w", err)
	}

	// Compute coin point Sigma = sk * H
	Sigma := H.ScalarMult(ks.SecretShare)

	// Generate non-interactive DLEQ proof
	proof, err := GenerateDLEQProof(ks.SecretShare, GeneratorG, ks.PublicKeyShare, H, Sigma)
	if err != nil {
		return nil, fmt.Errorf("failed generating coin DLEQ proof: %w", err)
	}

	return &CoinShare{
		CommitteeID: ks.CommitteeID,
		NodeID:      ks.NodeID,
		NodeIndex:   ks.NodeIndex,
		Round:       round,
		Tag:         tag,
		SharePoint:  Sigma,
		Proof:       proof,
	}, nil
}

// VerifyCoinShare verifies a participant's coin share using the DLEQ proof against their public key.
func VerifyCoinShare(share *CoinShare, pkShare *CurvePoint, sessionTag string) bool {
	if share == nil || pkShare == nil || share.SharePoint == nil || share.Proof == nil {
		return false
	}
	tag := fmt.Sprintf("%s:round:%d", sessionTag, share.Round)
	H, err := HashToCurve(tag)
	if err != nil {
		return false
	}
	return VerifyDLEQProof(share.Proof, GeneratorG, pkShare, H, share.SharePoint)
}

// CombineCoinShares reconstructs the unique common coin from >= t+1 valid shares using Lagrange interpolation.
// Returns the unpredictable common coin bit b in {0, 1}.
func CombineCoinShares(shares []*CoinShare, t int) (int, error) {
	if len(shares) < t+1 {
		return 0, fmt.Errorf("%w: have %d, require %d", ErrInsufficientCoinShares, len(shares), t+1)
	}

	// Deduplicate by NodeIndex
	seen := make(map[int]bool)
	uniqueShares := make([]*CoinShare, 0, t+1)
	for _, s := range shares {
		if !seen[s.NodeIndex] {
			seen[s.NodeIndex] = true
			uniqueShares = append(uniqueShares, s)
			if len(uniqueShares) == t+1 {
				break
			}
		}
	}
	if len(uniqueShares) < t+1 {
		return 0, ErrInsufficientCoinShares
	}

	// Build Lagrange interpolation coefficients at x = 0
	xTarget := NewFieldElement(0)
	xCoords := make([]*FieldElement, t+1)
	for i := 0; i < t+1; i++ {
		xCoords[i] = NewFieldElement(int64(uniqueShares[i].NodeIndex))
	}

	// Interpolate Sigma = \sum_{i=1}^{t+1} \lambda_i(0) * Sigma_i
	combinedSigma := &CurvePoint{X: Zero, Y: Zero}
	for i := 0; i < t+1; i++ {
		lambdaI, err := LagrangeCoefficient(xTarget, xCoords[i], xCoords)
		if err != nil {
			return 0, fmt.Errorf("lagrange inversion failed for coin share %d: %w", uniqueShares[i].NodeIndex, err)
		}
		term := uniqueShares[i].SharePoint.ScalarMult(lambdaI)
		combinedSigma = combinedSigma.Add(term)
	}

	// Final coin bit = SHA-256(combinedSigma)[0] mod 2
	h := sha256.New()
	h.Write(combinedSigma.Bytes())
	var roundBuf [4]byte
	binary.BigEndian.PutUint32(roundBuf[:], uint32(uniqueShares[0].Round))
	h.Write(roundBuf[:])
	digest := h.Sum(nil)

	coinBit := int(digest[0] & 1)
	return coinBit, nil
}
