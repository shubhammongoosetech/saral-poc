package cryptography

import (
	"crypto/sha256"
	"encoding/binary"
)

// ProveSigningCommitment links the dealer's signing point to its Pedersen
// commitment by proving knowledge of the blinding scalar.
func ProveSigningCommitment(context string, committed, signing *CurvePoint, blind *FieldElement) (string, string, error) {
	curve := blind.Curve()
	nonce, err := curve.RandomScalar()
	if err != nil {
		return "", "", err
	}
	defer nonce.Zero()
	announcement := curve.blindGenerator().ScalarMult(nonce)
	challenge := signingCommitmentChallenge(context, committed, signing, announcement)
	response := nonce.Add(challenge.Mul(blind))
	defer response.Zero()
	return announcement.Hex(), response.Hex(), nil
}

func VerifySigningCommitment(context string, committed, signing *CurvePoint, announcementHex, responseHex string) bool {
	curve := committed.Curve()
	announcement, err := curve.ParsePoint(announcementHex)
	if err != nil {
		return false
	}
	response, err := curve.ParseScalar(responseHex)
	if err != nil {
		return false
	}
	challenge := signingCommitmentChallenge(context, committed, signing, announcement)
	blinding := committed.Add(signing.ScalarMult(curve.Scalar(-1)))
	return curve.blindGenerator().ScalarMult(response).Equal(announcement.Add(blinding.ScalarMult(challenge)))
}

func signingCommitmentChallenge(context string, committed, signing, announcement *CurvePoint) *FieldElement {
	c := committed.Curve()
	hash := sha256.New()
	hash.Write([]byte("saral/dkg/signing-commitment/v1"))
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(context))))
	hash.Write([]byte(context))
	hash.Write(committed.Bytes())
	hash.Write(signing.Bytes())
	hash.Write(announcement.Bytes())
	scalar := c.Scalar(0)
	scalar.val.SetBytes(hash.Sum(nil)).Mod(scalar.val, c.order())
	return scalar
}
