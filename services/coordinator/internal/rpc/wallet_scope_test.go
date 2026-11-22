package rpc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestVerifiedWalletKeyAcrossQuorums(t *testing.T) {
	edX, _ := new(big.Int).SetString("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16)
	edY, _ := new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16)
	for _, tc := range []struct {
		curve       string
		order, x, y *big.Int
		multiply    func(x, y, scalar *big.Int) (*big.Int, *big.Int)
	}{
		{"secp256k1", Secp256k1N, Secp256k1Gx, Secp256k1Gy, Secp256k1ScalarMult},
		{"ed25519", Ed25519L, edX, edY, Ed25519ScalarMult},
	} {
		t.Run(tc.curve, func(t *testing.T) {
			masterX, masterY := tc.multiply(tc.x, tc.y, big.NewInt(7))
			key := fmt.Sprintf("04%064x%064x", masterX, masterY)
			encoded, _ := hex.DecodeString(key)
			digest := sha256.Sum256(encoded)
			var shares []walletPublicContribution
			for i := 1; i <= 5; i++ {
				// The polynomial wraps in the correct scalar field, exposing any mismatched-order use.
				scalar := big.NewInt(int64(7 - i - i*i))
				scalar.Mod(scalar, tc.order)
				x, y := tc.multiply(tc.x, tc.y, scalar)
				point, err := decodeWalletPublicPoint(fmt.Sprintf("04%064x%064x", x, y), tc.curve)
				if err != nil {
					t.Fatal(err)
				}
				shares = append(shares, walletPublicContribution{i, point, digest})
			}
			for _, quorum := range [][]walletPublicContribution{shares[:3], shares[2:], {shares[0], shares[2], shares[4]}} {
				got, _, err := reconstructVerifiedWalletKey(quorum, tc.curve)
				if err != nil || got != key {
					t.Fatalf("valid quorum returned %s, %v", got, err)
				}
			}

			wrong := shares[0]
			wrong.point = shares[4].point
			if _, _, err := reconstructVerifiedWalletKey([]walletPublicContribution{wrong, shares[1], shares[2]}, tc.curve); err == nil {
				t.Fatal("a share that disagrees with the master commitment was accepted")
			}
			got, _, err := reconstructVerifiedWalletKey([]walletPublicContribution{wrong, shares[1], shares[2], shares[3]}, tc.curve)
			if err != nil || got != key {
				t.Fatal("an invalid contribution displaced a valid quorum")
			}
		})
	}
}
