package rpc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

// CurvePoint represents an affine point (X, Y) on an elliptic curve.
type CurvePoint struct {
	X *big.Int
	Y *big.Int
}

// Secp256k1 Curve Constants
var (
	Secp256k1P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	Secp256k1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	Secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Secp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	// Ed25519 (Edwards25519) Constants
	Ed25519P, _  = new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16) // 2^255 - 19
	Ed25519L, _  = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16) // Order L
	Ed25519D, _  = new(big.Int).SetString("52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3", 16) // d = -121665/121666 mod P
	Ed25519Bx, _ = new(big.Int).SetString("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A", 16)
	Ed25519By, _ = new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16) // 4/5 mod P
)

// Secp256k1 Point Addition: P1 + P2 on y^2 = x^3 + 7 mod P
func Secp256k1Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			return big.NewInt(0), big.NewInt(0)
		}
		// Point doubling: m = 3*x1^2 / (2*y1) mod P
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1))
		num.Mod(num, Secp256k1P)
		den := new(big.Int).Mul(big.NewInt(2), y1)
		den.Mod(den, Secp256k1P)
		inv := new(big.Int).ModInverse(den, Secp256k1P)
		if inv == nil {
			return big.NewInt(0), big.NewInt(0)
		}
		m := new(big.Int).Mul(num, inv)
		m.Mod(m, Secp256k1P)

		x3 := new(big.Int).Mul(m, m)
		x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x1))
		x3.Mod(x3, Secp256k1P)
		if x3.Sign() < 0 {
			x3.Add(x3, Secp256k1P)
		}

		y3 := new(big.Int).Sub(x1, x3)
		y3.Mul(y3, m)
		y3.Sub(y3, y1)
		y3.Mod(y3, Secp256k1P)
		if y3.Sign() < 0 {
			y3.Add(y3, Secp256k1P)
		}
		return x3, y3
	}

	// Point addition: m = (y2 - y1) / (x2 - x1) mod P
	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, Secp256k1P)
	if num.Sign() < 0 {
		num.Add(num, Secp256k1P)
	}
	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, Secp256k1P)
	if den.Sign() < 0 {
		den.Add(den, Secp256k1P)
	}
	inv := new(big.Int).ModInverse(den, Secp256k1P)
	if inv == nil {
		return big.NewInt(0), big.NewInt(0)
	}
	m := new(big.Int).Mul(num, inv)
	m.Mod(m, Secp256k1P)

	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, Secp256k1P)
	if x3.Sign() < 0 {
		x3.Add(x3, Secp256k1P)
	}

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y1)
	y3.Mod(y3, Secp256k1P)
	if y3.Sign() < 0 {
		y3.Add(y3, Secp256k1P)
	}
	return x3, y3
}

// Secp256k1 Scalar Multiplication: k * (x, y) on secp256k1
func Secp256k1ScalarMult(x, y, k *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(0)
	bx, by := new(big.Int).Set(x), new(big.Int).Set(y)
	b := new(big.Int).Set(k)

	for b.Sign() > 0 {
		if b.Bit(0) == 1 {
			rx, ry = Secp256k1Add(rx, ry, bx, by)
		}
		bx, by = Secp256k1Add(bx, by, bx, by)
		b.Rsh(b, 1)
	}
	return rx, ry
}

// Ed25519 Point Addition on twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2 mod P
func Ed25519Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2) mod P
	numX := new(big.Int).Add(new(big.Int).Mul(x1, y2), new(big.Int).Mul(y1, x2))
	numX.Mod(numX, Ed25519P)

	x1x2 := new(big.Int).Mul(x1, x2)
	x1x2.Mod(x1x2, Ed25519P)
	y1y2 := new(big.Int).Mul(y1, y2)
	y1y2.Mod(y1y2, Ed25519P)
	dx1x2y1y2 := new(big.Int).Mul(Ed25519D, new(big.Int).Mul(x1x2, y1y2))
	dx1x2y1y2.Mod(dx1x2y1y2, Ed25519P)

	denX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	denX.Mod(denX, Ed25519P)
	invDenX := new(big.Int).ModInverse(denX, Ed25519P)
	x3 := new(big.Int).Mul(numX, invDenX)
	x3.Mod(x3, Ed25519P)

	// y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2) mod P
	numY := new(big.Int).Add(y1y2, x1x2)
	numY.Mod(numY, Ed25519P)

	denY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	denY.Mod(denY, Ed25519P)
	if denY.Sign() < 0 {
		denY.Add(denY, Ed25519P)
	}
	invDenY := new(big.Int).ModInverse(denY, Ed25519P)
	y3 := new(big.Int).Mul(numY, invDenY)
	y3.Mod(y3, Ed25519P)

	return x3, y3
}

// Ed25519 Scalar Multiplication: k * (x, y) on Edwards25519
func Ed25519ScalarMult(x, y, k *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(1) // identity point is (0, 1)
	bx, by := new(big.Int).Set(x), new(big.Int).Set(y)
	b := new(big.Int).Set(k)

	for b.Sign() > 0 {
		if b.Bit(0) == 1 {
			rx, ry = Ed25519Add(rx, ry, bx, by)
		}
		bx, by = Ed25519Add(bx, by, bx, by)
		b.Rsh(b, 1)
	}
	return rx, ry
}

// ParseCurvePointFromBytes parses 65-byte uncompressed, 33-byte compressed, or 32-byte Ed25519 point bytes.
func ParseCurvePointFromBytes(b []byte) (*CurvePoint, error) {
	if len(b) == 65 {
		if b[0] != 0x04 {
			return nil, fmt.Errorf("invalid prefix 0x%02x for uncompressed point", b[0])
		}
		x := new(big.Int).SetBytes(b[1:33])
		y := new(big.Int).SetBytes(b[33:65])
		return &CurvePoint{X: x, Y: y}, nil
	} else if len(b) == 33 {
		curve := elliptic.P256()
		x, y := elliptic.UnmarshalCompressed(curve, b)
		if x != nil && y != nil {
			return &CurvePoint{X: x, Y: y}, nil
		}
		// Also support secp256k1 compressed parsing
		xVal := new(big.Int).SetBytes(b[1:33])
		// y^2 = x^3 + 7 mod P
		x3 := new(big.Int).Exp(xVal, big.NewInt(3), Secp256k1P)
		rhs := new(big.Int).Add(x3, big.NewInt(7))
		rhs.Mod(rhs, Secp256k1P)
		// y = rhs^((P+1)/4) mod P
		exp := new(big.Int).Add(Secp256k1P, big.NewInt(1))
		exp.Rsh(exp, 2)
		yVal := new(big.Int).Exp(rhs, exp, Secp256k1P)
		isOdd := b[0] == 0x03
		if (yVal.Bit(0) == 1) != isOdd {
			yVal.Sub(Secp256k1P, yVal)
		}
		return &CurvePoint{X: xVal, Y: yVal}, nil
	} else if len(b) == 32 {
		// Ed25519 32-byte compressed point: y is in bytes[0..30] and top bit of byte 31 is x sign
		yBytes := make([]byte, 32)
		copy(yBytes, b)
		xBit := (yBytes[31] >> 7) & 1
		yBytes[31] &= 0x7F

		// Reverse to big-endian for math/big
		beBytes := make([]byte, 32)
		for i := 0; i < 32; i++ {
			beBytes[i] = yBytes[31-i]
		}
		yVal := new(big.Int).SetBytes(beBytes)

		// Recover x: x^2 = (y^2 - 1) / (d*y^2 + 1) mod P
		y2 := new(big.Int).Mul(yVal, yVal)
		y2.Mod(y2, Ed25519P)
		u := new(big.Int).Sub(y2, big.NewInt(1))
		u.Mod(u, Ed25519P)
		if u.Sign() < 0 {
			u.Add(u, Ed25519P)
		}

		v := new(big.Int).Mul(Ed25519D, y2)
		v.Add(v, big.NewInt(1))
		v.Mod(v, Ed25519P)
		invV := new(big.Int).ModInverse(v, Ed25519P)
		if invV == nil {
			return &CurvePoint{X: big.NewInt(0), Y: yVal}, nil
		}
		x2 := new(big.Int).Mul(u, invV)
		x2.Mod(x2, Ed25519P)

		// Square root mod P (P = 5 mod 8, so standard sqrt)
		exp := new(big.Int).Add(Ed25519P, big.NewInt(3))
		exp.Rsh(exp, 3)
		xVal := new(big.Int).Exp(x2, exp, Ed25519P)
		if (xVal.Bit(0) == 1) != (xBit == 1) {
			xVal.Sub(Ed25519P, xVal)
		}
		return &CurvePoint{X: xVal, Y: yVal}, nil
	}
	return nil, fmt.Errorf("invalid point length %d (expected 32, 33, or 65 bytes)", len(b))
}

// LagrangeCoefficientAtZero computes lambda_i(0) = \prod_{j != i} (0 - x_j) / (x_i - x_j) mod order
func LagrangeCoefficientAtZero(iIndex int, allIndices []int, order *big.Int) (*big.Int, error) {
	xi := big.NewInt(int64(iIndex))
	num := big.NewInt(1)
	den := big.NewInt(1)

	for _, jIndex := range allIndices {
		if jIndex == iIndex {
			continue
		}
		xj := big.NewInt(int64(jIndex))

		negXj := new(big.Int).Neg(xj)
		negXj.Mod(negXj, order)
		num.Mul(num, negXj)
		num.Mod(num, order)

		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, order)
		if diff.Sign() == 0 {
			return nil, fmt.Errorf("duplicate participant index in Lagrange interpolation: %d", iIndex)
		}
		den.Mul(den, diff)
		den.Mod(den, order)
	}

	denInv := new(big.Int).ModInverse(den, order)
	if denInv == nil {
		return nil, fmt.Errorf("modular inverse does not exist for denominator in Lagrange interpolation")
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, order)
	return lambda, nil
}

// InterpolatePublicContributionsAtZero computes Y = \sum_{i=1}^k \lambda_i(0) * Y_i on NIST P-256 (default)
func InterpolatePublicContributionsAtZero(indices []int, points []*CurvePoint) (*CurvePoint, error) {
	return InterpolatePublicContributionsAtZeroForCurve(indices, points, "nist-p256")
}

// InterpolatePublicContributionsAtZeroForCurve computes Y = \sum_{i=1}^k \lambda_i(0) * Y_i on secp256k1, ed25519, or nist-p256.
func InterpolatePublicContributionsAtZeroForCurve(indices []int, points []*CurvePoint, curveName string) (*CurvePoint, error) {
	if len(indices) != len(points) || len(indices) == 0 {
		return nil, fmt.Errorf("indices and points count mismatch or empty")
	}

	normCurve := strings.ToLower(strings.TrimSpace(curveName))
	switch {
	case strings.Contains(normCurve, "secp256k1"):
		accX := big.NewInt(0)
		accY := big.NewInt(0)
		for i, pt := range points {
			lambda, err := LagrangeCoefficientAtZero(indices[i], indices, Secp256k1N)
			if err != nil {
				return nil, err
			}
			tx, ty := Secp256k1ScalarMult(pt.X, pt.Y, lambda)
			accX, accY = Secp256k1Add(accX, accY, tx, ty)
		}
		return &CurvePoint{X: accX, Y: accY}, nil

	case strings.Contains(normCurve, "ed25519"):
		accX := big.NewInt(0)
		accY := big.NewInt(1) // identity point on Edwards25519 is (0, 1)
		for i, pt := range points {
			lambda, err := LagrangeCoefficientAtZero(indices[i], indices, Ed25519L)
			if err != nil {
				return nil, err
			}
			tx, ty := Ed25519ScalarMult(pt.X, pt.Y, lambda)
			accX, accY = Ed25519Add(accX, accY, tx, ty)
		}
		return &CurvePoint{X: accX, Y: accY}, nil

	default: // NIST P-256
		curve := elliptic.P256()
		order := curve.Params().N
		accX := big.NewInt(0)
		accY := big.NewInt(0)
		for i, pt := range points {
			lambda, err := LagrangeCoefficientAtZero(indices[i], indices, order)
			if err != nil {
				return nil, err
			}
			tx, ty := curve.ScalarMult(pt.X, pt.Y, lambda.Bytes())
			if accX.Sign() == 0 && accY.Sign() == 0 {
				accX = tx
				accY = ty
			} else {
				accX, accY = curve.Add(accX, accY, tx, ty)
			}
		}
		return &CurvePoint{X: accX, Y: accY}, nil
	}
}

// --- Keccak-256 Hash Implementation ---

var keccakRoundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [5][5]uint{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

func keccakF1600(state *[5][5]uint64) {
	for round := 0; round < 24; round++ {
		var C [5]uint64
		for x := 0; x < 5; x++ {
			C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
		}
		var D [5]uint64
		for x := 0; x < 5; x++ {
			D[x] = C[(x+4)%5] ^ bits.RotateLeft64(C[(x+1)%5], 1)
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				state[x][y] ^= D[x]
			}
		}

		var B [5][5]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				B[y][(2*x+3*y)%5] = bits.RotateLeft64(state[x][y], int(keccakRot[x][y]))
			}
		}

		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				state[x][y] = B[x][y] ^ ((^B[(x+1)%5][y]) & B[(x+2)%5][y])
			}
		}

		state[0][0] ^= keccakRoundConstants[round]
	}
}

// Keccak256 computes standard Ethereum Keccak-256 hash.
func Keccak256(data []byte) []byte {
	rate := 136
	var state [5][5]uint64

	offset := 0
	for offset+rate <= len(data) {
		for i := 0; i < rate/8; i++ {
			x := i % 5
			y := i / 5
			w := uint64(data[offset+i*8]) |
				uint64(data[offset+i*8+1])<<8 |
				uint64(data[offset+i*8+2])<<16 |
				uint64(data[offset+i*8+3])<<24 |
				uint64(data[offset+i*8+4])<<32 |
				uint64(data[offset+i*8+5])<<40 |
				uint64(data[offset+i*8+6])<<48 |
				uint64(data[offset+i*8+7])<<56
			state[x][y] ^= w
		}
		keccakF1600(&state)
		offset += rate
	}

	padded := make([]byte, rate)
	rem := len(data) - offset
	copy(padded, data[offset:])
	padded[rem] = 0x01
	padded[rate-1] |= 0x80

	for i := 0; i < rate/8; i++ {
		x := i % 5
		y := i / 5
		w := uint64(padded[i*8]) |
			uint64(padded[i*8+1])<<8 |
			uint64(padded[i*8+2])<<16 |
			uint64(padded[i*8+3])<<24 |
			uint64(padded[i*8+4])<<32 |
			uint64(padded[i*8+5])<<40 |
			uint64(padded[i*8+6])<<48 |
			uint64(padded[i*8+7])<<56
		state[x][y] ^= w
	}
	keccakF1600(&state)

	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		x := i % 5
		y := i / 5
		w := state[x][y]
		out[i*8] = byte(w)
		out[i*8+1] = byte(w >> 8)
		out[i*8+2] = byte(w >> 16)
		out[i*8+3] = byte(w >> 24)
		out[i*8+4] = byte(w >> 32)
		out[i*8+5] = byte(w >> 40)
		out[i*8+6] = byte(w >> 48)
		out[i*8+7] = byte(w >> 56)
	}
	return out
}

// DeriveEvmAddress derives standard EIP-55 checksummed EVM address from uncompressed secp256k1 point
func DeriveEvmAddress(pt *CurvePoint) string {
	pubBytes := make([]byte, 64)
	xBytes := pt.X.Bytes()
	yBytes := pt.Y.Bytes()
	copy(pubBytes[32-len(xBytes):32], xBytes)
	copy(pubBytes[64-len(yBytes):64], yBytes)

	h := Keccak256(pubBytes)
	rawAddr := hex.EncodeToString(h[12:32]) // 20 bytes

	// EIP-55 Checksum
	clean := strings.ToLower(rawAddr)
	hash := hex.EncodeToString(Keccak256([]byte(clean)))

	var result strings.Builder
	result.WriteString("0x")
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c >= '0' && c <= '9' {
			result.WriteByte(c)
		} else {
			nibble := hash[i]
			if nibble >= '8' {
				result.WriteByte(c - 32)
			} else {
				result.WriteByte(c)
			}
		}
	}
	return result.String()
}

// DeriveSolanaAddress derives Base58 Solana address from Ed25519 point
func DeriveSolanaAddress(pt *CurvePoint) string {
	// 32-byte Ed25519 public key: little-endian y with x-sign in bit 7 of byte 31
	yBytes := pt.Y.Bytes()
	le := make([]byte, 32)
	for i := 0; i < len(yBytes); i++ {
		le[i] = yBytes[len(yBytes)-1-i]
	}
	if pt.X.Bit(0) == 1 {
		le[31] |= 0x80
	}
	return EncodeBase58(le)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func EncodeBase58(input []byte) string {
	digits := []byte{0}
	for _, b := range input {
		carry := int(b)
		for j := 0; j < len(digits); j++ {
			carry += int(digits[j]) << 8
			digits[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	var res strings.Builder
	for _, b := range input {
		if b == 0 {
			res.WriteByte(base58Alphabet[0])
		} else {
			break
		}
	}
	for i := len(digits) - 1; i >= 0; i-- {
		res.WriteByte(base58Alphabet[digits[i]])
	}
	return res.String()
}

// TaggedHash computes SHA256(SHA256(tag) || SHA256(tag) || data) for BIP-340/341 Taproot
func TaggedHash(tag string, data []byte) []byte {
	hTag := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(hTag[:])
	h.Write(hTag[:])
	h.Write(data)
	return h.Sum(nil)
}

// DeriveBitcoinTaprootAddress derives BIP-340/341 Taproot address from secp256k1 point
func DeriveBitcoinTaprootAddress(pt *CurvePoint, hrp string) string {
	xBytes := make([]byte, 32)
	rawX := pt.X.Bytes()
	copy(xBytes[32-len(rawX):32], rawX)

	// If y is odd, negate point P so y is even
	pY := new(big.Int).Set(pt.Y)
	if pY.Bit(0) == 1 {
		pY.Sub(Secp256k1P, pY)
	}

	// TapTweak t = TaggedHash("TapTweak", P_x)
	tweakBytes := TaggedHash("TapTweak", xBytes)
	tweakScalar := new(big.Int).SetBytes(tweakBytes)

	// Q = P + t*G
	tGx, tGy := Secp256k1ScalarMult(Secp256k1Gx, Secp256k1Gy, tweakScalar)
	qx, _ := Secp256k1Add(pt.X, pY, tGx, tGy)

	qXBytes := make([]byte, 32)
	rawQx := qx.Bytes()
	copy(qXBytes[32-len(rawQx):32], rawQx)

	return EncodeBech32m(hrp, 1, qXBytes)
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	generators := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= generators[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, int(hrp[i]>>5))
	}
	ret = append(ret, 0)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, int(hrp[i]&31))
	}
	return ret
}

func convertBits(data []byte, frombits, tobits uint, pad bool) ([]int, error) {
	acc := uint(0)
	bitsCount := uint(0)
	var ret []int
	maxv := uint((1 << tobits) - 1)
	for _, val := range data {
		acc = (acc << frombits) | uint(val)
		bitsCount += frombits
		for bitsCount >= tobits {
			bitsCount -= tobits
			ret = append(ret, int((acc>>bitsCount)&maxv))
		}
	}
	if pad {
		if bitsCount > 0 {
			ret = append(ret, int((acc<<(tobits-bitsCount))&maxv))
		}
	} else if bitsCount >= frombits || ((acc<<(tobits-bitsCount))&maxv) != 0 {
		return nil, fmt.Errorf("invalid bit padding")
	}
	return ret, nil
}

// EncodeBech32m encodes witness version and program into BIP-350 Bech32m address
func EncodeBech32m(hrp string, witnessVersion int, program []byte) string {
	const bech32mConst = 0x2bc830a3
	converted, _ := convertBits(program, 8, 5, true)
	data := append([]int{witnessVersion}, converted...)

	expHrp := hrpExpand(hrp)
	poly := append(expHrp, data...)
	poly = append(poly, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(poly) ^ bech32mConst

	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (mod >> (5 * (5 - i))) & 31
	}

	var res strings.Builder
	res.WriteString(hrp)
	res.WriteString("1")
	for _, d := range data {
		res.WriteByte(bech32Charset[d])
	}
	for _, c := range checksum {
		res.WriteByte(bech32Charset[c])
	}
	return res.String()
}
