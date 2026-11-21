import crypto from 'crypto';

// secp256k1 curve parameters
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function mod(a: bigint, m: bigint = P): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint = P): bigint {
  let res = 1n;
  let b = base % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return res;
}

function modInverse(k: bigint, m: bigint = P): bigint {
  let [a, b] = [mod(k, m), m];
  let [x0, x1] = [0n, 1n];
  while (a > 1n) {
    if (b === 0n) throw new Error('Division by zero in modInverse');
    const q = a / b;
    [a, b] = [b, a % b];
    [x0, x1] = [x1 - q * x0, x0];
  }
  return mod(x1, m);
}

interface Point {
  x: bigint;
  y: bigint;
}

function pointAdd(p1: Point | null, p2: Point | null): Point | null {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === p2.x) {
    if (p1.y === p2.y) {
      if (p1.y === 0n) return null;
      const m = mod(3n * p1.x * p1.x * modInverse(2n * p1.y));
      const x3 = mod(m * m - 2n * p1.x);
      const y3 = mod(m * (p1.x - x3) - p1.y);
      return { x: x3, y: y3 };
    }
    return null; // Point at infinity
  }
  const m = mod((p2.y - p1.y) * modInverse(p2.x - p1.x));
  const x3 = mod(m * m - p1.x - p2.x);
  const y3 = mod(m * (p1.x - x3) - p1.y);
  return { x: x3, y: y3 };
}

function scalarMult(k: bigint, pt: Point = { x: Gx, y: Gy }): Point {
  let res: Point | null = null;
  let curr: Point | null = pt;
  let n = mod(k, N);
  while (n > 0n) {
    if (n & 1n) {
      res = pointAdd(res, curr);
    }
    curr = pointAdd(curr, curr);
    n >>= 1n;
  }
  if (!res) throw new Error('Result of scalar multiplication is point at infinity');
  return res;
}

// BIP-340 / BIP-341 Tagged Hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
export function taggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = crypto.createHash('sha256').update(tag).digest();
  return crypto.createHash('sha256').update(tagHash).update(tagHash).update(data).digest();
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) {
        chk ^= GENERATORS[i];
      }
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function convertBits(data: number[], frombits: number, tobits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << tobits) - 1;
  for (const value of data) {
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (tobits - bits)) & maxv);
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    throw new Error('Invalid bit conversion');
  }
  return ret;
}

export function encodeTaprootAddress(hrp: string, outputKey32: Buffer): string {
  if (outputKey32.length !== 32) {
    throw new Error(`Invalid output key length: expected 32 bytes, got ${outputKey32.length}`);
  }
  const BECH32M_CONST = 0x2bc830a3; // BIP-350 Bech32m
  const data5Bit = convertBits(Array.from(outputKey32), 8, 5, true);
  const payload = [1, ...data5Bit]; // witness version 1 for Taproot
  const expandedHrp = bech32HrpExpand(hrp);
  const modVal = bech32Polymod([...expandedHrp, ...payload, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((modVal >> (5 * (5 - i))) & 31);
  }
  const combined = [...payload, ...checksum];
  return hrp + '1' + combined.map((d) => BECH32_CHARSET[d]).join('');
}

/**
 * Derives genuine Bitcoin Taproot address with BIP-341 output-key tweak and BIP-350 Bech32m encoding.
 *
 * Algorithm (BIP-341 Key-path spend):
 * 1. Extract internal public key point P = (Px, Py) on secp256k1.
 * 2. Lift P to have even Y coordinate: if Py is odd, Py = p - Py.
 * 3. Compute tweak t = TaggedHash("TapTweak", Px).
 * 4. Compute output key point Q = P + t * G.
 * 5. Extract 32-byte x-coordinate Qx.
 * 6. Encode witness version 1 with Bech32m and network prefix (default 'tb' for Testnet -> 'tb1p...').
 */
export function deriveBitcoinTaprootAddressFromPublicKey(
  pubKey: Buffer | string,
  hrp: string = 'tb'
): string {
  let buf: Buffer;
  if (typeof pubKey === 'string') {
    buf = Buffer.from(pubKey.replace(/^0x/, ''), 'hex');
  } else {
    buf = pubKey;
  }

  let px: bigint;
  let py: bigint;

  if (buf.length === 65 && buf[0] === 0x04) {
    px = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    py = BigInt('0x' + buf.subarray(33, 65).toString('hex'));
  } else if (buf.length === 64) {
    px = BigInt('0x' + buf.subarray(0, 32).toString('hex'));
    py = BigInt('0x' + buf.subarray(32, 64).toString('hex'));
  } else if (buf.length === 33 && (buf[0] === 0x02 || buf[0] === 0x03)) {
    px = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    // Recover y from curve equation y^2 = x^3 + 7 (mod p)
    const ySq = mod(px * px * px + 7n);
    let y = modPow(ySq, (P + 1n) / 4n, P); // p = 3 (mod 4)
    if ((y & 1n) !== BigInt(buf[0] & 1)) {
      y = mod(P - y);
    }
    py = y;
  } else {
    throw new Error(
      `Invalid secp256k1 public key for Taproot derivation: expected 64-byte raw coordinates, 65-byte uncompressed point, or 33-byte compressed point. Got ${buf.length} bytes. Arbitrary byte buffers are strictly rejected.`
    );
  }

  // Lift X: If Y is odd, negate Y so P has even Y coordinate (BIP-340 / BIP-341 convention)
  if ((py & 1n) === 1n) {
    py = mod(P - py);
  }

  const pxBuf = Buffer.from(px.toString(16).padStart(64, '0'), 'hex');
  const tweakBytes = taggedHash('TapTweak', pxBuf);
  const tweakScalar = BigInt('0x' + tweakBytes.toString('hex'));

  // Q = P + t * G
  const tG = scalarMult(tweakScalar);
  const Q = pointAdd({ x: px, y: py }, tG);
  if (!Q) {
    throw new Error('Taproot tweak resulted in point at infinity');
  }

  const qxBuf = Buffer.from(Q.x.toString(16).padStart(64, '0'), 'hex');
  return encodeTaprootAddress(hrp, qxBuf);
}
