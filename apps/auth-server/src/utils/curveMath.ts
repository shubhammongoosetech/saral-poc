/**
 * SARAL Protocol V3 — Elliptic Curve Point Addition & Verification
 *
 * Implements multi-domain public key combination:
 *   Y_wallet = Y_foundation + Y_public + Y_private
 *
 * Curves supported:
 * 1. secp256k1 (MST EVM, Bitcoin Taproot): Weierstrass curve y^2 = x^3 + 7 mod P
 * 2. ed25519 (Solana): Twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2 mod P
 *
 * STRICT ZERO-SECRET GUARANTEE (Requirement R4):
 * This module operates EXCLUSIVELY on public points. No private scalars or secrets
 * are ever accepted, handled, or computed.
 */

// secp256k1 Curve Constants
export const SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
export const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
export const SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
export const SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// ed25519 Curve Constants
export const ED25519_P = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEDn; // 2^255 - 19
export const ED25519_L = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3EDn;
export const ED25519_D = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3n; // d = -121665/121666 mod P
export const ED25519_I = 0x2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0n; // sqrt(-1) mod P

export interface ECPoint {
  x: bigint;
  y: bigint;
}

export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let res = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = mod(res * b, m);
    b = mod(b * b, m);
    e >>= 1n;
  }
  return res;
}

export function modInverse(k: bigint, m: bigint): bigint {
  let [a, b] = [mod(k, m), m];
  let [x0, x1] = [0n, 1n];
  while (a > 1n) {
    if (b === 0n) throw new Error('Modular inverse does not exist: division by zero');
    const q = a / b;
    [a, b] = [b, a % b];
    [x0, x1] = [x1 - q * x0, x0];
  }
  return mod(x1, m);
}

// ─── secp256k1 Operations ───────────────────────────────────────────────────

export function isOnSecp256k1(pt: ECPoint): boolean {
  if (pt.x === 0n && pt.y === 0n) return true; // Point at infinity
  const lhs = mod(pt.y * pt.y, SECP256K1_P);
  const rhs = mod(pt.x * pt.x * pt.x + 7n, SECP256K1_P);
  return lhs === rhs;
}

export function secp256k1Add(p1: ECPoint | null, p2: ECPoint | null): ECPoint | null {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === 0n && p1.y === 0n) return p2;
  if (p2.x === 0n && p2.y === 0n) return p1;

  if (p1.x === p2.x) {
    if (p1.y === p2.y) {
      if (p1.y === 0n) return null; // Tangent vertical -> infinity
      // Point doubling: m = (3*x1^2) / (2*y1) mod P
      const num = mod(3n * p1.x * p1.x, SECP256K1_P);
      const den = mod(2n * p1.y, SECP256K1_P);
      const m = mod(num * modInverse(den, SECP256K1_P), SECP256K1_P);
      const x3 = mod(m * m - 2n * p1.x, SECP256K1_P);
      const y3 = mod(m * (p1.x - x3) - p1.y, SECP256K1_P);
      return { x: x3, y: y3 };
    }
    // Opposite points: x1 == x2, y1 != y2 -> infinity
    return null;
  }

  // Point addition: m = (y2 - y1) / (x2 - x1) mod P
  const num = mod(p2.y - p1.y, SECP256K1_P);
  const den = mod(p2.x - p1.x, SECP256K1_P);
  const m = mod(num * modInverse(den, SECP256K1_P), SECP256K1_P);
  const x3 = mod(m * m - p1.x - p2.x, SECP256K1_P);
  const y3 = mod(m * (p1.x - x3) - p1.y, SECP256K1_P);
  return { x: x3, y: y3 };
}

export function parseSecp256k1PublicKey(hexStr: string): ECPoint {
  const clean = hexStr.trim().replace(/^0x/, '');
  const buf = Buffer.from(clean, 'hex');

  // 65-byte uncompressed (0x04 || X || Y)
  if (buf.length === 65 && buf[0] === 0x04) {
    const x = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    const y = BigInt('0x' + buf.subarray(33, 65).toString('hex'));
    return { x, y };
  }

  // 64-byte raw coordinates (X || Y)
  if (buf.length === 64) {
    const x = BigInt('0x' + buf.subarray(0, 32).toString('hex'));
    const y = BigInt('0x' + buf.subarray(32, 64).toString('hex'));
    return { x, y };
  }

  // 33-byte compressed (0x02 or 0x03 || X)
  if (buf.length === 33 && (buf[0] === 0x02 || buf[0] === 0x03)) {
    const prefix = buf[0];
    const px = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    const ySq = mod(px * px * px + 7n, SECP256K1_P);
    let py = modPow(ySq, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
    if ((py & 1n) !== BigInt(prefix & 1)) {
      py = mod(SECP256K1_P - py, SECP256K1_P);
    }
    const pt = { x: px, y: py };
    if (!isOnSecp256k1(pt)) {
      throw new Error(`Invalid compressed secp256k1 point`);
    }
    return pt;
  }

  throw new Error(`Unsupported secp256k1 public key length ${buf.length} bytes (expected 65, 64, or 33 bytes)`);
}

export function formatSecp256k1Uncompressed(pt: ECPoint): string {
  const xHex = pt.x.toString(16).padStart(64, '0');
  const yHex = pt.y.toString(16).padStart(64, '0');
  return `04${xHex}${yHex}`;
}

/**
 * Combines multiple secp256k1 public keys via group point addition:
 *   Y_total = Y_1 + Y_2 + ... + Y_n
 * Fails closed if fewer than 1 key is provided or any point is invalid.
 */
export function addSecp256k1PublicKeys(keys: string[]): string {
  if (!keys || keys.length === 0) {
    throw new Error('addSecp256k1PublicKeys: at least one public key is required');
  }

  let acc: ECPoint | null = null;
  for (const k of keys) {
    const pt = parseSecp256k1PublicKey(k);
    acc = secp256k1Add(acc, pt);
    if (!acc) {
      throw new Error('secp256k1 public key addition produced point at infinity');
    }
  }

  if (!acc) {
    throw new Error('secp256k1 addition resulted in null point');
  }

  return formatSecp256k1Uncompressed(acc);
}

// ─── ed25519 Operations ─────────────────────────────────────────────────────

export function isOnEd25519(pt: ECPoint): boolean {
  // -x^2 + y^2 = 1 + d*x^2*y^2 mod P
  const x2 = mod(pt.x * pt.x, ED25519_P);
  const y2 = mod(pt.y * pt.y, ED25519_P);
  const lhs = mod(y2 - x2, ED25519_P);
  const rhs = mod(1n + mod(ED25519_D * mod(x2 * y2, ED25519_P), ED25519_P), ED25519_P);
  return lhs === rhs;
}

export function ed25519Add(p1: ECPoint, p2: ECPoint): ECPoint {
  // Identity point on ed25519 is (0, 1)
  if (p1.x === 0n && p1.y === 1n) return { x: p2.x, y: p2.y };
  if (p2.x === 0n && p2.y === 1n) return { x: p1.x, y: p1.y };

  // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2) mod P
  const numX = mod(p1.x * p2.y + p1.y * p2.x, ED25519_P);
  const x1x2 = mod(p1.x * p2.x, ED25519_P);
  const y1y2 = mod(p1.y * p2.y, ED25519_P);
  const dx1x2y1y2 = mod(ED25519_D * mod(x1x2 * y1y2, ED25519_P), ED25519_P);

  const denX = mod(1n + dx1x2y1y2, ED25519_P);
  const invDenX = modInverse(denX, ED25519_P);
  const x3 = mod(numX * invDenX, ED25519_P);

  // y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2) mod P
  const numY = mod(y1y2 + x1x2, ED25519_P);
  const denY = mod(1n - dx1x2y1y2, ED25519_P);
  const invDenY = modInverse(denY, ED25519_P);
  const y3 = mod(numY * invDenY, ED25519_P);

  return { x: x3, y: y3 };
}

export function parseEd25519PublicKey(hexStr: string): ECPoint {
  const clean = hexStr.trim().replace(/^0x/, '');
  const buf = Buffer.from(clean, 'hex');

  // 65-byte uncompressed (0x04 || X || Y)
  if (buf.length === 65 && buf[0] === 0x04) {
    const x = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    const y = BigInt('0x' + buf.subarray(33, 65).toString('hex'));
    return { x, y };
  }

  // 32-byte compressed format (little-endian y with x-sign in bit 7 of byte 31)
  if (buf.length === 32) {
    const yBytes = Buffer.from(buf);
    const xBit = (yBytes[31] >> 7) & 1;
    yBytes[31] &= 0x7f;

    // Convert little-endian y to BigInt
    let y = 0n;
    for (let i = 0; i < 32; i++) {
      y += BigInt(yBytes[i]) << BigInt(8 * i);
    }
    y = mod(y, ED25519_P);

    // Recover x: x^2 = (y^2 - 1) / (d*y^2 + 1) mod P
    const y2 = mod(y * y, ED25519_P);
    const u = mod(y2 - 1n, ED25519_P);
    const v = mod(ED25519_D * y2 + 1n, ED25519_P);
    const invV = modInverse(v, ED25519_P);
    const x2 = mod(u * invV, ED25519_P);

    if (x2 === 0n) {
      if (xBit !== 0) throw new Error('Invalid ed25519 public key: x is 0 but sign bit is 1');
      return { x: 0n, y };
    }

    // Square root mod P (P = 5 mod 8, so standard ed25519 sqrt)
    // candidate x = x2^((P+3)/8) mod P
    let x = modPow(x2, (ED25519_P + 3n) / 8n, ED25519_P);
    const check = mod(x * x, ED25519_P);
    if (check !== x2) {
      x = mod(x * ED25519_I, ED25519_P);
      if (mod(x * x, ED25519_P) !== x2) {
        throw new Error('Failed computing modular square root for ed25519 x coordinate');
      }
    }

    if ((x & 1n) !== BigInt(xBit)) {
      x = mod(ED25519_P - x, ED25519_P);
    }

    const pt = { x, y };
    if (!isOnEd25519(pt)) {
      throw new Error('Recovered ed25519 point does not lie on curve');
    }
    return pt;
  }

  throw new Error(`Unsupported ed25519 public key length ${buf.length} bytes (expected 32 or 65 bytes)`);
}

export function formatEd25519Compressed(pt: ECPoint): string {
  // 32-byte Ed25519 compressed: little-endian y with bit 7 of byte 31 set if x is odd
  const le = Buffer.alloc(32);
  let yVal = pt.y;
  for (let i = 0; i < 32; i++) {
    le[i] = Number(yVal & 0xffn);
    yVal >>= 8n;
  }
  if ((pt.x & 1n) === 1n) {
    le[31] |= 0x80;
  }
  return le.toString('hex');
}

export function formatEd25519Uncompressed(pt: ECPoint): string {
  const xHex = pt.x.toString(16).padStart(64, '0');
  const yHex = pt.y.toString(16).padStart(64, '0');
  return `04${xHex}${yHex}`;
}

/**
 * Combines multiple ed25519 public keys via group point addition:
 *   Y_total = Y_1 + Y_2 + ... + Y_n
 * Fails closed if fewer than 1 key is provided or any point is invalid.
 */
export function addEd25519PublicKeys(keys: string[]): string {
  if (!keys || keys.length === 0) {
    throw new Error('addEd25519PublicKeys: at least one public key is required');
  }

  let acc: ECPoint = { x: 0n, y: 1n }; // Identity point (0, 1)
  for (const k of keys) {
    const pt = parseEd25519PublicKey(k);
    acc = ed25519Add(acc, pt);
  }

  // Return uncompressed 65-byte hex (04...), compatible with deriveSolanaAddressFromPublicKey
  return formatEd25519Uncompressed(acc);
}
