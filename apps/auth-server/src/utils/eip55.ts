import crypto from 'crypto';

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

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

/**
 * Computes standard Keccak-256 hash. Strictly fails closed if keccak-256 is unavailable.
 * Never falls back to SHA-256.
 */
export function keccak256(data: Buffer | string): Buffer {
  return crypto.createHash('keccak-256').update(data).digest();
}

/**
 * Computes standard EIP-55 mixed-case checksum on a 20-byte EVM address using Keccak-256.
 * Fails closed if address format is invalid.
 */
export function toEip55Checksum(addrLower: string): string {
  const clean = addrLower.toLowerCase().replace(/^0x/, '');
  if (clean.length !== 40 || !/^[0-9a-f]{40}$/.test(clean)) {
    throw new Error(`Invalid EVM address for EIP-55 checksum: expected 40 hex characters, got "${addrLower}"`);
  }

  const hashHex = keccak256(clean).toString('hex');

  let ret = '0x';
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i];
    if (c >= '0' && c <= '9') {
      ret += c;
    } else {
      const nibble = parseInt(hashHex[i], 16);
      ret += nibble >= 8 ? c.toUpperCase() : c;
    }
  }
  return ret;
}

/**
 * Derives EIP-55 checksummed EVM address from secp256k1 public key.
 * Strictly accepts:
 * 1. 64-byte raw coordinates (X || Y).
 * 2. 65-byte uncompressed point prefixed with 0x04.
 * 3. 33-byte compressed point prefixed with 0x02 or 0x03.
 * Strictly fails closed if input is not a valid secp256k1 public key.
 * Never accepts arbitrary 32-byte hashes or seeds.
 */
export function deriveEvmAddressFromPublicKey(pubKey: Buffer | string): string {
  let buf: Buffer;
  if (typeof pubKey === 'string') {
    buf = Buffer.from(pubKey.replace(/^0x/, ''), 'hex');
  } else {
    buf = pubKey;
  }

  // 65-byte uncompressed point (0x04 || X || Y)
  if (buf.length === 65 && buf[0] === 0x04) {
    buf = buf.subarray(1);
  } else if (buf.length === 33 && (buf[0] === 0x02 || buf[0] === 0x03)) {
    // 33-byte compressed point: decompress Y using curve equation y^2 = x^3 + 7 (mod p)
    const prefix = buf[0];
    const px = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    const ySq = mod(px * px * px + 7n);
    let py = modPow(ySq, (P + 1n) / 4n, P);
    if ((py & 1n) !== BigInt(prefix & 1)) {
      py = mod(P - py);
    }
    const xBuf = Buffer.from(px.toString(16).padStart(64, '0'), 'hex');
    const yBuf = Buffer.from(py.toString(16).padStart(64, '0'), 'hex');
    buf = Buffer.concat([xBuf, yBuf]);
  }

  if (buf.length !== 64) {
    throw new Error(
      `Invalid secp256k1 public key length ${buf.length} bytes: expected 64-byte raw coordinates, 65-byte uncompressed point (0x04), or 33-byte compressed point (0x02/0x03). Arbitrary seeds are strictly prohibited.`
    );
  }

  const h = keccak256(buf);
  const rawAddr = h.subarray(12, 32).toString('hex');
  return toEip55Checksum(rawAddr);
}
