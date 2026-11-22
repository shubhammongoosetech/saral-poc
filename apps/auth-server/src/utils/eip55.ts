import { keccak_256 } from '@noble/hashes/sha3';
import { decodeSecp256k1Point } from './secp256k1';

/**
 * Computes legacy Keccak-256, as required for EVM addresses and EIP-55.
 */
export function keccak256(data: Buffer | string): Buffer {
  return Buffer.from(keccak_256(data));
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
  const h = keccak256(decodeSecp256k1Point(pubKey).subarray(1));
  const rawAddr = h.subarray(12, 32).toString('hex');
  return toEip55Checksum(rawAddr);
}
