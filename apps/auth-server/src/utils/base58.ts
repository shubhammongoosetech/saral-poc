const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58(buffer: Buffer): string {
  if (buffer.length === 0) return '';
  const digits: number[] = [0];
  for (let i = 0; i < buffer.length; i++) {
    for (let j = 0; j < digits.length; j++) digits[j] <<= 8;
    digits[0] += buffer[i];
    let carry = 0;
    for (let j = 0; j < digits.length; j++) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (let i = 0; buffer[i] === 0 && i < buffer.length - 1; i++) {
    digits.push(0);
  }
  return digits.reverse().map((d) => BASE58_ALPHABET[d]).join('');
}

/**
 * Derives native Base58 Solana address from genuine Ed25519 public key.
 * Strictly accepts ONLY:
 * 1. 32-byte compressed Ed25519 public key.
 * 2. 65-byte uncompressed curve point (0x04 || X || Y) which is converted via standard Ed25519 point compression.
 * Strictly fails closed on arbitrary lengths or invalid formats.
 */
export function deriveSolanaAddressFromPublicKey(pubKey: Buffer | string): string {
  let buf: Buffer;
  if (typeof pubKey === 'string') {
    buf = Buffer.from(pubKey.replace(/^0x/, ''), 'hex');
  } else {
    buf = pubKey;
  }

  // 65-byte uncompressed point (0x04 || X || Y)
  if (buf.length === 65 && buf[0] === 0x04) {
    const x = BigInt('0x' + buf.subarray(1, 33).toString('hex'));
    const yBytes = buf.subarray(33, 65);
    const le = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      le[i] = yBytes[31 - i];
    }
    if ((x & 1n) === 1n) {
      le[31] |= 0x80;
    }
    buf = le;
  }

  if (buf.length !== 32) {
    throw new Error(
      `Invalid Ed25519 public key length ${buf.length} bytes: expected exactly 32-byte compressed key or 65-byte uncompressed point. Arbitrary 32-byte strings or random hashes must never substitute for a genuine public key.`
    );
  }

  return encodeBase58(buf);
}
