import { ECDH } from 'crypto';

export function decodeSecp256k1Point(publicKey: Buffer | string): Buffer {
  let bytes: Buffer;
  if (typeof publicKey === 'string') {
    const hex = publicKey.replace(/^0x/, '');
    if (!/^(?:[0-9a-f]{2})+$/i.test(hex)) {
      throw new Error('Invalid secp256k1 public key encoding');
    }
    bytes = Buffer.from(hex, 'hex');
  } else {
    bytes = publicKey;
  }
  const point = bytes.length === 64 ? Buffer.concat([Buffer.from([4]), bytes]) : bytes;
  if (!(point.length === 65 && point[0] === 4) && !(point.length === 33 && [2, 3].includes(point[0]))) {
    throw new Error('Invalid secp256k1 public key length or prefix');
  }
  return ECDH.convertKey(point, 'secp256k1', undefined, undefined, 'uncompressed') as Buffer;
}
