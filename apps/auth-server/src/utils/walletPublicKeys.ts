import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { WalletCurve } from '../config/wallet';

function edwardsPoint(key: Buffer) {
  const compressed = key.length === 65 && key[0] === 4 ? Buffer.from(key.subarray(33)).reverse() : key;
  if (compressed !== key && (key[32] & 1)) compressed[31] |= 0x80;
  const point = ed25519.Point.fromHex(compressed);
  if (point.is0() || !point.isTorsionFree()) throw new Error('Invalid Ed25519 subgroup key');
  if (compressed !== key) {
    const { x, y } = point.toAffine();
    if (x !== BigInt('0x' + key.subarray(1, 33).toString('hex'))
      || y !== BigInt('0x' + key.subarray(33).toString('hex'))) {
      throw new Error('Non-canonical Ed25519 affine key');
    }
  }
  return point;
}

export function combineWalletPublicKeys(curve: WalletCurve, hexKeys: readonly string[]): string {
  if (hexKeys.length !== 1 && hexKeys.length !== 3) {
    throw new Error('Wallet key requires all of its configured domains');
  }
  const keys = hexKeys.map((hex) => {
    if (!/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error('Invalid public point encoding');
    return Buffer.from(hex, 'hex');
  });
  if (curve === 'ed25519') {
    const key = keys.reduce((sum, bytes) => sum.add(edwardsPoint(bytes)), ed25519.Point.ZERO);
    if (key.is0()) throw new Error('Invalid aggregate Ed25519 key');
    return Buffer.from(key.toBytes()).toString('hex');
  }
  const key = keys.reduce((sum, bytes) => sum.add(secp256k1.Point.fromHex(bytes)), secp256k1.Point.ZERO);
  if (key.is0()) throw new Error('Invalid aggregate secp256k1 key');
  return Buffer.from(key.toBytes(false)).toString('hex');
}
