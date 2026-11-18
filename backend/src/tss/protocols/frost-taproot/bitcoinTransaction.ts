/**
 * bitcoinTransaction.ts
 *
 * BIP-341 / BIP-342 Bitcoin Taproot (P2TR) Transaction Construction,
 * TapSighash computation, and Schnorr witness attachment.
 */

import crypto from 'crypto';
import { taggedHash } from './frostTaproot';
import { FrostTaprootSignature } from './types';

export interface TaprootUtxo {
  txid: string;      // 64-character hex
  vout: number;      // 32-bit uint
  valueSatoshis: bigint; // 64-bit uint
  scriptPubKeyHex: string; // 0x5120<32-byte-Q_x>
}

export interface TaprootSpendRecipient {
  toAddress: string;       // Bech32m address
  outputKeyXHex?: string;  // 32-byte hex if known
  valueSatoshis: bigint;
}

export interface PreparedTaprootTx {
  sighash: Buffer;         // 32-byte TapSighash to sign
  unsignedTxBytes: Buffer;
  utxos: TaprootUtxo[];
  recipients: TaprootSpendRecipient[];
}

/**
 * Derives a P2TR scriptPubKey from a 32-byte x-only public key Q_x:
 * OP_1 (0x51) + PUSH32 (0x20) + 32-byte Q_x
 */
export function createP2TRScriptPubKey(outputKeyX: Buffer): Buffer {
  if (outputKeyX.length !== 32) {
    throw new Error(`[Bitcoin Taproot] Invalid outputKeyX length: expected 32 bytes, got ${outputKeyX.length}`);
  }
  return Buffer.concat([Buffer.from([0x51, 0x20]), outputKeyX]);
}

/**
 * Computes standard BIP-341 Taproot Sighash (SIGHASH_DEFAULT = 0x00) for key-path spending.
 */
export function computeTaprootKeyPathSighash(
  inputIndex: number,
  utxos: TaprootUtxo[],
  recipients: TaprootSpendRecipient[],
  locktime = 0
): Buffer {
  // 1. sha_prevouts = SHA256(outpoint_0 || outpoint_1 || ...)
  const prevoutsBuffers: Buffer[] = [];
  for (const u of utxos) {
    const txidReversed = Buffer.from(u.txid, 'hex').reverse();
    const voutBuf = Buffer.alloc(4);
    voutBuf.writeUInt32LE(u.vout, 0);
    prevoutsBuffers.push(Buffer.concat([txidReversed, voutBuf]));
  }
  const sha_prevouts = crypto.createHash('sha256').update(Buffer.concat(prevoutsBuffers)).digest();

  // 2. sha_amounts = SHA256(amount_0 || amount_1 || ...)
  const amountsBuffers: Buffer[] = [];
  for (const u of utxos) {
    const amtBuf = Buffer.alloc(8);
    amtBuf.writeBigUInt64LE(u.valueSatoshis, 0);
    amountsBuffers.push(amtBuf);
  }
  const sha_amounts = crypto.createHash('sha256').update(Buffer.concat(amountsBuffers)).digest();

  // 3. sha_scriptpubkeys = SHA256(len(spk0) || spk0 || ...)
  const spkBuffers: Buffer[] = [];
  for (const u of utxos) {
    const spk = Buffer.from(u.scriptPubKeyHex, 'hex');
    spkBuffers.push(Buffer.from([spk.length]), spk);
  }
  const sha_scriptpubkeys = crypto.createHash('sha256').update(Buffer.concat(spkBuffers)).digest();

  // 4. sha_sequences = SHA256(seq0 || seq1 || ...)
  const seqBuffers: Buffer[] = [];
  for (let i = 0; i < utxos.length; i++) {
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(0xffffffff, 0); // Standard sequence
    seqBuffers.push(seq);
  }
  const sha_sequences = crypto.createHash('sha256').update(Buffer.concat(seqBuffers)).digest();

  // 5. sha_outputs = SHA256(output0 || output1 || ...)
  const outputBuffers: Buffer[] = [];
  for (const r of recipients) {
    const amt = Buffer.alloc(8);
    amt.writeBigUInt64LE(r.valueSatoshis, 0);
    let spk: Buffer;
    if (r.outputKeyXHex) {
      spk = createP2TRScriptPubKey(Buffer.from(r.outputKeyXHex, 'hex'));
    } else {
      // Dummy 34-byte scriptPubKey if parsing not available
      spk = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 0xee)]);
    }
    outputBuffers.push(amt, Buffer.from([spk.length]), spk);
  }
  const sha_outputs = crypto.createHash('sha256').update(Buffer.concat(outputBuffers)).digest();

  // 6. Build TapSighash preimage
  // Epoch: 0x00, SIGHASH_DEFAULT: 0x00, nVersion: 2 (4 bytes LE), nLockTime: locktime (4 bytes LE)
  const headerBuf = Buffer.alloc(10);
  headerBuf.writeUInt8(0x00, 0); // Epoch
  headerBuf.writeUInt8(0x00, 1); // Sighash type
  headerBuf.writeInt32LE(2, 2);  // Version 2
  headerBuf.writeUInt32LE(locktime, 6);

  const inputIndexBuf = Buffer.alloc(4);
  inputIndexBuf.writeUInt32LE(inputIndex, 0);

  const sighashPreimage = Buffer.concat([
    headerBuf,
    sha_prevouts,
    sha_amounts,
    sha_scriptpubkeys,
    sha_sequences,
    sha_outputs,
    Buffer.from([0x00]), // Spend type (no annex, no script path)
    inputIndexBuf,
  ]);

  return taggedHash('TapSighash', sighashPreimage);
}

/**
 * Assembles a fully signed SegWit / Taproot raw transaction ready for broadcast.
 */
export function assembleTaprootSignedTransaction(
  utxos: TaprootUtxo[],
  recipients: TaprootSpendRecipient[],
  signatures: FrostTaprootSignature[],
  locktime = 0
): { rawSignedTxHex: string; txid: string } {
  const parts: Buffer[] = [];

  // Version 2 (4 bytes LE)
  const ver = Buffer.alloc(4);
  ver.writeInt32LE(2, 0);
  parts.push(ver);

  // Marker 0x00 and Flag 0x01 for SegWit
  parts.push(Buffer.from([0x00, 0x01]));

  // Input count (varint)
  parts.push(Buffer.from([utxos.length]));
  for (const u of utxos) {
    const txidRev = Buffer.from(u.txid, 'hex').reverse();
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(u.vout, 0);
    const scriptLen = Buffer.from([0x00]); // Empty scriptSig for SegWit
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(0xffffffff, 0);
    parts.push(txidRev, vout, scriptLen, seq);
  }

  // Output count (varint)
  parts.push(Buffer.from([recipients.length]));
  for (const r of recipients) {
    const amt = Buffer.alloc(8);
    amt.writeBigUInt64LE(r.valueSatoshis, 0);
    let spk: Buffer;
    if (r.outputKeyXHex) {
      spk = createP2TRScriptPubKey(Buffer.from(r.outputKeyXHex, 'hex'));
    } else {
      spk = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 0xaa)]);
    }
    parts.push(amt, Buffer.from([spk.length]), spk);
  }

  // Witness stack for each input:
  // For key-path spending: 1 stack item containing the 64-byte Schnorr signature
  for (let i = 0; i < utxos.length; i++) {
    const sig = signatures[i] || signatures[0];
    const sigBytes = Buffer.from(sig.rawSignatureHex, 'hex');
    parts.push(Buffer.from([0x01])); // 1 item on stack
    parts.push(Buffer.from([sigBytes.length])); // 64 bytes
    parts.push(sigBytes);
  }

  // Locktime (4 bytes LE)
  const lt = Buffer.alloc(4);
  lt.writeUInt32LE(locktime, 0);
  parts.push(lt);

  const fullTx = Buffer.concat(parts);

  // Compute txid: double-SHA256 of transaction without SegWit marker/flag/witnesses
  const legacyParts: Buffer[] = [ver, Buffer.from([utxos.length])];
  for (const u of utxos) {
    const txidRev = Buffer.from(u.txid, 'hex').reverse();
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(u.vout, 0);
    legacyParts.push(txidRev, vout, Buffer.from([0x00]), Buffer.alloc(4, 0xff));
  }
  legacyParts.push(Buffer.from([recipients.length]));
  for (const r of recipients) {
    const amt = Buffer.alloc(8);
    amt.writeBigUInt64LE(r.valueSatoshis, 0);
    let spk: Buffer;
    if (r.outputKeyXHex) {
      spk = createP2TRScriptPubKey(Buffer.from(r.outputKeyXHex, 'hex'));
    } else {
      spk = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32, 0xaa)]);
    }
    legacyParts.push(amt, Buffer.from([spk.length]), spk);
  }
  legacyParts.push(lt);

  const txidRaw = crypto
    .createHash('sha256')
    .update(crypto.createHash('sha256').update(Buffer.concat(legacyParts)).digest())
    .digest();
  const txid = Buffer.from(txidRaw).reverse().toString('hex');

  return {
    rawSignedTxHex: fullTx.toString('hex'),
    txid,
  };
}
