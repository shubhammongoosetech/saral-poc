/**
 * solanaTransaction.ts
 *
 * Solana Transaction construction, message compilation, and FROST signature application.
 */

import {
  Transaction,
  SystemProgram,
  PublicKey,
} from '@solana/web3.js';
import { FrostEd25519Signature } from './types';

export interface UnsignedSolanaTransferParams {
  fromPubkey: string;       // Base58
  toPubkey: string;         // Base58
  lamports: bigint | number;
  recentBlockhash: string;
}

export interface PreparedSolanaTransaction {
  transaction: Transaction;
  messageBytes: Uint8Array;
  messageBase64: string;
  fromPubkey: PublicKey;
}

/**
 * Creates an unsigned Solana transfer transaction and extracts the exact message bytes to sign.
 */
export function prepareSolanaTransferTransaction(
  params: UnsignedSolanaTransferParams
): PreparedSolanaTransaction {
  const from = new PublicKey(params.fromPubkey);
  const to = new PublicKey(params.toPubkey);

  const tx = new Transaction({
    recentBlockhash: params.recentBlockhash,
    feePayer: from,
  });

  tx.add(
    SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: to,
      lamports: BigInt(params.lamports),
    })
  );

  const messageBytes = tx.serializeMessage();

  return {
    transaction: tx,
    messageBytes,
    messageBase64: Buffer.from(messageBytes).toString('base64'),
    fromPubkey: from,
  };
}

/**
 * Applies the 64-byte FROST Ed25519 signature to the Solana transaction.
 */
export function applyFrostSignatureToSolanaTransaction(
  tx: Transaction,
  signerPubkey: PublicKey,
  signature: FrostEd25519Signature
): { rawSignedTransaction: Buffer; signatureBase58: string } {
  const sigBuffer = Buffer.from(signature.rawSignatureHex, 'hex');
  if (sigBuffer.length !== 64) {
    throw new Error(`[Solana] Invalid Ed25519 signature length: expected 64 bytes, got ${sigBuffer.length}`);
  }

  tx.addSignature(signerPubkey, sigBuffer);

  if (!tx.verifySignatures()) {
    throw new Error('[Solana] Transaction verifySignatures failed after applying FROST signature');
  }

  const rawSignedTransaction = tx.serialize();
  const signatureBase58 = tx.signature ? Buffer.from(tx.signature).toString('base64') : '';

  return {
    rawSignedTransaction,
    signatureBase58,
  };
}
