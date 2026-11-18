/**
 * evmTransaction.ts
 *
 * EVM Transaction serialization, Keccak-256 hash extraction,
 * and CGGMP21 threshold signature attachment (EIP-1559 and Legacy).
 */

import { ethers } from 'ethers';
import { Cggmp21Signature } from './types';

export interface UnsignedEvmTxParams {
  to: string;
  valueWei: bigint | string;
  nonce: number;
  gasLimit: bigint | string;
  gasPrice?: bigint | string;
  maxFeePerGas?: bigint | string;
  maxPriorityFeePerGas?: bigint | string;
  data?: string;
  chainId: bigint | number;
  type?: number; // 0 for Legacy, 2 for EIP-1559
}

export interface PreparedEvmTx {
  unsignedSerialized: string;
  txHashToSign: string;       // Keccak256 hash of unsignedSerialized
  txHashToSignBytes: Buffer;
  transaction: ethers.Transaction;
}

/**
 * Prepares an EVM transaction and computes the Keccak256 message hash to be signed via CGGMP21.
 */
export function prepareEvmTransaction(params: UnsignedEvmTxParams): PreparedEvmTx {
  const isEip1559 = params.type === 2 || (params.maxFeePerGas !== undefined && params.type !== 0);

  const txData: ethers.TransactionLike = {
    to: ethers.getAddress(params.to),
    value: BigInt(params.valueWei),
    nonce: params.nonce,
    gasLimit: BigInt(params.gasLimit),
    data: params.data || '0x',
    chainId: BigInt(params.chainId),
    type: isEip1559 ? 2 : 0,
  };

  if (isEip1559) {
    txData.maxFeePerGas = BigInt(params.maxFeePerGas || params.gasPrice || 30000000000n);
    txData.maxPriorityFeePerGas = BigInt(params.maxPriorityFeePerGas || 1500000000n);
  } else {
    txData.gasPrice = BigInt(params.gasPrice || 20000000000n);
  }

  const tx = ethers.Transaction.from(txData);
  const unsignedSerialized = tx.unsignedSerialized;
  const txHashToSign = ethers.keccak256(unsignedSerialized);
  const txHashToSignBytes = Buffer.from(txHashToSign.slice(2), 'hex');

  return {
    unsignedSerialized,
    txHashToSign,
    txHashToSignBytes,
    transaction: tx,
  };
}

/**
 * Attaches the CGGMP21 signature to the EVM transaction and produces the raw signed transaction bytes.
 */
export function applyCggmp21SignatureToEvmTx(
  prepared: PreparedEvmTx,
  sig: Cggmp21Signature
): {
  rawSignedTx: string;
  txHash: string;
} {
  const tx = prepared.transaction.clone();
  tx.signature = ethers.Signature.from({
    r: sig.r,
    s: sig.s,
    yParity: sig.yParity,
  });

  const rawSignedTx = tx.serialized;
  const txHash = tx.hash;

  if (!txHash) {
    throw new Error('[EVM Transaction] Failed to calculate transaction hash after signing');
  }

  return {
    rawSignedTx,
    txHash,
  };
}
