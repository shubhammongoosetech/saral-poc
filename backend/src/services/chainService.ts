/**
 * chainService.ts
 *
 * EVM Blockchain Integration for SARAL (MST Testnet / EIP-155).
 *
 * Supports:
 *   - Live balance retrieval.
 *   - Account nonce & gas fee estimation.
 *   - Direct raw signed transaction broadcasting (ethers.js v6).
 *   - Zero private-key handling: chainService accepts ONLY finalized rawSignedTx.
 */

import { ethers } from 'ethers';
import { env } from '../config/env';
import { prisma } from '../config/db';

let providerInstance: ethers.JsonRpcProvider | null = null;

export function getProvider(): ethers.JsonRpcProvider {
  if (!providerInstance) {
    const network = ethers.Network.from({
      chainId: env.CHAIN_ID,
      name: 'mst-testnet',
    });
    providerInstance = new ethers.JsonRpcProvider(env.RPC_URL, network, {
      staticNetwork: network,
    });
  }
  return providerInstance;
}

/**
 * Fetches live wei balance for an EVM address with a bounded timeout,
 * returning null if the RPC node is unreachable or times out.
 */
export async function getBalanceWeiOrNull(address: string): Promise<bigint | null> {
  try {
    const provider = getProvider();
    let cleanAddress = address.trim();
    try {
      cleanAddress = ethers.getAddress(cleanAddress.toLowerCase());
    } catch {}

    return await Promise.race([
      provider.getBalance(cleanAddress),
      new Promise<bigint>((_, reject) =>
        setTimeout(() => reject(new Error('RPC Timeout')), 4000)
      ),
    ]);
  } catch {
    return null;
  }
}

export async function getBalance(address: string): Promise<string> {
  const balanceWei = await getBalanceWeiOrNull(address);
  return balanceWei !== null ? ethers.formatEther(balanceWei) : '0.0000';
}

export async function getAccountNonce(address: string): Promise<number> {
  const provider = getProvider();
  try {
    return await provider.getTransactionCount(address, 'latest');
  } catch {
    return 0;
  }
}

export async function getGasFeeData(): Promise<{ gasPrice: bigint; gasLimit: bigint }> {
  const provider = getProvider();
  try {
    const feeData = await provider.getFeeData();
    const gasPrice = feeData.gasPrice || ethers.parseUnits('1', 'gwei');
    const gasLimit = 21000n;
    return { gasPrice, gasLimit };
  } catch {
    return {
      gasPrice: ethers.parseUnits('1', 'gwei'),
      gasLimit: 21000n,
    };
  }
}

/**
 * Converts verbose ethers.js / JSON-RPC errors into concise user-safe messages
 * without leaking raw signed transaction hex blobs into UI alerts.
 */
export function formatRpcBroadcastError(err: any): string {
  const rpcInfoMsg: string = typeof err?.info?.error?.message === 'string' ? err.info.error.message : '';
  const shortMsg: string = typeof err?.shortMessage === 'string' ? err.shortMessage : '';
  const rawMsg: string = typeof err?.message === 'string' ? err.message : '';
  const combined = `${rpcInfoMsg} ${shortMsg} ${rawMsg}`;

  if (err?.code === 'INSUFFICIENT_FUNDS' || /insufficient funds/i.test(combined)) {
    const match = combined.match(/balance\s+(\d+),\s*tx cost\s+(\d+),\s*overshot\s+(\d+)/i);
    if (match) {
      const bal = ethers.formatEther(BigInt(match[1]));
      const cost = ethers.formatEther(BigInt(match[2]));
      const shortfall = ethers.formatEther(BigInt(match[3]));
      return `Insufficient funds for amount + gas fee (Balance: ${bal} MSTC, Required: ${cost} MSTC, Short by: ${shortfall} MSTC). Reduce the amount to cover gas.`;
    }
    return 'Insufficient funds to cover transaction amount and gas fee.';
  }

  const candidate =
    rpcInfoMsg ||
    shortMsg ||
    (typeof err?.reason === 'string' ? err.reason : '') ||
    rawMsg;
  const cleaned = candidate.replace(/\s*\(transaction="0x[0-9a-fA-F]+"[\s\S]*$/m, '').trim();
  return cleaned || 'Blockchain RPC node rejected raw transaction.';
}

/**
 * Broadcasts an already MPC-signed raw EVM transaction to the network.
 * Zero private key material is accepted or touched by this function.
 */
export async function broadcastRawTransaction(
  userId: string,
  rawSignedTx: string,
  toAddress: string,
  amount: string
): Promise<{
  txHash: string;
  broadcasted: boolean;
  message: string;
  explorerUrl: string;
  rpcError?: string;
}> {
  const provider = getProvider();

  let cleanToAddress = toAddress.trim();
  try {
    cleanToAddress = ethers.getAddress(cleanToAddress.toLowerCase());
  } catch {
    throw new Error(`Invalid recipient address format: ${toAddress}`);
  }

  let txHash = ethers.keccak256(rawSignedTx);
  let broadcasted = false;
  let message = '';
  let rpcError: string | undefined;

  try {
    const txResponse = await provider.broadcastTransaction(rawSignedTx);
    txHash = txResponse.hash;
    broadcasted = true;
    message = 'Transaction successfully signed via 3-Domain MPC and broadcasted to blockchain node!';
  } catch (err: any) {
    // STRICT RULE: No fake success! Accurately report that RPC broadcast failed
    broadcasted = false;
    rpcError = formatRpcBroadcastError(err);
    message = rpcError;
    console.error(`[chainService] Blockchain broadcast rejected: ${err?.message || rpcError}`);
  }

  // Idempotently log transaction in database with truthful status
  try {
    await prisma.transaction.upsert({
      where: { txHash },
      update: {
        status: broadcasted ? 'BROADCASTED' : 'FAILED_RPC_REJECTED',
      },
      create: {
        userId,
        txHash,
        toAddress: cleanToAddress,
        amount,
        status: broadcasted ? 'BROADCASTED' : 'FAILED_RPC_REJECTED',
      },
    });
  } catch (err) {
    console.error('[chainService] Error recording transaction in DB:', err);
  }

  return {
    txHash,
    broadcasted,
    message,
    explorerUrl: `https://testnet.mstscan.com/tx/${txHash}`,
    rpcError,
  };
}
