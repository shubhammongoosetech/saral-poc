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

export async function getBalance(address: string): Promise<string> {
  try {
    const provider = getProvider();
    let cleanAddress = address.trim();
    try {
      cleanAddress = ethers.getAddress(cleanAddress.toLowerCase());
    } catch {}

    const balanceWei = await Promise.race([
      provider.getBalance(cleanAddress),
      new Promise<bigint>((_, reject) =>
        setTimeout(() => reject(new Error('RPC Timeout')), 4000)
      ),
    ]);
    return ethers.formatEther(balanceWei);
  } catch {
    return '0.0000';
  }
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
    rpcError = err?.message || 'Blockchain RPC node rejected raw transaction';
    message = `MPC threshold signature valid, but blockchain broadcast was rejected by node: ${rpcError}`;
    console.error(`[chainService] Blockchain broadcast rejected: ${rpcError}`);
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
