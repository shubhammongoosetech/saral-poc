import { ethers } from 'ethers';
import { env } from '../config/env';
import { prisma } from '../config/db';
import { wipeBuffer } from '../utils/crypto';

let providerInstance: ethers.JsonRpcProvider | null = null;

export function getProvider(): ethers.JsonRpcProvider {
  if (!providerInstance) {
    providerInstance = new ethers.JsonRpcProvider(env.RPC_URL, {
      chainId: env.CHAIN_ID,
      name:    'mst-testnet',
    });
  }
  return providerInstance;
}

export async function getBalance(address: string): Promise<string> {
  try {
    const provider    = getProvider();
    let cleanAddress  = address.trim();
    try { cleanAddress = ethers.getAddress(cleanAddress.toLowerCase()); } catch {}

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

export async function sendTransaction(
  userId:     string,
  privateKey: string | Buffer,
  toAddress:  string,
  amount:     string
): Promise<{ txHash: string; broadcasted: boolean; message: string; explorerUrl: string }> {
  let wallet: ethers.Wallet | null = null;
  let signingKey: ethers.SigningKey | null = null;

  try {
    const provider = getProvider();
    signingKey = new ethers.SigningKey(privateKey);
    wallet = new ethers.Wallet(signingKey, provider);

    let cleanToAddress = toAddress.trim();
    try {
      cleanToAddress = ethers.getAddress(cleanToAddress.toLowerCase());
    } catch {
      throw new Error(`Invalid recipient Ethereum address format: ${toAddress}`);
    }

    const value = ethers.parseEther(amount.trim());
    if (value <= 0n) throw new Error('Transfer amount must be greater than zero');

    const balance  = await provider.getBalance(wallet.address);
    const feeData  = await provider.getFeeData();
    const gasPrice = feeData.gasPrice || ethers.parseUnits('1', 'gwei');
    const gasLimit = 21000n;
    const gasCost  = gasPrice * gasLimit;
    const total    = value + gasCost;

    if (balance < total) {
      const maxSendable = balance > gasCost ? ethers.formatEther(balance - gasCost) : '0';
      throw new Error(
        `Insufficient balance. Wallet: ${ethers.formatEther(balance)} MSTC. ` +
        `Need: ${ethers.formatEther(total)} MSTC (incl. ~${ethers.formatEther(gasCost)} gas). ` +
        `Max sendable: ~${maxSendable} MSTC.`
      );
    }

    const nonce = await provider.getTransactionCount(wallet.address, 'latest');

    const txResponse = await wallet.sendTransaction({
      to: cleanToAddress, value, gasLimit, gasPrice, nonce,
    });

    const txHash = txResponse.hash;

    // Record in DB via Prisma (upsert by txHash — idempotent)
    await prisma.transaction.upsert({
      where:  { txHash },
      update: {},
      create: { userId, txHash, toAddress: cleanToAddress, amount },
    });

    return {
      txHash,
      broadcasted:  true,
      message:      'Transaction successfully broadcasted to MST Testnet!',
      explorerUrl:  `https://testnet.mstscan.com/tx/${txHash}`,
    };
  } catch (err: any) {
    throw new Error(err.shortMessage || err.reason || err.message || 'Transaction broadcast failed');
  } finally {
    // SECURITY: Scrub raw key buffer from memory immediately
    if (Buffer.isBuffer(privateKey)) {
      wipeBuffer(privateKey);
    }
    wallet = null;
    signingKey = null;
  }
}
