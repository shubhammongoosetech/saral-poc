import { z } from 'zod';
import { ethers } from 'ethers';
import { PublicKey } from '@solana/web3.js';
import { ChainConfig } from '../types/chain';
import { ChainAddressMismatchError, SaralError } from '../errors/SaralError';

export const evmChainSchema = z.object({
  id: z.string().min(1, 'Chain id is required'),
  name: z.string().min(1, 'Chain name is required'),
  type: z.literal('evm'),
  curve: z.literal('secp256k1'),
  signatureScheme: z.literal('ecdsa'),
  chainId: z.number().int().positive('EVM chainId must be a positive integer'),
  rpcUrl: z.string().url('rpcUrl must be a valid URL'),
  symbol: z.string().min(1, 'Currency symbol is required'),
  explorerUrl: z.string().url('explorerUrl must be a valid URL'),
  testnet: z.boolean().optional(),
  defaultTxType: z.union([z.literal(0), z.literal(2)]).optional(),
});

export const solanaChainSchema = z.object({
  id: z.string().min(1, 'Chain id is required'),
  name: z.string().min(1, 'Chain name is required'),
  type: z.literal('solana'),
  curve: z.literal('ed25519'),
  signatureScheme: z.literal('eddsa'),
  cluster: z.enum(['devnet', 'testnet', 'mainnet-beta']),
  rpcUrl: z.string().url('rpcUrl must be a valid URL'),
  symbol: z.string().min(1, 'Currency symbol is required'),
  explorerUrl: z.string().url('explorerUrl must be a valid URL'),
  testnet: z.boolean().optional(),
});

export const chainConfigSchema = z.discriminatedUnion('type', [
  evmChainSchema,
  solanaChainSchema,
]);

/**
 * Validates a candidate chain configuration object using Zod.
 * Throws SaralError with code INVALID_CONFIG if validation fails.
 */
export function validateChainConfig(config: unknown): ChainConfig {
  const result = chainConfigSchema.safeParse(config);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new SaralError('INVALID_CONFIG', `Invalid chain configuration: ${issues}`, {
      issues: result.error.issues,
    });
  }
  return result.data as ChainConfig;
}

/**
 * Validates an address against the target chain type.
 * Throws ChainAddressMismatchError if address is invalid for the chain.
 */
export function assertValidChainAddress(chain: ChainConfig, address: string): void {
  const cleanAddress = address.trim();

  if (chain.type === 'evm') {
    if (!ethers.isAddress(cleanAddress)) {
      throw new ChainAddressMismatchError(
        chain.id,
        address,
        '0x-prefixed 40-hex-character EVM address'
      );
    }
  } else if (chain.type === 'solana') {
    try {
      const pubkey = new PublicKey(cleanAddress);
      // Valid Solana address must be on curve or valid 32-byte Ed25519 public key
      if (pubkey.toBytes().length !== 32) {
        throw new Error('Not 32 bytes');
      }
    } catch {
      throw new ChainAddressMismatchError(
        chain.id,
        address,
        'base58-encoded 32-byte Solana public key'
      );
    }
  } else {
    throw new SaralError('INVALID_CONFIG', `Unsupported chain type: ${(chain as ChainConfig).type}`);
  }
}

/**
 * Returns boolean whether address matches chain format without throwing.
 */
export function isValidChainAddress(chain: ChainConfig, address: string): boolean {
  try {
    assertValidChainAddress(chain, address);
    return true;
  } catch {
    return false;
  }
}

