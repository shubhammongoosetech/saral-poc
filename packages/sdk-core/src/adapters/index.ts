import { ethers } from 'ethers';
import { Connection } from '@solana/web3.js';
import { ChainConfig } from '../types/chain';
import { ChainAdapter } from '../types/adapter';
import { EvmAdapter } from './EvmAdapter';
import { SolanaAdapter } from './SolanaAdapter';
import { SaralError } from '../errors/SaralError';

export * from './EvmAdapter';
export * from './SolanaAdapter';

/**
 * Factory helper that instantiates the proper ChainAdapter for a given ChainConfig.
 */
export function createChainAdapter(
  chain: ChainConfig,
  customProvider?: ethers.JsonRpcProvider | Connection
): ChainAdapter {
  if (chain.type === 'evm') {
    return new EvmAdapter(chain, customProvider instanceof ethers.JsonRpcProvider ? customProvider : undefined);
  }
  if (chain.type === 'solana') {
    return new SolanaAdapter(chain, customProvider instanceof Connection ? customProvider : undefined);
  }
  throw new SaralError('INVALID_CONFIG', `No adapter implemented for chain type: ${(chain as ChainConfig).type}`);
}
