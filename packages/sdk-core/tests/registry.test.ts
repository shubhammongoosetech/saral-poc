import { describe, it, expect } from 'vitest';
import {
  ChainRegistry,
  defaultChainRegistry,
  assertValidChainAddress,
  isValidChainAddress,
  SaralError,
  ChainAddressMismatchError,
  MST_TESTNET,
  POLYGON_AMOY,
  SOLANA_DEVNET,
} from '../src';

describe('ChainRegistry & Chain Detection', () => {
  it('loads built-in chains: mst-testnet, polygon-amoy, solana-devnet', () => {
    const registry = new ChainRegistry();
    expect(registry.hasChain('mst-testnet')).toBe(true);
    expect(registry.hasChain('polygon-amoy')).toBe(true);
    expect(registry.hasChain('solana-devnet')).toBe(true);

    const mst = registry.getChain('mst-testnet');
    expect(mst.type).toBe('evm');
    expect(mst.curve).toBe('secp256k1');
    expect(mst.signatureScheme).toBe('ecdsa');
    expect(mst.chainId).toBe(91562037);

    const sol = registry.getChain('solana-devnet');
    expect(sol.type).toBe('solana');
    expect(sol.curve).toBe('ed25519');
    expect(sol.signatureScheme).toBe('eddsa');
  });

  it('determines curve and signature scheme automatically from chain entry', () => {
    const registry = new ChainRegistry();
    const detectedEvm = registry.detectChain('mst-testnet');
    expect(detectedEvm.curve).toBe('secp256k1');
    expect(detectedEvm.scheme).toBe('ecdsa');

    const detectedSolana = registry.detectChain('solana-devnet');
    expect(detectedSolana.curve).toBe('ed25519');
    expect(detectedSolana.scheme).toBe('eddsa');
  });

  it('throws CHAIN_NOT_FOUND when requesting an unregistered chain', () => {
    const registry = new ChainRegistry();
    expect(() => registry.getChain('unknown-chain-xyz')).toThrowError(SaralError);
    try {
      registry.getChain('unknown-chain-xyz');
    } catch (err: any) {
      expect(err.code).toBe('CHAIN_NOT_FOUND');
    }
  });

  it('registers custom chain with Zod validation', () => {
    const registry = new ChainRegistry();
    const custom = registry.registerChain({
      id: 'ethereum-sepolia',
      name: 'Ethereum Sepolia',
      type: 'evm',
      curve: 'secp256k1',
      signatureScheme: 'ecdsa',
      chainId: 11155111,
      rpcUrl: 'https://rpc.sepolia.org',
      symbol: 'ETH',
      explorerUrl: 'https://sepolia.etherscan.io',
      testnet: true,
    });

    expect(custom.id).toBe('ethereum-sepolia');
    expect(registry.hasChain('ethereum-sepolia')).toBe(true);
  });

  it('rejects invalid custom chain configurations', () => {
    const registry = new ChainRegistry();
    expect(() =>
      registry.registerChain({
        id: 'bad-chain',
        type: 'evm',
        // Missing required fields like rpcUrl, chainId, etc.
      })
    ).toThrowError(SaralError);
  });

  it('validates EVM addresses strictly and rejects mismatches', () => {
    const validEvm = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const invalidAddress = 'not-an-address';
    const solanaAddress = '4Nd1mBQtrMJVYVfKf2PJy9NZzqndNUcxYuiPE3MrHyRg';

    expect(isValidChainAddress(MST_TESTNET, validEvm)).toBe(true);
    expect(isValidChainAddress(MST_TESTNET, invalidAddress)).toBe(false);
    expect(isValidChainAddress(MST_TESTNET, solanaAddress)).toBe(false);

    expect(() => assertValidChainAddress(MST_TESTNET, solanaAddress)).toThrowError(
      ChainAddressMismatchError
    );
  });

  it('validates Solana base58 32-byte addresses strictly', () => {
    const validSolana = '4Nd1mBQtrMJVYVfKf2PJy9NZzqndNUcxYuiPE3MrHyRg';
    const evmAddress = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

    expect(isValidChainAddress(SOLANA_DEVNET, validSolana)).toBe(true);
    expect(isValidChainAddress(SOLANA_DEVNET, evmAddress)).toBe(false);

    expect(() => assertValidChainAddress(SOLANA_DEVNET, evmAddress)).toThrowError(
      ChainAddressMismatchError
    );
  });
});

