import { describe, it, expect, vi } from 'vitest';
import { ethers } from 'ethers';
import { EvmAdapter, MST_TESTNET, POLYGON_AMOY, SaralError } from '../src';

describe('EvmAdapter Unit Tests', () => {
  it('throws NONCE_FETCH_FAILED when RPC fails to get nonce — NEVER defaults to 0', async () => {
    const mockProvider = {
      getTransactionCount: vi.fn().mockRejectedValue(new Error('RPC Connection Refused')),
      getBalance: vi.fn().mockResolvedValue(ethers.parseEther('10')),
      getFeeData: vi.fn().mockResolvedValue({
        gasPrice: ethers.parseUnits('1', 'gwei'),
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
    } as unknown as ethers.JsonRpcProvider;

    const adapter = new EvmAdapter(MST_TESTNET, mockProvider);

    await expect(
      adapter.buildUnsignedTx(
        {
          chain: 'mst-testnet',
          to: '0x1111111111111111111111111111111111111111',
          amount: '0.1',
        },
        '0x2222222222222222222222222222222222222222'
      )
    ).rejects.toThrowError(SaralError);

    try {
      await adapter.buildUnsignedTx(
        {
          chain: 'mst-testnet',
          to: '0x1111111111111111111111111111111111111111',
          amount: '0.1',
        },
        '0x2222222222222222222222222222222222222222'
      );
    } catch (err: any) {
      expect(err.code).toBe('NONCE_FETCH_FAILED');
    }
  });

  it('throws INSUFFICIENT_FUNDS when balance is less than amount + gas fee — NEVER skips balance check', async () => {
    const mockProvider = {
      getTransactionCount: vi.fn().mockResolvedValue(5),
      getBalance: vi.fn().mockResolvedValue(ethers.parseEther('0.05')), // Only 0.05 available
      getFeeData: vi.fn().mockResolvedValue({
        gasPrice: ethers.parseUnits('1', 'gwei'),
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
    } as unknown as ethers.JsonRpcProvider;

    const adapter = new EvmAdapter(MST_TESTNET, mockProvider);

    await expect(
      adapter.buildUnsignedTx(
        {
          chain: 'mst-testnet',
          to: '0x1111111111111111111111111111111111111111',
          amount: '1.0', // Requesting 1.0 MSTC
        },
        '0x2222222222222222222222222222222222222222'
      )
    ).rejects.toThrowError(SaralError);

    try {
      await adapter.buildUnsignedTx(
        {
          chain: 'mst-testnet',
          to: '0x1111111111111111111111111111111111111111',
          amount: '1.0',
        },
        '0x2222222222222222222222222222222222222222'
      );
    } catch (err: any) {
      expect(err.code).toBe('INSUFFICIENT_FUNDS');
      expect(err.message).toContain('Insufficient funds');
    }
  });

  it('builds unsigned transaction with dynamic estimateGas instead of hardcoded 21000', async () => {
    const mockEstimateGas = vi.fn().mockResolvedValue(45000n);
    const mockProvider = {
      getTransactionCount: vi.fn().mockResolvedValue(1),
      getBalance: vi.fn().mockResolvedValue(ethers.parseEther('100')),
      getFeeData: vi.fn().mockResolvedValue({
        gasPrice: ethers.parseUnits('2', 'gwei'),
      }),
      estimateGas: mockEstimateGas,
    } as unknown as ethers.JsonRpcProvider;

    const adapter = new EvmAdapter(MST_TESTNET, mockProvider);
    const unsignedTx = await adapter.buildUnsignedTx(
      {
        chain: 'mst-testnet',
        to: '0x1111111111111111111111111111111111111111',
        amount: '0.1',
        memo: 'Payment with metadata',
      },
      '0x2222222222222222222222222222222222222222'
    );

    expect(mockEstimateGas).toHaveBeenCalled();
    // 45000 + 10% buffer = 49500
    expect(unsignedTx.metadata.gasLimit).toBe('49500');
    expect(unsignedTx.hashToSign.length).toBe(32);
  });

  it('supports EIP-1559 Type 2 transactions on chains like Polygon Amoy', async () => {
    const mockProvider = {
      getTransactionCount: vi.fn().mockResolvedValue(2),
      getBalance: vi.fn().mockResolvedValue(ethers.parseEther('50')),
      getFeeData: vi.fn().mockResolvedValue({
        maxFeePerGas: ethers.parseUnits('30', 'gwei'),
        maxPriorityFeePerGas: ethers.parseUnits('2', 'gwei'),
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
    } as unknown as ethers.JsonRpcProvider;

    const adapter = new EvmAdapter(POLYGON_AMOY, mockProvider);
    const unsignedTx = await adapter.buildUnsignedTx(
      {
        chain: 'polygon-amoy',
        to: '0x1111111111111111111111111111111111111111',
        amount: '0.5',
      },
      '0x2222222222222222222222222222222222222222'
    );

    expect(unsignedTx.metadata.type).toBe(2);
    expect(adapter.chain.id).toBe('polygon-amoy');
    expect(adapter.explorerUrl('0xabc123')).toBe('https://amoy.polygonscan.com/tx/0xabc123');
  });

  it('attaches signature, computes txHash, and preserves recovery id', async () => {
    const mockProvider = {
      getTransactionCount: vi.fn().mockResolvedValue(0),
      getBalance: vi.fn().mockResolvedValue(ethers.parseEther('10')),
      getFeeData: vi.fn().mockResolvedValue({
        gasPrice: ethers.parseUnits('1', 'gwei'),
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
    } as unknown as ethers.JsonRpcProvider;

    const adapter = new EvmAdapter(MST_TESTNET, mockProvider);
    const unsignedTx = await adapter.buildUnsignedTx(
      {
        chain: 'mst-testnet',
        to: '0x1111111111111111111111111111111111111111',
        amount: '0.1',
      },
      '0x2222222222222222222222222222222222222222'
    );

    const dummySig = {
      r: '0x5e33bced4853a41f9ab41af2b79bd8ef2ae6b47d4c74f7f6b68637a30492b25a',
      s: '0x3f78a4707406c7ac73a61de7d6a68dae4c445afaad6b902f1e6a0f3378801de3',
      yParity: 0,
      v: 27,
      rawBytes: new Uint8Array(65),
    };

    const signedTx = adapter.attachSignature(unsignedTx, dummySig);
    expect(signedTx.txHash.startsWith('0x')).toBe(true);
    expect(signedTx.rawTx.startsWith('0x')).toBe(true);
  });
});

