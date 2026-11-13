import { describe, it, expect, vi } from 'vitest';
import { Keypair, Connection } from '@solana/web3.js';
import { SolanaAdapter, SOLANA_DEVNET, SaralError } from '../src';

describe('SolanaAdapter Unit Tests', () => {
  it('builds versioned transaction and tracks lastValidBlockHeight', async () => {
    const fromKp = Keypair.generate();
    const toKp = Keypair.generate();
    const blockhashKp = Keypair.generate();

    const mockConnection = {
      getBalance: vi.fn().mockResolvedValue(10_000_000_000), // 10 SOL
      getLatestBlockhash: vi.fn().mockResolvedValue({
        blockhash: blockhashKp.publicKey.toBase58(),
        lastValidBlockHeight: 1500,
      }),
    } as unknown as Connection;

    const adapter = new SolanaAdapter(SOLANA_DEVNET, mockConnection);
    const unsignedTx = await adapter.buildUnsignedTx(
      {
        chain: 'solana-devnet',
        to: toKp.publicKey.toBase58(),
        amount: '1.5',
      },
      fromKp.publicKey.toBase58()
    );

    expect(unsignedTx.curve).toBe('ed25519');
    expect(unsignedTx.metadata.blockhash).toBe(blockhashKp.publicKey.toBase58());
    expect(unsignedTx.metadata.lastValidBlockHeight).toBe(1500);
    expect(unsignedTx.hashToSign.length).toBe(32);
  });

  it('throws INSUFFICIENT_FUNDS when SOL balance is insufficient', async () => {
    const fromKp = Keypair.generate();
    const toKp = Keypair.generate();

    const mockConnection = {
      getBalance: vi.fn().mockResolvedValue(1000), // 1000 lamports (much less than 1 SOL)
    } as unknown as Connection;

    const adapter = new SolanaAdapter(SOLANA_DEVNET, mockConnection);

    await expect(
      adapter.buildUnsignedTx(
        {
          chain: 'solana-devnet',
          to: toKp.publicKey.toBase58(),
          amount: '1.0',
        },
        fromKp.publicKey.toBase58()
      )
    ).rejects.toThrowError(SaralError);
  });

  it('rebuilds transaction automatically when blockhash expires before signing', async () => {
    const fromKp = Keypair.generate();
    const toKp = Keypair.generate();
    const oldBlockhash = Keypair.generate().publicKey.toBase58();
    const freshBlockhash = Keypair.generate().publicKey.toBase58();

    const mockConnection = {
      getBalance: vi.fn().mockResolvedValue(10_000_000_000),
      getLatestBlockhash: vi
        .fn()
        .mockResolvedValueOnce({
          blockhash: oldBlockhash,
          lastValidBlockHeight: 1000,
        })
        .mockResolvedValueOnce({
          blockhash: freshBlockhash,
          lastValidBlockHeight: 1200,
        }),
      getBlockHeight: vi.fn().mockResolvedValue(1050), // Current height 1050 > lastValidBlockHeight 1000
    } as unknown as Connection;

    const adapter = new SolanaAdapter(SOLANA_DEVNET, mockConnection);

    // Initial build
    const initialTx = await adapter.buildUnsignedTx(
      {
        chain: 'solana-devnet',
        to: toKp.publicKey.toBase58(),
        amount: '0.1',
      },
      fromKp.publicKey.toBase58()
    );

    expect(initialTx.metadata.blockhash).toBe(oldBlockhash);

    // Check expiry & rebuild
    const rebuiltTx = await adapter.rebuildIfExpired(initialTx, fromKp.publicKey.toBase58());
    expect(rebuiltTx.metadata.blockhash).toBe(freshBlockhash);
    expect(rebuiltTx.metadata.lastValidBlockHeight).toBe(1200);
  });

  it('attaches 64-byte EdDSA signature and formats explorer URL', () => {
    const fromKp = Keypair.generate();
    const toKp = Keypair.generate();
    const blockhashKp = Keypair.generate();

    const mockConnection = {
      getBalance: vi.fn().mockResolvedValue(10_000_000_000),
      getLatestBlockhash: vi.fn().mockResolvedValue({
        blockhash: blockhashKp.publicKey.toBase58(),
        lastValidBlockHeight: 1500,
      }),
    } as unknown as Connection;

    const adapter = new SolanaAdapter(SOLANA_DEVNET, mockConnection);
    const dummySignature = {
      r: '0x1',
      s: '0x2',
      rawBytes: new Uint8Array(64),
    };

    const dummyUnsignedTx = {
      chainId: 'solana-devnet',
      curve: 'ed25519' as const,
      rawBytes: new Uint8Array(100),
      hashToSign: new Uint8Array(32),
      metadata: {
        from: fromKp.publicKey.toBase58(),
        to: toKp.publicKey.toBase58(),
      },
    };

    expect(adapter.explorerUrl('5abc123')).toBe(
      'https://explorer.solana.com/tx/5abc123?cluster=devnet'
    );
  });
});

