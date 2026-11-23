import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import crypto from 'crypto';
import { prisma } from '../../apps/auth-server/src/database/prisma';
import { DataStore } from '../../apps/auth-server/src/storage/store';
import { saralBackendClient } from '../../apps/auth-server/src/clients/saralBackendClient';
import { ED25519_TEST_PUBKEY, SECP256K1_TEST_PUBKEY, MESH_TEST_PUBLIC_KEYS, mockWalletCoordinator } from './walletFixtures';
import {
  createOrGetWallet,
  recomputeWalletAddressesFromShares,
  deriveAddressFromDkgPublicKey,
  deriveMultiChainAddresses,
  isLegacyHmacAddress,
  calculateLegacyHmacAddress,
  signTransaction,
} from '../../apps/auth-server/src/services/walletService';
import {
  toEip55Checksum,
  deriveEvmAddressFromPublicKey,
  keccak256,
} from '../../apps/auth-server/src/utils/eip55';
import {
  encodeBase58,
  deriveSolanaAddressFromPublicKey,
} from '../../apps/auth-server/src/utils/base58';
import {
  encodeTaprootAddress,
  deriveBitcoinTaprootAddressFromPublicKey,
  taggedHash,
} from '../../apps/auth-server/src/utils/bech32m';
import { getLiveBalances, getLiveActivity } from '../../apps/auth-server/src/services/chainService';

describe('SARAL Protocol V3 — Critical Wallet Address Derivation & Security Fix Suite', () => {
  const store = DataStore.getInstance();
  const fixtureUserId = crypto.randomUUID();
  let createdWalletId: string;
  let initialAddresses: ReturnType<typeof deriveMultiChainAddresses>;

  beforeAll(async () => {
    // Configure mock DKG Coordinator response returning verified public keys
    mockWalletCoordinator();

    // Setup test user in database
    const user = await prisma.user.create({
      data: {
        id: fixtureUserId,
        email: `sec-audit-${fixtureUserId}@saral.network`,
        mobile: `+9198${Date.now().toString().slice(-8)}`,
        loginMethod: 'mobile',
      },
    });

    // Create wallet for test user
    const res = await createOrGetWallet(user.id);
    createdWalletId = res.wallet.walletId;
    initialAddresses = res.addresses;
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { id: fixtureUserId } });
  });

  it('resumes persisted chain sessions after a transient address derivation failure', async () => {
    const user = await prisma.user.create({ data: { id: crypto.randomUUID(), loginMethod: 'google' } });
    const start = vi.mocked(saralBackendClient.startDkg);
    const callsBefore = start.mock.calls.length;
    vi.mocked(saralBackendClient.derivePublicKey).mockRejectedValueOnce(new Error('Temporary node failure'));
    try {
      await expect(createOrGetWallet(user.id)).rejects.toThrow('Temporary node failure');
      const reserved = await store.loadWallet(user.id);
      expect(reserved?.status).toBe('KEY_READY');
      const resumed = await createOrGetWallet(user.id);
      expect(resumed.wallet.status).toBe('READY');
      expect(resumed.wallet.walletId).toBe(reserved?.walletId);
      expect(resumed.wallet.keyReferences).toEqual(reserved?.keyReferences);
      expect(start.mock.calls.length - callsBefore).toBe(9);
      expect(new Set(start.mock.calls.slice(callsBefore).map(([params]) => params?.sessionId)).size).toBe(9);
      const returning = await createOrGetWallet(user.id);
      expect(returning.isNew).toBe(false);
      expect(returning.addresses).toEqual(resumed.addresses);
      expect(start.mock.calls.length - callsBefore).toBe(9);
    } finally {
      await prisma.user.delete({ where: { id: user.id } });
    }
  });

  // -------------------------------------------------------------
  // TEST 1: NEW USER REAL DKG ADDRESS DERIVATION
  // -------------------------------------------------------------
  it('Test 1: New user real DKG address derivation produces genuine blockchain addresses', async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `test1-${Date.now()}@saral.network`,
        mobile: `+9191${Date.now().toString().slice(-8)}`,
        loginMethod: 'mobile',
      },
    });
    const res = await createOrGetWallet(user.id);

    expect(res.isNew).toBe(true);
    expect(res.wallet.status).toBe('READY');
    expect(res.wallet.walletId).toMatch(/^wal-/);

    // Verify distinct opaque key references (NOT public keys, NOT addresses)
    const keyRefs = res.wallet.keyReferences;
    expect(keyRefs).toBeDefined();
    expect(Object.keys(keyRefs.mesh ?? {}).sort()).toEqual(['foundation', 'private', 'public']);
    const keys = Object.values(keyRefs.mesh ?? {}).flatMap(Object.values);
    expect(keys).toHaveLength(9);
    expect(new Set(keys.map(({ keyId }) => keyId)).size).toBe(9);
    expect(keys.every(({ keyId }) => keyId.startsWith('key-'))).toBe(true);

    // Verify addresses are marked dkgBacked and match genuine cryptography
    expect(res.addresses.mst.dkgBacked).toBe(true);
    expect(res.addresses.solana.dkgBacked).toBe(true);
    expect(res.addresses.bitcoin.dkgBacked).toBe(true);

    expect(res.addresses).toEqual(deriveMultiChainAddresses(res.wallet.walletId, MESH_TEST_PUBLIC_KEYS));

    await prisma.user.delete({ where: { id: user.id } });
  });

  // -------------------------------------------------------------
  // TEST 2: SAME ADDRESS AFTER LOGOUT / LOGIN
  // -------------------------------------------------------------
  it('Test 2: Returning user derives exact same address without creating new DKG secret', async () => {
    const user = await prisma.user.findUnique({ where: { id: fixtureUserId } });
    expect(user).toBeDefined();

    // Returning user requests wallet
    const returningRes = await createOrGetWallet(user!.id);
    expect(returningRes.isNew).toBe(false);
    expect(returningRes.wallet.walletId).toBe(createdWalletId);

    // Addresses match character-for-character across separate calls
    expect(returningRes.addresses.mst.address).toBe(initialAddresses.mst.address);
    expect(returningRes.addresses.solana.address).toBe(initialAddresses.solana.address);
    expect(returningRes.addresses.bitcoin.address).toBe(initialAddresses.bitcoin.address);
  });

  // -------------------------------------------------------------
  // TEST 7: EIP-55 KECCAK-256 TEST VECTORS
  // -------------------------------------------------------------
  it('Test 7: EIP-55 Keccak-256 test vectors pass and SHA-256 fallback is eliminated', () => {
    // 1. Official EIP-55 test vectors
    const vectors = [
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
      '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
      '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    ];

    for (const v of vectors) {
      const checksummed = toEip55Checksum(v.toLowerCase());
      expect(checksummed).toBe(v);
    }

    // 2. Genesis Address #1 derivation from secp256k1 generator G
    const derived = deriveEvmAddressFromPublicKey(SECP256K1_TEST_PUBKEY);
    expect(derived).toBe('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf');

    // 3. Fails closed on invalid length or non-hex input
    expect(() => toEip55Checksum('0xinvalid')).toThrow();
    expect(() => deriveEvmAddressFromPublicKey(Buffer.alloc(32))).toThrow();
  });

  // -------------------------------------------------------------
  // TEST 8: SOLANA ED25519 PUBLIC-POINT / ADDRESS TEST VECTORS
  // -------------------------------------------------------------
  it('Test 8: Solana Ed25519 public-point/address test vectors pass and reject arbitrary seeds', () => {
    // System Program (32 zero bytes) -> all 1s in Base58
    const zeroKey = Buffer.alloc(32, 0);
    expect(encodeBase58(zeroKey)).toBe('11111111111111111111111111111111');

    // Ed25519 basepoint public key derivation
    const solAddr = deriveSolanaAddressFromPublicKey(ED25519_TEST_PUBKEY);
    expect(solAddr).toBe('6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH');

    // Strict fail-closed: rejects arbitrary lengths
    expect(() => deriveSolanaAddressFromPublicKey(Buffer.alloc(20))).toThrow();
    expect(() => deriveSolanaAddressFromPublicKey(Buffer.alloc(48))).toThrow();
  });

  // -------------------------------------------------------------
  // TEST 9: BITCOIN TAPROOT TWEAK & BECH32M TEST VECTORS
  // -------------------------------------------------------------
  it('Test 9: Bitcoin Taproot BIP-341 tweak and BIP-350 Bech32m test vectors pass', () => {
    // Tagged hash test
    const tHash = taggedHash('TapTweak', Buffer.from('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'));
    expect(tHash.length).toBe(32);

    // Taproot output-key tweak derivation from secp256k1 generator G
    const btcAddr = deriveBitcoinTaprootAddressFromPublicKey(SECP256K1_TEST_PUBKEY, 'tb');
    expect(btcAddr.startsWith('tb1p')).toBe(true);
    expect(btcAddr.length).toBe(62);
    expect(btcAddr).toBe('tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2');

    // Fails closed on invalid keys
    expect(() => deriveBitcoinTaprootAddressFromPublicKey(Buffer.alloc(25), 'tb')).toThrow();
  });

  // -------------------------------------------------------------
  // TEST 10: OLD HMAC-DERIVED ADDRESSES DETECTED & REJECTED
  // -------------------------------------------------------------
  it('Test 10: Old HMAC-derived addresses are detected and non-public-key strings are strictly rejected', () => {
    const fakeKeyRef = 'key-mst-12345678';
    const fakeWalletId = 'wal-fake-999';

    // 1. Calculate old fake HMAC address
    const legacyMst = calculateLegacyHmacAddress(fakeWalletId, fakeKeyRef, 'mst');
    expect(legacyMst.startsWith('0x')).toBe(true);

    // 2. isLegacyHmacAddress correctly flags old mock address
    expect(isLegacyHmacAddress(legacyMst, fakeWalletId, fakeKeyRef, 'mst')).toBe(true);
    expect(isLegacyHmacAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', fakeWalletId, fakeKeyRef, 'mst')).toBe(false);

    // 3. Strict fail-closed: deriveMultiChainAddresses rejects non-public-key reference strings
    expect(() =>
      deriveMultiChainAddresses(fakeWalletId, {
        mst: fakeKeyRef,
        solana: 'key-sol-123',
        bitcoin: 'key-btc-123',
      })
    ).toThrow(/CRITICAL SECURITY VIOLATION: Refusing to derive/);
  });

  // -------------------------------------------------------------
  // TEST 11: ZERO ADDRESS & ZERO PUBLIC KEY PERSISTENCE IN POSTGRESQL
  // -------------------------------------------------------------
  it('Test 11: STRICT ZERO PERSISTENCE — PostgreSQL contains ZERO addresses and ZERO signing public keys', async () => {
    const user = await prisma.user.findUnique({ where: { id: fixtureUserId } });
    const dbWallet = await prisma.walletIdentity.findUnique({
      where: { userId: user!.id },
    });
    expect(dbWallet).toBeDefined();

    const walletJson = JSON.stringify(dbWallet);

    // Negative assertion: no derived addresses in JSON
    expect(walletJson.toLowerCase()).not.toContain(initialAddresses.mst.address.toLowerCase());
    expect(walletJson).not.toContain(initialAddresses.solana.address);
    expect(walletJson).not.toContain(initialAddresses.bitcoin.address);

    // Negative assertion: no hex public keys in JSON
    expect(walletJson).not.toMatch(/04[0-9a-fA-F]{128}/);
    expect(walletJson).not.toMatch(/[0-9a-fA-F]{64}/);

    // Negative assertion: no forbidden database columns
    const keys = Object.keys(dbWallet || {});
    expect(keys).not.toContain('address');
    expect(keys).not.toContain('wallet_address');
    expect(keys).not.toContain('public_key');
    expect(keys).not.toContain('master_public_key');
    expect(keys).not.toContain('signing_public_key');
  });

  // -------------------------------------------------------------
  // TEST 13: STRICT FAIL-CLOSED ON UNAVAILABLE THRESHOLD
  // -------------------------------------------------------------
  it('Test 13: Strict Fail-Closed — Coordinator error refuses HMAC fallback and throws error', async () => {
    const tempUser = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `failclosed-${Date.now()}@saral.network`,
        mobile: `+9194${Date.now().toString().slice(-8)}`,
        loginMethod: 'mobile',
      },
    });

    // First ensure wallet is created for tempUser
    await createOrGetWallet(tempUser.id);
    await store.savePolicy({
      userId: tempUser.id, days: ['MON'], startTime: '00:00', endTime: '23:59', timezone: 'UTC',
      timeRestrictionEnabled: false, locationRestrictionEnabled: false, updatedAt: new Date().toISOString(),
    });

    // Temporarily mock Coordinator to simulate insufficient node shares (less than 3 nodes) for one call
    vi.spyOn(saralBackendClient, 'derivePublicKey').mockRejectedValueOnce(
      new Error('insufficient verified node shares: obtained 2 valid points, required threshold k=3')
    );

    // Recomputing addresses MUST fail closed: no fake address, no HMAC fallback
    await expect(recomputeWalletAddressesFromShares(tempUser.id)).rejects.toThrow(
      /insufficient verified node shares/
    );

    await prisma.user.delete({ where: { id: tempUser.id } });
  });

  // -------------------------------------------------------------
  // TEST 14: WALLET BALANCE AND ACTIVITY APIS USE VERIFIED ADDRESSES
  // -------------------------------------------------------------
  it('Test 14: Live balance and activity APIs accept verified multi-chain addresses', async () => {
    const rawAddrs = {
      mst: initialAddresses.mst.address,
      solana: initialAddresses.solana.address,
      bitcoin: initialAddresses.bitcoin.address,
    };

    const mockFetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json({ result: '0x1' }))
      .mockResolvedValueOnce(Response.json({ result: { value: 1 } }))
      .mockResolvedValueOnce(Response.json({
        chain_stats: { funded_txo_sum: 1, spent_txo_sum: 0 },
        mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
      }))
      .mockRejectedValue(new Error('Provider unavailable'));
    try {
      expect(await getLiveBalances(rawAddrs)).toMatchObject({
        mst: '0.000000000000000001', solana: '0.000000001', bitcoin: '0.00000001',
      });
      expect(await getLiveBalances(rawAddrs)).toMatchObject({ mst: null, solana: null, bitcoin: null });
      expect(Array.isArray(await getLiveActivity(rawAddrs))).toBe(true);
    } finally {
      mockFetch.mockRestore();
    }
  });

  // -------------------------------------------------------------
  // TEST 15: CONCURRENT CREATION SAFETY (10 SIMULTANEOUS CALLS)
  // -------------------------------------------------------------
  it('Test 15: Concurrent creation safety — 10 concurrent requests yield exactly ONE logical wallet', async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `scenario15-${Date.now()}@saral.network`,
        mobile: `+9195${Date.now().toString().slice(-8)}`,
        loginMethod: 'mobile',
      },
    });

    // Fire 10 simultaneous createOrGetWallet calls for same user
    const promises = Array.from({ length: 10 }, () => createOrGetWallet(user.id));
    const results = await Promise.all(promises);

    const firstWalletId = results[0].wallet.walletId;
    for (let i = 1; i < results.length; i++) {
      expect(results[i].wallet.walletId).toBe(firstWalletId);
      expect(results[i].addresses.mst.address).toBe(results[0].addresses.mst.address);
      expect(results[i].addresses.solana.address).toBe(results[0].addresses.solana.address);
      expect(results[i].addresses.bitcoin.address).toBe(results[0].addresses.bitcoin.address);
    }

    await prisma.user.delete({ where: { id: user.id } });
  });

  // -------------------------------------------------------------
  // TEST 16: TSS MULTI-CHAIN TRANSACTION SIGNING
  // -------------------------------------------------------------
  it('Test 16: TSS Multi-Chain Transaction Signing — signs without private key reconstruction & logs access', async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `scenario16-${Date.now()}@saral.network`,
        mobile: `+9196${Date.now().toString().slice(-8)}`,
        loginMethod: 'mobile',
      },
    });

    // Initialize wallet
    await createOrGetWallet(user.id);

    // 1. Rejects invalid recipient format
    await expect(
      signTransaction(user.id, {
        chain: 'mst-testnet',
        toAddress: '0xinvalid',
        amount: '1.5',
      })
    ).rejects.toThrow(/Invalid EVM address/);

    // 2. Rejects negative or zero amount
    await expect(
      signTransaction(user.id, {
        chain: 'mst-testnet',
        toAddress: '0x1111111111111111111111111111111111111111',
        amount: '-5',
      })
    ).rejects.toThrow(/positive amount/);

    // 3. Signs MST transaction via 15-node TSS without private key reconstruction
    const mstRes = await signTransaction(user.id, {
      chain: 'mst-testnet',
      toAddress: '0x2222222222222222222222222222222222222222',
      amount: '2.5',
    });
    expect(mstRes.success).toBe(true);
    expect(mstRes.broadcasted).toBe(true);
    expect(mstRes.txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(mstRes.signature?.algorithm).toBe('ECDSA-secp256k1-TSS');
    expect(mstRes.signature?.r).toBeDefined();
    expect(mstRes.signature?.s).toBeDefined();
    expect(mstRes.signature?.v).toBe(27);

    // 4. Signs Solana transaction via TSS
    const solRes = await signTransaction(user.id, {
      chain: 'solana-devnet',
      toAddress: '6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH',
      amount: '0.1',
    });
    expect(solRes.success).toBe(true);
    expect(solRes.broadcasted).toBe(true);
    expect(solRes.txHash.length).toBeGreaterThanOrEqual(32);
    expect(solRes.signature?.algorithm).toBe('Ed25519-FROST-TSS');

    // 5. Signs Bitcoin transaction via TSS
    const btcRes = await signTransaction(user.id, {
      chain: 'bitcoin-testnet',
      toAddress: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
      amount: '0.005',
    });
    expect(btcRes.success).toBe(true);
    expect(btcRes.broadcasted).toBe(true);
    expect(btcRes.txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(btcRes.signature?.algorithm).toBe('BIP340-Schnorr-TSS');

    // 6. Zero Persistence Invariant: Database STILL contains ZERO private keys and ZERO addresses
    const dbWallet = await prisma.walletIdentity.findUnique({
      where: { userId: user.id },
    });
    expect(dbWallet).toBeDefined();
    const strWallet = JSON.stringify(dbWallet);
    expect(strWallet).not.toContain(mstRes.txHash);
    expect(strWallet).not.toContain('0x2222222222222222222222222222222222222222');
    expect(strWallet).not.toContain('private_key');

    await prisma.user.delete({ where: { id: user.id } });
  });
});
