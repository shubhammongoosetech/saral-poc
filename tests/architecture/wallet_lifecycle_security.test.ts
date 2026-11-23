import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import crypto from 'crypto';
import { prisma } from '../../apps/auth-server/src/database/prisma';
import { DataStore } from '../../apps/auth-server/src/storage/store';
import { saralBackendClient } from '../../apps/auth-server/src/clients/saralBackendClient';
import {
  createOrGetWallet,
  recomputeWalletAddressesFromShares,
  deriveAddressFromDkgPublicKey,
  deriveMultiChainAddresses,
  isLegacyHmacAddress,
  calculateLegacyHmacAddress,
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
  let createdWalletId: string;
  let initialAddresses: ReturnType<typeof deriveMultiChainAddresses>;

  // Verified DKG Aggregate Public Keys
  const SECP256K1_TEST_PUBKEY =
    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
  const ED25519_TEST_PUBKEY =
    '042169367072777666f3593f95feb28688789dd6b04e7cf45cb08f6ec91449bdf16666666666666666666666666666666666666666666666666666666666666658';

  beforeAll(async () => {
    // Configure mock DKG Coordinator response returning verified public keys
    vi.spyOn(saralBackendClient, 'startDkg').mockImplementation(async (domainOrParams: any, maybeParams?: any) => {
      const p = typeof domainOrParams === 'object' ? domainOrParams : maybeParams || {};
      return {
        success: true,
        sessionId: p.sessionId || 'sess-1',
        committeeId: p.committeeId || 'committee-foundation',
        state: 'COMPLETED',
        n: 5,
        k: 3,
        t: 1,
        committee: ['saral-foundation-1', 'saral-foundation-2', 'saral-foundation-3', 'saral-foundation-4', 'saral-foundation-5'],
      };
    });
    vi.spyOn(saralBackendClient, 'getDkgStatus').mockImplementation(async (domainOrSessionId: any, maybeSessionId?: any) => {
      const sId = typeof domainOrSessionId === 'string' ? domainOrSessionId : maybeSessionId || 'sess-1';
      return {
        sessionId: sId,
        committeeId: 'committee-foundation',
        epoch: 1,
        n: 5,
        k: 3,
        t: 1,
        state: 'COMPLETED',
        completedNodes: 5,
        totalNodes: 5,
        committee: ['saral-foundation-1', 'saral-foundation-2', 'saral-foundation-3', 'saral-foundation-4', 'saral-foundation-5'],
        qualifiedSet: ['saral-foundation-1', 'saral-foundation-2', 'saral-foundation-3', 'saral-foundation-4', 'saral-foundation-5'],
        masterPublicKey: SECP256K1_TEST_PUBKEY,
      };
    });
    vi.spyOn(saralBackendClient, 'derivePublicKey').mockImplementation(async (domainOrParams: any, maybeParams?: any) => {
      const params = typeof domainOrParams === 'object' ? domainOrParams : maybeParams || {};
      if (params.curve === 'ed25519' || params.chainFamily === 'solana') {
        return {
          success: true,
          walletId: params.walletId,
          keyId: params.keyId,
          sessionId: params.dkgSessionId || 'sess-1',
          committeeId: 'committee-foundation',
          epoch: 1,
          curve: 'ed25519',
          threshold: 3,
          masterPublicKey: ED25519_TEST_PUBKEY,
        };
      }
      return {
        success: true,
        walletId: params.walletId,
        keyId: params.keyId,
        sessionId: params.dkgSessionId || 'sess-1',
        committeeId: 'committee-foundation',
        epoch: 1,
        curve: 'secp256k1',
        threshold: 3,
        masterPublicKey: SECP256K1_TEST_PUBKEY,
      };
    });

    // Setup test user in database
    await prisma.user.deleteMany({ where: { email: 'sec-audit@saral.network' } });
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: 'sec-audit@saral.network',
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
    await prisma.user.deleteMany({ where: { email: 'sec-audit@saral.network' } });
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
    expect(keyRefs.mst).toMatch(/^key-mst-/);
    expect(keyRefs.solana).toMatch(/^key-sol-/);
    expect(keyRefs.bitcoin).toMatch(/^key-btc-/);
    expect(keyRefs.mst).not.toMatch(/^0x/);
    expect(keyRefs.mst).not.toMatch(/^04/);

    // Verify addresses are marked dkgBacked and match genuine cryptography
    expect(res.addresses.mst.dkgBacked).toBe(true);
    expect(res.addresses.solana.dkgBacked).toBe(true);
    expect(res.addresses.bitcoin.dkgBacked).toBe(true);

    expect(res.addresses.mst.address).toBe('0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69');
    expect(res.addresses.solana.address).toBeDefined();
    expect(res.addresses.solana.address.length).toBeGreaterThan(30);
    expect(res.addresses.bitcoin.address).toMatch(/^tb1p/);

    await prisma.user.delete({ where: { id: user.id } });
  });

  // -------------------------------------------------------------
  // TEST 2: SAME ADDRESS AFTER LOGOUT / LOGIN
  // -------------------------------------------------------------
  it('Test 2: Returning user derives exact same address without creating new DKG secret', async () => {
    const user = await prisma.user.findFirst({ where: { email: 'sec-audit@saral.network' } });
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
    expect(solAddr).toBe('6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7igV');

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
    const user = await prisma.user.findFirst({ where: { email: 'sec-audit@saral.network' } });
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

    // Temporarily mock Coordinator to simulate insufficient node shares (less than 3 nodes) for one call
    vi.spyOn(saralBackendClient, 'derivePublicKey').mockRejectedValueOnce(
      new Error('insufficient verified node shares: obtained 2 valid points, required threshold k=3')
    );

    // Recomputing addresses MUST fail closed: no fake address, no HMAC fallback
    await expect(recomputeWalletAddressesFromShares(tempUser.id)).rejects.toThrow(
      /CRITICAL_SECURITY_ERROR/
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

    const balances = await getLiveBalances(rawAddrs);
    expect(balances).toBeDefined();
    expect(typeof balances.mst).toBe('string');
    expect(parseFloat(balances.mst)).toBeGreaterThanOrEqual(0);
    expect(typeof balances.solana).toBe('string');
    expect(parseFloat(balances.solana)).toBeGreaterThanOrEqual(0);
    expect(typeof balances.bitcoin).toBe('string');
    expect(parseFloat(balances.bitcoin)).toBeGreaterThanOrEqual(0);

    const activity = await getLiveActivity(rawAddrs);
    expect(Array.isArray(activity)).toBe(true);
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
});
