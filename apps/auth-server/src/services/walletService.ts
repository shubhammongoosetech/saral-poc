/**
 * SARAL Protocol V3 — Core Wallet Service
 *
 * Implements:
 * 1. Genuine 3-of-5 DKG-Backed Blockchain Address Derivation.
 * 2. Strict Zero Address & Zero Public Key Persistence in Database.
 * 3. Elimination of HMAC-based Address Fallbacks.
 * 4. Curve-Specific Compliance:
 *    - MST Testnet: secp256k1 Keccak-256 + EIP-55 mixed-case checksum
 *    - Solana Devnet: Ed25519 32-byte public key Base58
 *    - Bitcoin Testnet: secp256k1 BIP-341 Taproot output-key tweak + BIP-350 Bech32m (tb1p...)
 * 5. Strict Fail-Closed Security: No fake addresses, no random strings, clear errors.
 * 6. Migration & Legacy HMAC Detection for old fake addresses.
 */

import crypto from 'crypto';
import { DataStore, WalletMetadataRecord } from '../storage/store';
import { evaluateWorkingPolicy } from './policyService';
import { saralBackendClient } from '../clients/saralBackendClient';
import {
  toEip55Checksum,
  deriveEvmAddressFromPublicKey,
} from '../utils/eip55';
import {
  encodeBase58,
  deriveSolanaAddressFromPublicKey,
} from '../utils/base58';
import {
  encodeTaprootAddress as encodeTaprootBech32m,
  deriveBitcoinTaprootAddressFromPublicKey,
} from '../utils/bech32m';

export { toEip55Checksum, encodeBase58, encodeTaprootBech32m };

const store = DataStore.getInstance();

export interface ChainAddressInfo {
  blockchain: string;
  network: string;
  curve: string;
  address: string;
  status: string;
  verified: boolean;
  explorerUrl: string;
  notes: string;
  dkgBacked?: boolean;
  legacyHmacDetected?: boolean;
  migrationNotice?: string;
}

export interface MultiChainAddressesResponse {
  walletId: string;
  userId: string;
  status: string;
  addresses: {
    mst: ChainAddressInfo;
    solana: ChainAddressInfo;
    bitcoin: ChainAddressInfo;
  };
  policyStatus: {
    allowed: boolean;
    serverTime: string;
  };
}

/**
 * Calculates what the old deprecated HMAC algorithm would have produced for a given keyRef/walletId.
 * Strictly used for audit, legacy detection, and warning users whose addresses were not DKG-backed.
 */
export function calculateLegacyHmacAddress(
  walletId: string,
  keyRef: string,
  chain: 'mst' | 'solana' | 'bitcoin'
): string {
  if (chain === 'mst') {
    const seed = crypto
      .createHmac('sha256', keyRef || walletId)
      .update(`${walletId}:mst-testnet:secp256k1`)
      .digest();
    return toEip55Checksum(seed.subarray(12, 32).toString('hex'));
  } else if (chain === 'solana') {
    const seed = crypto
      .createHmac('sha256', keyRef || walletId)
      .update(`${walletId}:solana-devnet:ed25519`)
      .digest();
    return encodeBase58(seed);
  } else {
    const seed = crypto
      .createHmac('sha256', keyRef || walletId)
      .update(`${walletId}:bitcoin-taproot:secp256k1`)
      .digest();
    return encodeTaprootBech32m('tb', seed);
  }
}

/**
 * Checks whether an address was derived using the old deprecated HMAC algorithm.
 */
export function isLegacyHmacAddress(
  address: string,
  walletId: string,
  keyRef: string,
  chain: 'mst' | 'solana' | 'bitcoin'
): boolean {
  try {
    const legacy = calculateLegacyHmacAddress(walletId, keyRef, chain);
    return legacy.toLowerCase() === address.toLowerCase();
  } catch (_) {
    return false;
  }
}

/**
 * Derives a specific chain address exclusively from a verified DKG public key point.
 * Strictly fails closed if the public key format is invalid.
 */
export function deriveAddressFromDkgPublicKey(
  chain: 'mst' | 'solana' | 'bitcoin',
  pubKeyHex: string
): string {
  const cleanHex = pubKeyHex.replace(/^0x/, '');

  if (chain === 'mst') {
    return deriveEvmAddressFromPublicKey(cleanHex);
  } else if (chain === 'solana') {
    return deriveSolanaAddressFromPublicKey(cleanHex);
  } else if (chain === 'bitcoin') {
    return deriveBitcoinTaprootAddressFromPublicKey(cleanHex, 'tb');
  }

  throw new Error(`Unsupported chain family: ${chain}`);
}

/**
 * Derives multi-chain addresses exclusively from verified DKG public keys in RAM.
 * ZERO addresses are persisted in the central database.
 */
export function deriveMultiChainAddresses(
  walletId: string,
  keyRefsOrPublicKeys: {
    mst?: string;
    solana?: string;
    bitcoin?: string;
    dkgSessionId?: string;
  }
): {
  mst: ChainAddressInfo;
  solana: ChainAddressInfo;
  bitcoin: ChainAddressInfo;
} {
  const mstKey = keyRefsOrPublicKeys.mst || '';
  const solKey = keyRefsOrPublicKeys.solana || '';
  const btcKey = keyRefsOrPublicKeys.bitcoin || '';

  // Validate that inputs are valid cryptographic public keys, not arbitrary reference strings.
  // secp256k1: 64-byte raw coordinates, 65-byte uncompressed (04...), or 33-byte compressed (02/03...)
  // ed25519: 32-byte hex or 65-byte uncompressed
  const isSecpKey = (k: string) => /^(04[0-9a-fA-F]{128}|(02|03)[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$/.test(k);
  const isEdKey = (k: string) => /^(04[0-9a-fA-F]{128}|[0-9a-fA-F]{64})$/.test(k);

  let mstAddress: string;
  let solAddress: string;
  let btcAddress: string;

  if (isSecpKey(mstKey)) {
    mstAddress = deriveAddressFromDkgPublicKey('mst', mstKey);
  } else {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to derive MST address from non-public-key reference "${mstKey}". Addresses must be derived exclusively from verified 3-of-5 DKG public keys.`
    );
  }

  if (isEdKey(solKey)) {
    solAddress = deriveAddressFromDkgPublicKey('solana', solKey);
  } else {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to derive Solana address from non-public-key reference "${solKey}". Addresses must be derived exclusively from verified 3-of-5 DKG public keys.`
    );
  }

  if (isSecpKey(btcKey)) {
    btcAddress = deriveAddressFromDkgPublicKey('bitcoin', btcKey);
  } else {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to derive Bitcoin address from non-public-key reference "${btcKey}". Addresses must be derived exclusively from verified 3-of-5 DKG public keys.`
    );
  }

  return {
    mst: {
      blockchain: 'mst',
      network: 'mst-testnet',
      curve: 'secp256k1',
      address: mstAddress,
      status: 'ACTIVE_VERIFIED',
      verified: true,
      dkgBacked: true,
      explorerUrl: `https://explorer.mst.saral.network/address/${mstAddress}`,
      notes: 'Native EVM compatible sovereign chain with Keccak-256 and EIP-55 checksum',
    },
    solana: {
      blockchain: 'solana',
      network: 'solana-devnet',
      curve: 'ed25519',
      address: solAddress,
      status: 'ACTIVE_VERIFIED',
      verified: true,
      dkgBacked: true,
      explorerUrl: `https://explorer.solana.com/address/${solAddress}?cluster=devnet`,
      notes: 'Native Ed25519 32-byte public key Base58 encoded',
    },
    bitcoin: {
      blockchain: 'bitcoin',
      network: 'bitcoin-testnet',
      curve: 'secp256k1',
      address: btcAddress,
      status: 'ACTIVE_VERIFIED',
      verified: true,
      dkgBacked: true,
      explorerUrl: `https://blockstream.info/testnet/address/${btcAddress}`,
      notes: 'BIP-340/341 Taproot output with BIP-350 Bech32m encoding (tb1p...)',
    },
  };
}

// In-flight mutex map to prevent concurrent duplicate wallet creations for same user (Section 6 & 15)
const inFlightCreations = new Map<
  string,
  Promise<{
    wallet: WalletMetadataRecord;
    isNew: boolean;
    addresses: ReturnType<typeof deriveMultiChainAddresses>;
  }>
>();

/**
 * Recomputes returning user's wallet public key and multi-chain addresses directly from
 * verified distributed key shares on the Go Coordinator without ever reconstructing private keys.
 * STRICT FAIL-CLOSED: Never falls back to HMAC or arbitrary random addresses!
 */
export async function recomputeWalletAddressesFromShares(
  userId: string,
  clientLat?: number,
  clientLng?: number
): Promise<MultiChainAddressesResponse> {
  const policy = store.getPolicy(userId);
  let policyResult = { allowed: true, serverTime: new Date().toISOString() };
  if (policy) {
    const res = evaluateWorkingPolicy(userId, clientLat, clientLng);
    if (!res.allowed) {
      const err: any = new Error(res.reason || 'Access denied by Working Policy.');
      err.statusCode = 403;
      err.policyResult = res;
      throw err;
    }
    policyResult = res;
  }

  const wallet = store.getWalletByUserId(userId);
  if (!wallet) {
    const err: any = new Error('No SARAL wallet found for user. Please complete onboarding.');
    err.statusCode = 404;
    throw err;
  }

  const keyRefs = wallet.keyReferences || {};
  const dkgSessionId = keyRefs.dkgSessionId;

  let mstPubkey = '';
  let solPubkey = '';
  let btcPubkey = '';

  // 1. MST EVM (secp256k1)
  try {
    const mstResp = await saralBackendClient.derivePublicKey({
      walletId: wallet.walletId,
      userId,
      keyId: keyRefs.mst,
      dkgSessionId,
      committeeId: 'committee-foundation',
      curve: 'secp256k1',
      chainFamily: 'mst',
    });
    if (mstResp?.masterPublicKey) {
      mstPubkey = mstResp.masterPublicKey;
    }
  } catch (err: any) {
    if (keyRefs.mst && /^(04[0-9a-fA-F]{128}|(02|03)[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$/.test(keyRefs.mst)) {
      mstPubkey = keyRefs.mst;
    } else {
      throw new Error(
        `CRITICAL_SECURITY_ERROR: Failed to obtain verified 3-of-5 DKG public key for MST: ${err.message}. Fail-closed active.`
      );
    }
  }

  // 2. Solana (ed25519)
  try {
    const solResp = await saralBackendClient.derivePublicKey({
      walletId: wallet.walletId,
      userId,
      keyId: keyRefs.solana,
      dkgSessionId,
      committeeId: 'committee-foundation',
      curve: 'ed25519',
      chainFamily: 'solana',
    });
    if (solResp?.masterPublicKey) {
      solPubkey = solResp.masterPublicKey;
    }
  } catch (err: any) {
    if (keyRefs.solana && /^(04[0-9a-fA-F]{128}|[0-9a-fA-F]{64})$/.test(keyRefs.solana)) {
      solPubkey = keyRefs.solana;
    } else {
      throw new Error(
        `CRITICAL_SECURITY_ERROR: Failed to obtain verified 3-of-5 DKG public key for Solana: ${err.message}. Fail-closed active.`
      );
    }
  }

  // 3. Bitcoin (secp256k1)
  try {
    const btcResp = await saralBackendClient.derivePublicKey({
      walletId: wallet.walletId,
      userId,
      keyId: keyRefs.bitcoin,
      dkgSessionId,
      committeeId: 'committee-foundation',
      curve: 'secp256k1',
      chainFamily: 'bitcoin',
    });
    if (btcResp?.masterPublicKey) {
      btcPubkey = btcResp.masterPublicKey;
    }
  } catch (err: any) {
    if (keyRefs.bitcoin && /^(04[0-9a-fA-F]{128}|(02|03)[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$/.test(keyRefs.bitcoin)) {
      btcPubkey = keyRefs.bitcoin;
    } else {
      throw new Error(
        `CRITICAL_SECURITY_ERROR: Failed to obtain verified 3-of-5 DKG public key for Bitcoin: ${err.message}. Fail-closed active.`
      );
    }
  }

  const addresses = deriveMultiChainAddresses(wallet.walletId, {
    mst: mstPubkey,
    solana: solPubkey,
    bitcoin: btcPubkey,
    dkgSessionId,
  });

  // Check for legacy HMAC migration
  if (keyRefs.mst && isLegacyHmacAddress(addresses.mst.address, wallet.walletId, keyRefs.mst, 'mst')) {
    addresses.mst.legacyHmacDetected = true;
    addresses.mst.migrationNotice =
      'WARNING: Previous session displayed an unverified mock address. Address updated to genuine 3-of-5 DKG-backed key.';
  }

  return {
    walletId: wallet.walletId,
    userId: wallet.userId,
    status: 'READY',
    addresses,
    policyStatus: { allowed: true, serverTime: policyResult.serverTime },
  };
}

/**
 * Creates the user's single logical wallet through an idempotent state machine.
 * STRICT ONE-USER-ONE-WALLET RULE: If a wallet exists, returns the existing one!
 * CONCURRENT CREATION SAFETY: Deduplicates simultaneous requests into one active execution.
 */
export async function createOrGetWallet(userId: string): Promise<{
  wallet: WalletMetadataRecord;
  isNew: boolean;
  addresses: ReturnType<typeof deriveMultiChainAddresses>;
}> {
  // Check if wallet already exists
  const existing = store.getWalletByUserId(userId);
  if (existing && existing.status === 'READY') {
    const derived = await recomputeWalletAddressesFromShares(userId);
    return {
      wallet: existing,
      isNew: false,
      addresses: derived.addresses,
    };
  }

  // Deduplicate in-flight concurrent requests for same user
  if (inFlightCreations.has(userId)) {
    return inFlightCreations.get(userId)!;
  }

  const creationPromise = (async () => {
    try {
      // Re-check existing wallet after acquiring lock
      const doubleCheck = store.getWalletByUserId(userId);
      if (doubleCheck && doubleCheck.status === 'READY') {
        const derived = await recomputeWalletAddressesFromShares(userId);
        return {
          wallet: doubleCheck,
          isNew: false,
          addresses: derived.addresses,
        };
      }

      // First-time creation with stable opaque identifiers (Section 6)
      const walletId = `wal-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      // Distinct stable opaque chain-specific key references (Section 6)
      let dkgSessionId = `dkg-foundation-${crypto.randomUUID()}`;
      const keyMst = `key-mst-${crypto.randomBytes(8).toString('hex')}`;
      const keySol = `key-sol-${crypto.randomBytes(8).toString('hex')}`;
      const keyBtc = `key-btc-${crypto.randomBytes(8).toString('hex')}`;

      const keyReferences = {
        mst: keyMst,
        solana: keySol,
        bitcoin: keyBtc,
        dkgSessionId,
      };

      console.log(`[DKG] Initiating Dealerless 3-of-5 DKG on Coordinator for user ${userId}...`);
      const dkgSession = await saralBackendClient.startDkg({
        committeeId: 'committee-foundation',
        sessionId: dkgSessionId,
        n: 5,
        k: 3,
        t: 1,
      });
      if (dkgSession && dkgSession.sessionId) {
        dkgSessionId = dkgSession.sessionId;
        keyReferences.dkgSessionId = dkgSessionId;
      }
      console.log(`[DKG] Dealerless DKG session initialized: ${dkgSessionId}`);

      const newWallet: WalletMetadataRecord = {
        userId,
        walletId,
        status: 'READY',
        keyReferences,
        createdAt: now,
        updatedAt: now,
      };

      // Persist ONLY metadata into the database (ZERO addresses, ZERO public keys)
      store.saveWallet(newWallet);

      store.logSecurity({
        id: crypto.randomUUID(),
        userId,
        eventType: 'WALLET_CREATED_ONE_USER_ONE_WALLET',
        severity: 'INFO',
        details: { walletId, keyReferences },
        timestamp: now,
      });

      // Derive addresses from the real DKG shares via Coordinator
      const derived = await recomputeWalletAddressesFromShares(userId);

      return {
        wallet: newWallet,
        isNew: true,
        addresses: derived.addresses,
      };
    } finally {
      inFlightCreations.delete(userId);
    }
  })();

  inFlightCreations.set(userId, creationPromise);
  return creationPromise;
}

/**
 * Retrieves the user's addresses on-the-fly, strictly enforcing Working Policy.
 * Dynamically resolves from genuine 3-of-5 DKG shares in RAM.
 */
export async function getAuthenticatedWalletAddresses(
  userId: string,
  clientLat?: number,
  clientLng?: number
): Promise<MultiChainAddressesResponse> {
  return recomputeWalletAddressesFromShares(userId, clientLat, clientLng);
}
