/**
 * SARAL Protocol V3 — Core Wallet Service
 *
 * Implements 3-Domain Separation of Powers Architecture:
 * 1. For BOTH new and returning users, all 3 domains MUST take part:
 *    Foundation (5 nodes) + Public (5 nodes) + Private (5 nodes) = 15 nodes.
 * 2. Exactly ONE wallet per user (unique userId constraint). Same user -> same wallet, always.
 * 3. Returning user reuses the exact same 3-domain DKG sessions created at initial wallet creation.
 *    Never runs a new DKG for a user who already has a READY wallet.
 * 4. STRICT ZERO-SECRET PERSISTENCE (Requirement R4):
 *    Private signing keys are NEVER created, assembled, reconstructed, or persisted on any server,
 *    coordinator, node, database, log, or client device. Only public points and encrypted per-node
 *    shares inside each node's local AES-256-GCM vault exist.
 * 5. ZERO ADDRESS & ZERO PUBLIC KEY PERSISTENCE (Requirement R5):
 *    Addresses and public keys are NEVER stored in the database.
 *    They are re-derived in RAM at every login from the 3 domains via:
 *      Y_wallet = Y_foundation + Y_public + Y_private
 * 6. DYNAMIC NODE COUNTS & THRESHOLDS FROM ENV (Requirement R6):
 *    All parameters are sourced dynamically from DOMAINS configuration.
 */

import crypto from 'crypto';
import { DataStore, WalletMetadataRecord } from '../storage/store';
import { evaluateWorkingPolicy } from './policyService';
import { saralBackendClient } from '../clients/saralBackendClient';
import { DOMAINS, DOMAINS_MAP } from '../config/env';
import { addSecp256k1PublicKeys, addEd25519PublicKeys } from '../utils/curveMath';
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
 * Legacy HMAC calculation used EXCLUSIVELY for detecting and flagging old mock addresses.
 * STRICTLY NEVER used to generate addresses for new or returning user wallet flows.
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
      `CRITICAL SECURITY VIOLATION: Refusing to derive MST address from non-public-key reference "${mstKey}". Addresses must be derived exclusively from verified 3-domain DKG public keys.`
    );
  }

  if (isEdKey(solKey)) {
    solAddress = deriveAddressFromDkgPublicKey('solana', solKey);
  } else {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to derive Solana address from non-public-key reference "${solKey}". Addresses must be derived exclusively from verified 3-domain DKG public keys.`
    );
  }

  if (isSecpKey(btcKey)) {
    btcAddress = deriveAddressFromDkgPublicKey('bitcoin', btcKey);
  } else {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to derive Bitcoin address from non-public-key reference "${btcKey}". Addresses must be derived exclusively from verified 3-domain DKG public keys.`
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
 * verified distributed key shares on the 3 Domain Coordinators without ever reconstructing private keys.
 *
 * Curve Point Combination:
 *   Y_mst = Y_foundation_mst + Y_public_mst + Y_private_mst (secp256k1)
 *   Y_sol = Y_foundation_sol + Y_public_sol + Y_private_sol (ed25519)
 *   Y_btc = Y_foundation_btc + Y_public_btc + Y_private_btc (secp256k1)
 *
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
  const dkgSessionIds = keyRefs.dkgSessionIds;

  // Strict 3-Domain Invariant: All 3 domain session IDs must be present
  if (
    !dkgSessionIds ||
    !dkgSessionIds.foundation ||
    !dkgSessionIds.public ||
    !dkgSessionIds.private
  ) {
    const err: any = new Error(
      'Wallet incomplete or legacy: all 3 domain sessions (foundation, public, private) are strictly required. Re-onboarding required.'
    );
    err.statusCode = 409;
    throw err;
  }

  // 1. MST EVM (secp256k1) — Query all 3 domains concurrently & add points
  let mstPubkey = '';
  try {
    const mstDomainPoints = await Promise.all(
      DOMAINS.map(async (domain) => {
        const resp = await saralBackendClient.derivePublicKey({
          walletId: wallet.walletId,
          userId,
          keyId: keyRefs.mst,
          dkgSessionId: dkgSessionIds[domain.name],
          committeeId: domain.committeeId,
          curve: 'secp256k1',
          chainFamily: 'mst',
        });
        if (!resp?.masterPublicKey) {
          throw new Error(`Missing masterPublicKey from ${domain.name} domain for MST`);
        }
        return resp.masterPublicKey;
      })
    );
    mstPubkey = addSecp256k1PublicKeys(mstDomainPoints);
  } catch (err: any) {
    throw new Error(
      `CRITICAL_SECURITY_ERROR: Failed to derive 3-domain public key for MST: ${err.message}. Fail-closed active.`
    );
  }

  // 2. Solana (ed25519) — Query all 3 domains concurrently & add points
  let solPubkey = '';
  try {
    const solDomainPoints = await Promise.all(
      DOMAINS.map(async (domain) => {
        const resp = await saralBackendClient.derivePublicKey({
          walletId: wallet.walletId,
          userId,
          keyId: keyRefs.solana,
          dkgSessionId: dkgSessionIds[domain.name],
          committeeId: domain.committeeId,
          curve: 'ed25519',
          chainFamily: 'solana',
        });
        if (!resp?.masterPublicKey) {
          throw new Error(`Missing masterPublicKey from ${domain.name} domain for Solana`);
        }
        return resp.masterPublicKey;
      })
    );
    solPubkey = addEd25519PublicKeys(solDomainPoints);
  } catch (err: any) {
    throw new Error(
      `CRITICAL_SECURITY_ERROR: Failed to derive 3-domain public key for Solana: ${err.message}. Fail-closed active.`
    );
  }

  // 3. Bitcoin (secp256k1) — Query all 3 domains concurrently & add points
  let btcPubkey = '';
  try {
    const btcDomainPoints = await Promise.all(
      DOMAINS.map(async (domain) => {
        const resp = await saralBackendClient.derivePublicKey({
          walletId: wallet.walletId,
          userId,
          keyId: keyRefs.bitcoin,
          dkgSessionId: dkgSessionIds[domain.name],
          committeeId: domain.committeeId,
          curve: 'secp256k1',
          chainFamily: 'bitcoin',
        });
        if (!resp?.masterPublicKey) {
          throw new Error(`Missing masterPublicKey from ${domain.name} domain for Bitcoin`);
        }
        return resp.masterPublicKey;
      })
    );
    btcPubkey = addSecp256k1PublicKeys(btcDomainPoints);
  } catch (err: any) {
    throw new Error(
      `CRITICAL_SECURITY_ERROR: Failed to derive 3-domain public key for Bitcoin: ${err.message}. Fail-closed active.`
    );
  }

  // Derive addresses strictly in RAM — zero database / file / log persistence
  const addresses = deriveMultiChainAddresses(wallet.walletId, {
    mst: mstPubkey,
    solana: solPubkey,
    bitcoin: btcPubkey,
    dkgSessionId: dkgSessionIds.foundation,
  });

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
    const sessionIds = existing.keyReferences?.dkgSessionIds;
    const is3Domain = sessionIds && sessionIds.foundation && sessionIds.public && sessionIds.private;
    if (!is3Domain) {
      existing.status = 'LEGACY_SINGLE_DOMAIN';
      await store.saveWallet(existing);
      const err: any = new Error(
        'Legacy single-domain wallet detected. Protocol requires 3-domain security. Re-onboarding required.'
      );
      err.statusCode = 409;
      throw err;
    }
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
        const sessionIds = doubleCheck.keyReferences?.dkgSessionIds;
        const is3Domain = sessionIds && sessionIds.foundation && sessionIds.public && sessionIds.private;
        if (!is3Domain) {
          doubleCheck.status = 'LEGACY_SINGLE_DOMAIN';
          await store.saveWallet(doubleCheck);
          const err: any = new Error(
            'Legacy single-domain wallet detected. Protocol requires 3-domain security. Re-onboarding required.'
          );
          err.statusCode = 409;
          throw err;
        }
        const derived = await recomputeWalletAddressesFromShares(userId);
        return {
          wallet: doubleCheck,
          isNew: false,
          addresses: derived.addresses,
        };
      }

      // Check if DKG was already in progress with existing session IDs
      let walletId = doubleCheck?.walletId || `wal-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      let dkgSessionIds = doubleCheck?.keyReferences?.dkgSessionIds || {
        foundation: `dkg-foundation-${crypto.randomUUID()}`,
        public: `dkg-public-${crypto.randomUUID()}`,
        private: `dkg-private-${crypto.randomUUID()}`,
      };

      const keyMst = doubleCheck?.keyReferences?.mst || `key-mst-${crypto.randomBytes(8).toString('hex')}`;
      const keySol = doubleCheck?.keyReferences?.solana || `key-sol-${crypto.randomBytes(8).toString('hex')}`;
      const keyBtc = doubleCheck?.keyReferences?.bitcoin || `key-btc-${crypto.randomBytes(8).toString('hex')}`;

      const keyReferences = {
        mst: keyMst,
        solana: keySol,
        bitcoin: keyBtc,
        dkgSessionId: dkgSessionIds.foundation,
        dkgSessionIds,
      };

      const pendingWallet: WalletMetadataRecord = {
        userId,
        walletId,
        status: 'DKG_IN_PROGRESS',
        keyReferences,
        createdAt: doubleCheck?.createdAt || now,
        updatedAt: now,
      };
      await store.saveWallet(pendingWallet);

      console.log(`[DKG] Initiating 3-Domain Dealerless DKG across Foundation, Public, and Private domains for user ${userId}...`);

      // Start DKGs on ALL 3 domains in parallel
      await saralBackendClient.runOnAllDomains(async (domainName) => {
        const domainConfig = DOMAINS_MAP[domainName];
        return saralBackendClient.startDkg({
          committeeId: domainConfig.committeeId,
          sessionId: dkgSessionIds[domainName],
          committee: domainConfig.nodeIds,
          n: domainConfig.n,
          k: domainConfig.k,
          t: domainConfig.t,
          walletId,
          userId,
        });
      });

      console.log(`[DKG] 3-Domain DKG sessions initialized:`, dkgSessionIds);

      // Await genuine DKG consensus across all 3 domains
      const pollStart = Date.now();
      const maxPollTime = 15000;
      const completedDomains = new Set<string>();

      while (Date.now() - pollStart < maxPollTime && completedDomains.size < DOMAINS.length) {
        await Promise.all(
          DOMAINS.map(async (domain) => {
            if (completedDomains.has(domain.name)) return;
            try {
              const status = await saralBackendClient.getDkgStatus(dkgSessionIds[domain.name]);
              if (
                status?.state === 'COMPLETED' ||
                (status?.completedNodes && status.completedNodes >= domain.k)
              ) {
                completedDomains.add(domain.name);
              }
            } catch (_) {}
          })
        );
        if (completedDomains.size === DOMAINS.length) break;
        await new Promise((r) => setTimeout(r, 250));
      }

      if (completedDomains.size < DOMAINS.length) {
        const errorWallet: WalletMetadataRecord = {
          userId,
          walletId,
          status: 'ERROR',
          error: `3-Domain DKG consensus timed out. Completed domains: ${Array.from(completedDomains).join(', ')} of 3.`,
          keyReferences,
          createdAt: pendingWallet.createdAt,
          updatedAt: new Date().toISOString(),
        };
        await store.saveWallet(errorWallet);
        throw new Error(
          `Failed to obtain verified 3-domain DKG public keys: consensus timed out on 1 or more domains. Fail-closed active.`
        );
      }

      pendingWallet.status = 'KEY_READY';
      await store.saveWallet(pendingWallet);

      // Derive addresses from the real 3-domain shares via Coordinators
      const derived = await recomputeWalletAddressesFromShares(userId);

      const readyWallet: WalletMetadataRecord = {
        userId,
        walletId,
        status: 'READY',
        keyReferences,
        createdAt: pendingWallet.createdAt,
        updatedAt: new Date().toISOString(),
      };
      await store.saveWallet(readyWallet);

      store.logSecurity({
        id: crypto.randomUUID(),
        userId,
        eventType: 'WALLET_CREATED_THREE_DOMAIN',
        severity: 'INFO',
        details: { walletId, keyReferences },
        timestamp: now,
      });

      return {
        wallet: readyWallet,
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
 * Dynamically resolves from genuine 3-domain DKG shares in RAM.
 */
export async function getAuthenticatedWalletAddresses(
  userId: string,
  clientLat?: number,
  clientLng?: number
): Promise<MultiChainAddressesResponse> {
  return recomputeWalletAddressesFromShares(userId, clientLat, clientLng);
}
