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
import { DOMAINS, DomainName } from '../config/env';
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
  const dkgSessionIds = keyRefs.dkgSessionIds as any;

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

  // FIX 1f: Legacy wallet detection — flat 3-string layout check
  const isLegacyFlatString =
    typeof dkgSessionIds.foundation === 'string' ||
    typeof dkgSessionIds.public === 'string' ||
    typeof dkgSessionIds.private === 'string';

  if (isLegacyFlatString) {
    wallet.status = 'LEGACY_CURVE_MISMATCH';
    await store.saveWallet(wallet);
    const err: any = new Error(
      'Wallet created with single/unsupported curve. Please re-onboard.'
    );
    err.statusCode = 409;
    throw err;
  }

  // Validate 6-session nested curve structure: 3 domains x 2 curves
  const hasAllCurves =
    dkgSessionIds.foundation?.secp256k1 &&
    dkgSessionIds.foundation?.ed25519 &&
    dkgSessionIds.public?.secp256k1 &&
    dkgSessionIds.public?.ed25519 &&
    dkgSessionIds.private?.secp256k1 &&
    dkgSessionIds.private?.ed25519;

  if (!hasAllCurves) {
    const err: any = new Error(
      'Wallet incomplete or legacy: all 3 domain sessions across both secp256k1 and ed25519 are strictly required. Re-onboarding required.'
    );
    err.statusCode = 409;
    throw err;
  }

  // 1. secp256k1 DKG (serves MST EVM and Bitcoin Taproot) — Query all 3 domains concurrently & add points
  let mstPubkey = '';
  let btcPubkey = '';
  try {
    const secpDomainPoints = await Promise.all(
      DOMAINS.map(async (domain) => {
        const resp = await saralBackendClient.derivePublicKey(domain.name, {
          walletId: wallet.walletId,
          userId,
          keyId: keyRefs.mst,
          dkgSessionId: dkgSessionIds[domain.name].secp256k1,
          committeeId: domain.committeeId,
          curve: 'secp256k1',
          chainFamily: 'mst',
        });
        if (!resp?.masterPublicKey) {
          throw new Error(`Missing masterPublicKey from ${domain.name} domain for secp256k1`);
        }
        return resp.masterPublicKey;
      })
    );
    mstPubkey = addSecp256k1PublicKeys(secpDomainPoints);
    // FIX 1c & FIX 1g: Both MST and Bitcoin share the verified secp256k1 public key point Y.
    // BIP-340/341 Taproot Parity Invariant:
    // Taproot addresses use the x-only public key (32 bytes) of the combined secp256k1 curve point Y.
    // In elliptic curve cryptography, both point Y = (x, y) and its negation -Y = (x, -y mod p) share
    // the identical x-coordinate and yield the identical Taproot bech32m address.
    // Threshold Taproot Schnorr signatures handle the odd/even parity bit during partial-signature aggregation
    // without ever needing to expose, reconstruct, or persist the master private key scalar.
    btcPubkey = mstPubkey;
  } catch (err: any) {
    throw new Error(
      `CRITICAL_SECURITY_ERROR: Failed to derive 3-domain public key for secp256k1 (MST/BTC): ${err.message}. Fail-closed active.`
    );
  }

  // 2. ed25519 DKG (serves Solana) — Query all 3 domains concurrently & add points
  let solPubkey = '';
  try {
    const solDomainPoints = await Promise.all(
      DOMAINS.map(async (domain) => {
        const resp = await saralBackendClient.derivePublicKey(domain.name, {
          walletId: wallet.walletId,
          userId,
          keyId: keyRefs.solana,
          dkgSessionId: dkgSessionIds[domain.name].ed25519,
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
      `CRITICAL_SECURITY_ERROR: Failed to derive 3-domain public key for Solana (ed25519): ${err.message}. Fail-closed active.`
    );
  }

  // Derive addresses strictly in RAM — zero database / file / log persistence
  const addresses = deriveMultiChainAddresses(wallet.walletId, {
    mst: mstPubkey,
    solana: solPubkey,
    bitcoin: btcPubkey,
    dkgSessionId: dkgSessionIds.foundation.secp256k1,
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
    const sessionIds = existing.keyReferences?.dkgSessionIds as any;
    const isLegacyFlatString =
      typeof sessionIds?.foundation === 'string' ||
      typeof sessionIds?.public === 'string' ||
      typeof sessionIds?.private === 'string';

    if (isLegacyFlatString) {
      existing.status = 'LEGACY_CURVE_MISMATCH';
      await store.saveWallet(existing);
      const err: any = new Error(
        'Wallet created with single/unsupported curve. Please re-onboard.'
      );
      err.statusCode = 409;
      throw err;
    }

    const is6SessionReady =
      sessionIds?.foundation?.secp256k1 &&
      sessionIds?.foundation?.ed25519 &&
      sessionIds?.public?.secp256k1 &&
      sessionIds?.public?.ed25519 &&
      sessionIds?.private?.secp256k1 &&
      sessionIds?.private?.ed25519;

    if (!is6SessionReady) {
      existing.status = 'LEGACY_CURVE_MISMATCH';
      await store.saveWallet(existing);
      const err: any = new Error(
        'Legacy single-domain or unsupported curve wallet detected. Protocol requires 3-domain multi-curve security. Re-onboarding required.'
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
        const sessionIds = doubleCheck.keyReferences?.dkgSessionIds as any;
        const isLegacyFlatString =
          typeof sessionIds?.foundation === 'string' ||
          typeof sessionIds?.public === 'string' ||
          typeof sessionIds?.private === 'string';

        if (isLegacyFlatString) {
          doubleCheck.status = 'LEGACY_CURVE_MISMATCH';
          await store.saveWallet(doubleCheck);
          const err: any = new Error(
            'Wallet created with single/unsupported curve. Please re-onboard.'
          );
          err.statusCode = 409;
          throw err;
        }

        const is6SessionReady =
          sessionIds?.foundation?.secp256k1 &&
          sessionIds?.foundation?.ed25519 &&
          sessionIds?.public?.secp256k1 &&
          sessionIds?.public?.ed25519 &&
          sessionIds?.private?.secp256k1 &&
          sessionIds?.private?.ed25519;

        if (!is6SessionReady) {
          doubleCheck.status = 'LEGACY_CURVE_MISMATCH';
          await store.saveWallet(doubleCheck);
          const err: any = new Error(
            'Legacy single-domain or unsupported curve wallet detected. Protocol requires 3-domain multi-curve security. Re-onboarding required.'
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

      // FIX 6: Retry on ERROR or DKG_IN_PROGRESS:
      // If previous wallet exists but is not READY, abort old sessions and generate FRESH 6 sessions,
      // but KEEP the same walletId and DB row (UNIQUE(userId) constraint).
      let walletId = doubleCheck?.walletId || `wal-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      if (doubleCheck && (doubleCheck.status === 'ERROR' || doubleCheck.status === 'DKG_IN_PROGRESS')) {
        const oldSessions = doubleCheck.keyReferences?.dkgSessionIds;
        if (oldSessions) {
          await Promise.all(
            DOMAINS.map(async (domain) => {
              const domEntry = oldSessions[domain.name];
              if (typeof domEntry === 'string') {
                await saralBackendClient.abortDkg(domain.name, domEntry).catch(() => {});
              } else if (domEntry && typeof domEntry === 'object') {
                if (domEntry.secp256k1) {
                  await saralBackendClient.abortDkg(domain.name, domEntry.secp256k1).catch(() => {});
                }
                if (domEntry.ed25519) {
                  await saralBackendClient.abortDkg(domain.name, domEntry.ed25519).catch(() => {});
                }
              }
            })
          );
        }
      }

      // Generate 6 fresh session IDs: 3 domains x 2 curves
      const dkgSessionIds = {
        foundation: {
          secp256k1: `dkg-foundation-secp-${crypto.randomUUID()}`,
          ed25519: `dkg-foundation-ed-${crypto.randomUUID()}`,
        },
        public: {
          secp256k1: `dkg-public-secp-${crypto.randomUUID()}`,
          ed25519: `dkg-public-ed-${crypto.randomUUID()}`,
        },
        private: {
          secp256k1: `dkg-private-secp-${crypto.randomUUID()}`,
          ed25519: `dkg-private-ed-${crypto.randomUUID()}`,
        },
      };

      const keyMst = doubleCheck?.keyReferences?.mst || `key-mst-${crypto.randomBytes(8).toString('hex')}`;
      const keySol = doubleCheck?.keyReferences?.solana || `key-sol-${crypto.randomBytes(8).toString('hex')}`;
      const keyBtc = doubleCheck?.keyReferences?.bitcoin || `key-btc-${crypto.randomBytes(8).toString('hex')}`;

      const keyReferences = {
        mst: keyMst,
        solana: keySol,
        bitcoin: keyBtc,
        dkgSessionId: dkgSessionIds.foundation.secp256k1,
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

      // FIX 7: Sanitized audit log using opaque correlation ID (no userId / session IDs leaked)
      const correlationId = `corr-${crypto.randomUUID()}`;
      console.log(`[DKG] Initiating 3-Domain Multi-Curve Dealerless DKG across 3 domains (6 sessions: 3 domains x 2 curves) [correlationId: ${correlationId}]`);

      // Start 6 DKGs across all 3 domains x 2 curves in parallel
      await Promise.all(
        DOMAINS.flatMap((domain) =>
          (['secp256k1', 'ed25519'] as const).map(async (curve) => {
            const sessionId = dkgSessionIds[domain.name][curve];
            const keyId = curve === 'secp256k1' ? keyMst : keySol;
            return saralBackendClient.startDkg(domain.name, {
              committeeId: domain.committeeId,
              sessionId,
              committee: domain.nodeIds,
              n: domain.n,
              k: domain.k,
              t: domain.t,
              walletId,
              userId,
              curve,
              keyId,
              chainFamily: curve === 'secp256k1' ? 'mst' : 'solana',
            });
          })
        )
      );

      // FIX 3: Await genuine DKG consensus across all 6 sessions
      // Require state === 'COMPLETED' && masterPublicKey && (qualifiedSet?.length ?? 0) >= k
      const pollStart = Date.now();
      const rawTimeout = parseInt(process.env.SARAL_DKG_TIMEOUT_MS || '15000', 10);
      const maxPollTime = isNaN(rawTimeout) || rawTimeout <= 0 ? 15000 : rawTimeout;
      const completedSessions = new Set<string>();

      const requiredSessions: { domain: DomainName; curve: 'secp256k1' | 'ed25519'; sessionId: string; k: number }[] = [];
      for (const domain of DOMAINS) {
        for (const curve of ['secp256k1', 'ed25519'] as const) {
          requiredSessions.push({
            domain: domain.name,
            curve,
            sessionId: dkgSessionIds[domain.name][curve],
            k: domain.k,
          });
        }
      }

      while (Date.now() - pollStart < maxPollTime && completedSessions.size < requiredSessions.length) {
        await Promise.all(
          requiredSessions.map(async (item) => {
            const sessionKey = `${item.domain}:${item.curve}`;
            if (completedSessions.has(sessionKey)) return;
            try {
              const status = await saralBackendClient.getDkgStatus(item.domain, item.sessionId);
              if (
                status?.state === 'COMPLETED' &&
                status?.masterPublicKey &&
                (status?.qualifiedSet?.length ?? 0) >= item.k
              ) {
                completedSessions.add(sessionKey);
              }
            } catch (_) {}
          })
        );
        if (completedSessions.size === requiredSessions.length) break;
        await new Promise((r) => setTimeout(r, 250));
      }

      if (completedSessions.size < requiredSessions.length) {
        const errorWallet: WalletMetadataRecord = {
          userId,
          walletId,
          status: 'ERROR',
          error: `3-Domain Multi-Curve DKG consensus timed out. Completed sessions: ${completedSessions.size} of ${requiredSessions.length}.`,
          keyReferences,
          createdAt: pendingWallet.createdAt,
          updatedAt: new Date().toISOString(),
        };
        await store.saveWallet(errorWallet);
        throw new Error(
          `Failed to obtain verified 3-domain DKG public keys: consensus timed out on 1 or more curve sessions. Fail-closed active.`
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
        isNew: !doubleCheck,
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
