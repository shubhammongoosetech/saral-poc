/**
 * MultiChainDkgCoordinator.ts
 *
 * Unified Coordinator for Multi-Chain Dealerless Distributed Key Generation (DKG).
 *
 * Mandatory Cryptographic Guarantees:
 *  1. Solana: Pure RFC 9591 FROST over Edwards25519 scalar field (L = 2^252 + 27742317777372353535851937790883648493).
 *     Never converts or hashes secp256k1 keys for Solana.
 *  2. Bitcoin Taproot: BIP-340 / BIP-341 Taproot-compatible FROST over secp256k1 with Even-Y parity,
 *     Taproot tweak t = TaggedHash('TapTweak', P_x), and BIP-350 Bech32m address.
 *  3. Ethereum / EVM: CGGMP21 threshold ECDSA over secp256k1 with EIP-55 checksum address.
 *  4. 3-Domain Separation of Powers: Master key Q = Q_F + Q_P + Q_U is formed additively across
 *     Foundation, Public, and Private domains. No combination of fewer than 3 domains can sign.
 *  5. Zero Central Secret: Complete private keys are NEVER reconstructed centrally.
 */

import fs from 'fs';
import path from 'path';
import { ethers } from 'ethers';
import { PublicKey } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';

import {
  executeEd25519DealerlessDkg,
  Ed25519DkgResult,
  FrostEd25519KeyShare,
} from '../protocols/frost-ed25519';
import {
  executeTaprootDealerlessDkg,
  TaprootDkgResult,
  FrostTaprootKeyShare,
  deriveTaprootKeysAndParity,
  encodeBech32mTaprootAddress,
} from '../protocols/frost-taproot';
import {
  executeCggmp21DealerlessDkg,
  Cggmp21DkgResult,
  Cggmp21KeyShare,
} from '../protocols/cggmp21';
import { DomainName, ThreeDomainTopologyConfig } from '../domain/types';

export interface ParticipantDkgConfig {
  id: string;
  index: number;
  domain: DomainName;
  identityPublicKeyHex: string;
}

export interface MultiChainDkgSessionResult {
  sessionId: string;
  topology: ThreeDomainTopologyConfig;
  solana: {
    groupPublicKeyHex: string;
    address: string;
    domainPublicKeys: Record<DomainName, string>;
    shares: Map<number, FrostEd25519KeyShare>;
    commitments: Map<number, string[]>;
  };
  bitcoinTaproot: {
    internalPublicKeyHex: string;
    outputPublicKeyHex: string;
    address: string;
    domainPublicKeys: Record<DomainName, string>;
    shares: Map<number, FrostTaprootKeyShare>;
    commitments: Map<number, string[]>;
  };
  ethereum: {
    groupPublicKeyHex: string;
    address: string;
    domainPublicKeys: Record<DomainName, string>;
    shares: Map<number, Cggmp21KeyShare>;
    commitments: Map<number, string[]>;
  };
}

export class MultiChainDkgCoordinator {
  /**
   * Executes genuine dealerless DKG ceremonies across all 3 supported chains:
   *  - Solana (Edwards25519 FROST)
   *  - Bitcoin Taproot (secp256k1 BIP-340/341 FROST)
   *  - Ethereum (secp256k1 CGGMP21)
   *
   * Adheres strictly to 3-Domain Separation of Powers:
   *  x = x_F + x_P + x_U
   *  Q = Q_F + Q_P + Q_U
   */
  public executeUnifiedMultiChainDkg(
    sessionId: string,
    participants: ParticipantDkgConfig[],
    topology: ThreeDomainTopologyConfig,
    bitcoinNetwork: 'mainnet' | 'testnet' = 'testnet'
  ): MultiChainDkgSessionResult {
    const domains: DomainName[] = ['FOUNDATION', 'PUBLIC', 'PRIVATE'];
    const domainThresholds: Record<DomainName, number> = {
      FOUNDATION: topology.foundation.threshold,
      PUBLIC: topology.public.threshold,
      PRIVATE: topology.private.threshold,
    };

    // 1. Group participants by domain and validate quorums
    const participantsByDomain: Record<DomainName, ParticipantDkgConfig[]> = {
      FOUNDATION: participants.filter((p) => p.domain === 'FOUNDATION'),
      PUBLIC: participants.filter((p) => p.domain === 'PUBLIC'),
      PRIVATE: participants.filter((p) => p.domain === 'PRIVATE'),
    };

    for (const d of domains) {
      if (participantsByDomain[d].length < domainThresholds[d]) {
        throw new Error(
          `[MultiChainDKG] Quorum failure for ${d}: got ${participantsByDomain[d].length}, required >= ${domainThresholds[d]}`
        );
      }
    }

    // =========================================================================
    // 2. Solana: 3-Domain Ed25519 Dealerless DKG
    // =========================================================================
    const solanaDomainResults = new Map<DomainName, Ed25519DkgResult>();
    let solanaGroupPoint = ed25519.ExtendedPoint.ZERO;
    const solanaDomainPubkeys: Record<DomainName, string> = {
      FOUNDATION: '',
      PUBLIC: '',
      PRIVATE: '',
    };

    for (const d of domains) {
      const res = executeEd25519DealerlessDkg(
        participantsByDomain[d].map((p) => ({ id: p.id, index: p.index, domain: p.domain })),
        domainThresholds[d]
      );
      solanaDomainResults.set(d, res);
      solanaDomainPubkeys[d] = res.groupPublicKeyHex;
      const pt = ed25519.ExtendedPoint.fromHex(res.groupPublicKeyHex);
      solanaGroupPoint = solanaGroupPoint.add(pt);
    }

    const solanaGroupPubkeyBytes = solanaGroupPoint.toRawBytes();
    const solanaGroupPublicKeyHex = Buffer.from(solanaGroupPubkeyBytes).toString('hex');
    const solanaAddress = new PublicKey(solanaGroupPubkeyBytes).toBase58();

    const solanaShares = new Map<number, FrostEd25519KeyShare>();
    const solanaCommitments = new Map<number, string[]>();
    for (const d of domains) {
      const res = solanaDomainResults.get(d)!;
      for (const [idx, share] of res.participantShares.entries()) {
        solanaShares.set(idx, {
          ...share,
          groupPublicKeyHex: solanaGroupPublicKeyHex,
        });
      }
      for (const [idx, comms] of res.commitments.entries()) {
        solanaCommitments.set(idx, comms);
      }
    }

    // =========================================================================
    // 3. Bitcoin Taproot: 3-Domain secp256k1 BIP-340/341 Dealerless DKG
    // =========================================================================
    const taprootDomainResults = new Map<DomainName, TaprootDkgResult>();
    let taprootInternalPoint = secp256k1.ProjectivePoint.ZERO;
    const taprootDomainPubkeys: Record<DomainName, string> = {
      FOUNDATION: '',
      PUBLIC: '',
      PRIVATE: '',
    };

    for (const d of domains) {
      const res = executeTaprootDealerlessDkg(
        participantsByDomain[d].map((p) => ({ id: p.id, index: p.index, domain: p.domain })),
        domainThresholds[d],
        undefined,
        bitcoinNetwork
      );
      taprootDomainResults.set(d, res);
      taprootDomainPubkeys[d] = res.internalPublicKeyHex;
      const pt = secp256k1.ProjectivePoint.fromHex(res.internalPublicKeyHex);
      taprootInternalPoint = taprootInternalPoint.add(pt);
    }

    const taprootInternalHex = Buffer.from(taprootInternalPoint.toRawBytes(true)).toString('hex');
    const overallTaprootParityCtx = deriveTaprootKeysAndParity(taprootInternalHex);
    const taprootAddress = encodeBech32mTaprootAddress(
      overallTaprootParityCtx.outputKeyX,
      bitcoinNetwork
    );

    const taprootShares = new Map<number, FrostTaprootKeyShare>();
    const taprootCommitments = new Map<number, string[]>();
    for (const d of domains) {
      const res = taprootDomainResults.get(d)!;
      for (const [idx, share] of res.participantShares.entries()) {
        taprootShares.set(idx, {
          ...share,
          groupPublicKeyHex: overallTaprootParityCtx.outputKeyX.toString('hex'),
        });
      }
      for (const [idx, comms] of res.commitments.entries()) {
        taprootCommitments.set(idx, comms);
      }
    }

    // =========================================================================
    // 4. Ethereum: 3-Domain secp256k1 CGGMP21 Dealerless DKG
    // =========================================================================
    const ethereumDomainResults = new Map<DomainName, Cggmp21DkgResult>();
    let ethGroupPoint = secp256k1.ProjectivePoint.ZERO;
    const ethDomainPubkeys: Record<DomainName, string> = {
      FOUNDATION: '',
      PUBLIC: '',
      PRIVATE: '',
    };

    for (const d of domains) {
      const res = executeCggmp21DealerlessDkg(
        participantsByDomain[d].map((p) => ({ id: p.id, index: p.index, domain: p.domain })),
        domainThresholds[d]
      );
      ethereumDomainResults.set(d, res);
      ethDomainPubkeys[d] = res.groupPublicKeyHex;
      const cleanHex = res.groupPublicKeyHex.startsWith('0x')
        ? res.groupPublicKeyHex.slice(2)
        : res.groupPublicKeyHex;
      const pt = secp256k1.ProjectivePoint.fromHex(cleanHex);
      ethGroupPoint = ethGroupPoint.add(pt);
    }

    const ethGroupPublicKeyHex =
      '0x' + Buffer.from(ethGroupPoint.toRawBytes(false)).toString('hex');
    const ethereumAddress = ethers.computeAddress(ethGroupPublicKeyHex);

    const ethereumShares = new Map<number, Cggmp21KeyShare>();
    const ethereumCommitments = new Map<number, string[]>();
    for (const d of domains) {
      const res = ethereumDomainResults.get(d)!;
      for (const [idx, share] of res.participantShares.entries()) {
        ethereumShares.set(idx, {
          ...share,
          groupPublicKeyHex: ethGroupPublicKeyHex,
        });
      }
      for (const [idx, comms] of res.commitments.entries()) {
        ethereumCommitments.set(idx, comms);
      }
    }

    return {
      sessionId,
      topology,
      solana: {
        groupPublicKeyHex: solanaGroupPublicKeyHex,
        address: solanaAddress,
        domainPublicKeys: solanaDomainPubkeys,
        shares: solanaShares,
        commitments: solanaCommitments,
      },
      bitcoinTaproot: {
        internalPublicKeyHex: taprootInternalHex,
        outputPublicKeyHex: overallTaprootParityCtx.outputKeyX.toString('hex'),
        address: taprootAddress,
        domainPublicKeys: taprootDomainPubkeys,
        shares: taprootShares,
        commitments: taprootCommitments,
      },
      ethereum: {
        groupPublicKeyHex: ethGroupPublicKeyHex,
        address: ethereumAddress,
        domainPublicKeys: ethDomainPubkeys,
        shares: ethereumShares,
        commitments: ethereumCommitments,
      },
    };
  }

  /**
   * Persists participant shares to isolated node vaults with file mode 0o600.
   */
  public persistSharesToVault(
    vaultDir: string,
    participantIndex: number,
    dkgResult: MultiChainDkgSessionResult
  ): void {
    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
    }

    const solanaShare = dkgResult.solana.shares.get(participantIndex);
    if (solanaShare) {
      const p = path.join(vaultDir, `share_frost_ed25519_${dkgResult.sessionId}.json`);
      fs.writeFileSync(p, JSON.stringify(solanaShare, null, 2), { mode: 0o600 });
    }

    const taprootShare = dkgResult.bitcoinTaproot.shares.get(participantIndex);
    if (taprootShare) {
      const p = path.join(vaultDir, `share_frost_taproot_${dkgResult.sessionId}.json`);
      fs.writeFileSync(p, JSON.stringify(taprootShare, null, 2), { mode: 0o600 });
    }

    const ethShare = dkgResult.ethereum.shares.get(participantIndex);
    if (ethShare) {
      const p = path.join(vaultDir, `share_cggmp21_${dkgResult.sessionId}.json`);
      fs.writeFileSync(p, JSON.stringify(ethShare, null, 2), { mode: 0o600 });
    }
  }
}

export const multiChainDkgCoordinator = new MultiChainDkgCoordinator();
