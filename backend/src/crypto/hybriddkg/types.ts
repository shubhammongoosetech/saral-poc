/**
 * types.ts
 *
 * Types, message definitions, and configuration interfaces for Asynchronous
 * Verifiable Secret Sharing (HybridVSS) and Distributed Key Generation (HybridDKG).
 *
 * Reference:
 *   "Distributed Key Generation in the Wild" (Kate, Huang, Goldberg)
 *   Sections 3 & 4, Figures 1, 2, 3.
 */

import type { DomainType } from '../thresholdEcdsa';

export interface Clock {
  now(): number;
}

export interface Rng {
  randomScalar(): bigint;
}

export interface HybridDkgParams {
  n: number;
  t: number;
  f: number;
  degree: number;                  // degree = t
  threshold: number;               // k = t + 1 (reconstruction threshold)
  echoQuorum: number;              // ceil((n + t + 1) / 2)
  readyInterpolateThreshold: number; // t + 1
  readyCompleteThreshold: number;  // n - t - f
}

export interface NodeConfig {
  n: number;
  t: number;
  f: number;
  nodeIndex: number;               // 1-based index (1..n)
  nodeId: string;
  domain: DomainType;
  sessionId: string;
  allNodeIds: string[];
  helpLimitD?: number;             // d(kappa) upper bound on crashes (default 3)
  timeoutMs?: number;              // delay(T) for leader proposal timer
  clock?: Clock;
  rng?: Rng;
  signerPrivateKeyHex?: string;    // optional private key for signing RBC / leader change
  peerPublicKeys?: Map<number, string>; // nodeIndex -> compressed hex pubkey
}

// ---------------------------------------------------------------------------
// HybridVSS Messages (Figure 1)
// ---------------------------------------------------------------------------

export interface VssSendMsg {
  type: 'VSS_SEND';
  sessionId: string;
  domain: DomainType;
  dealerIndex: number;
  targetIndex: number;
  commitmentMatrix: string[][];    // (t+1) x (t+1) DLog commitments (paper sec 5.3)
  aCoeffs: string[];               // Coefficients of a_j(y) as 64-char hex strings
}

export interface VssEchoMsg {
  type: 'VSS_ECHO';
  sessionId: string;
  domain: DomainType;
  dealerIndex: number;
  fromIndex: number;
  targetIndex: number;
  commitmentMatrix: string[][];
  alpha: string;                   // alpha = a_from(target) as hex
}

export interface VssReadyMsg {
  type: 'VSS_READY';
  sessionId: string;
  domain: DomainType;
  dealerIndex: number;
  fromIndex: number;
  targetIndex: number;
  commitmentMatrix: string[][];
  beta: string;                    // beta = a_from(target) as hex
  signature?: string;              // Schnorr / ECDSA signature over (dealerIndex, mHash, beta)
}

export interface VssHelpMsg {
  type: 'VSS_HELP';
  sessionId: string;
  domain: DomainType;
  requesterIndex: number;
}

export interface VssHelpReplyMsg {
  type: 'VSS_HELP_REPLY';
  sessionId: string;
  domain: DomainType;
  fromIndex: number;
  targetIndex: number;
  messages: AnyProtocolMessage[];
}

export interface VssReconstructShareMsg {
  type: 'VSS_RECONSTRUCT_SHARE';
  sessionId: string;
  domain: DomainType;
  dealerIndex: number;
  fromIndex: number;
  sigma: string;                   // Final share s_from as hex
}

// ---------------------------------------------------------------------------
// HybridDKG Messages (Figures 2 & 3)
// ---------------------------------------------------------------------------

export interface DkgProposalMsg {
  type: 'DKG_PROPOSAL';
  sessionId: string;
  domain: DomainType;
  leaderIndex: number;
  Q: number[];                     // Selected t+1 dealer indices
  proofs: Record<number, VssReadyMsg[]>; // Dealer -> (n - t - f) ready messages
  signature?: string;
  signerPublicKeyHex?: string;
}

export interface DkgEchoMsg {
  type: 'DKG_ECHO';
  sessionId: string;
  domain: DomainType;
  leaderIndex: number;
  fromIndex: number;
  Q: number[];
  signature?: string;
  signerPublicKeyHex?: string;
}

export interface DkgReadyMsg {
  type: 'DKG_READY';
  sessionId: string;
  domain: DomainType;
  leaderIndex: number;
  fromIndex: number;
  Q: number[];
  signature?: string;
  signerPublicKeyHex?: string;
}

export interface DkgLeadChMsg {
  type: 'DKG_LEAD_CH';
  sessionId: string;
  domain: DomainType;
  proposedLeaderIndex: number;     // L' > L
  fromIndex: number;
  qHat: number[] | null;           // Possibly delivered Q or null
  signature?: string;
  signerPublicKeyHex?: string;
}

export type AnyProtocolMessage =
  | VssSendMsg
  | VssEchoMsg
  | VssReadyMsg
  | VssHelpMsg
  | VssHelpReplyMsg
  | VssReconstructShareMsg
  | DkgProposalMsg
  | DkgEchoMsg
  | DkgReadyMsg
  | DkgLeadChMsg;

export interface OutgoingMessage {
  targetIndex: number | 'broadcast';
  message: AnyProtocolMessage;
}

// ---------------------------------------------------------------------------
// Protocol Outputs
// ---------------------------------------------------------------------------

export interface HybridVssSharedOutput {
  dealerIndex: number;
  share: bigint;                   // s_i = a(0) mod n
  commitmentMatrix: string[][];
  matrixHash: string;
  readyProofs: VssReadyMsg[];      // n - t - f ready proofs
}

export interface HybridDkgOutput {
  nodeIndex: number;
  nodeId: string;
  domain: DomainType;
  share: bigint;                   // s_i = sum_{d in Q} s_{i,d} mod n
  domainPublicKeyHex: string;      // Q_d = sum_{d in Q} C_{d,00}
  commitments: string[];           // C_k = sum_{d in Q} C_{d,k0} for k in 0..t
  fullCommitmentMatrix: string[][];
  Q: number[];                     // Agreed set of t+1 dealers
}

export interface DkgResult {
  domain: DomainType;
  domainPublicKeyHex: string;        // Q_d = sum_{d in Q} C_{d,00}
  nodeShares: Map<string, bigint>;   // nodeId -> s_i (each node's accumulated share)
  allCommitments: Map<string, string[]>; // nodeId -> their row-0 commitments
  threshold: number;                 // Reconstruction threshold k = t + 1
  totalNodes: number;
}

