/**
 * types.ts
 *
 * Types for the SARAL 3-Domain Separation of Powers Access Structure
 * (FOUNDATION, PUBLIC, PRIVATE) across multi-chain threshold signing.
 */

export type DomainName = 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';

export interface DomainQuorumConfig {
  count: number;     // Total nodes in domain (n_d)
  threshold: number; // Required quorum in domain (t_d)
}

export interface ThreeDomainTopologyConfig {
  foundation: DomainQuorumConfig;
  public: DomainQuorumConfig;
  private: DomainQuorumConfig;
}

export interface DomainKeyComponents {
  foundationPublicKeyHex: string; // Q_F
  publicPublicKeyHex: string;     // Q_P
  privatePublicKeyHex: string;    // Q_U
  aggregatedPublicKeyHex: string; // Q = Q_F + Q_P + Q_U
}

export type SupportedChain = 'solana' | 'bitcoin-taproot' | 'ethereum';

export interface ActiveParticipantConfig {
  participantId: string;
  shareIndex: number;
  domain: DomainName;
  identityPublicKeyHex: string;
  identityPrivateKeyHex?: string;
  endpoint?: { host: string; port: number };
  daemon?: any;
  keyShare?: any;
}

export interface ThreeDomainSigningRequest {
  sessionId: string;
  chain: SupportedChain;
  messageOrTx: Uint8Array | Buffer | string;
  domainTopology: ThreeDomainTopologyConfig;
  domainKeys: DomainKeyComponents;
  activeParticipants: ActiveParticipantConfig[];
  extraParams?: {
    chainId?: bigint;       // For EVM
    merkleRoot?: Buffer;    // For Taproot
    recentBlockhash?: string; // For Solana
  };
}

export interface ThreeDomainSigningResult {
  sessionId: string;
  chain: SupportedChain;
  domainsParticipated: DomainName[];
  rawSignatureHex: string;
  txHash?: string;
  rawSignedTxHex?: string;
  verified: boolean;
}
