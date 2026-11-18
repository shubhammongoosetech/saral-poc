/**
 * types.ts
 *
 * Verifiable Secret Sharing (VSS) Core Types and Interfaces
 * Supports Feldman VSS, Pedersen VSS, and HybridVSS (Kate et al. 2012).
 */


export interface VssShare {
  index: number; // 1-based participant index
  value: bigint; // Secret share in F_n
}

export interface PedersenShare extends VssShare {
  blindingValue: bigint; // Blinding share t_i = Q(i) in F_n
}

export interface FeldmanVssPackage {
  dealerId: string;
  dealerIndex: number;
  threshold: number;
  totalShares: number;
  commitments: string[]; // C_k = a_k * G in compressed hex
  shares: VssShare[];
  createdAt: number;
}

export interface PedersenVssPackage {
  dealerId: string;
  dealerIndex: number;
  threshold: number;
  totalShares: number;
  commitments: string[]; // C_k = a_k * G + b_k * H in compressed hex
  shares: PedersenShare[];
  generatorH: string; // Compressed hex of generator H
  createdAt: number;
}

export interface VssComplaint {
  dealerId: string;
  dealerIndex: number;
  complainerId: string;
  complainerIndex: number;
  reason: 'INVALID_COMMITMENT' | 'SHARE_VERIFICATION_FAILED' | 'MALFORMED_SHARE' | 'TIMEOUT';
  signatureHex?: string;
  timestamp: number;
}

export interface VssComplaintResolution {
  dealerIndex: number;
  complainerIndex: number;
  isDealerMalicious: boolean;
  revealedShare?: VssShare;
  reason: string;
}
