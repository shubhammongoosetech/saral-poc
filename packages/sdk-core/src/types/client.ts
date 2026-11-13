import { CurveType } from './chain';
import { UnsignedTx } from './adapter';
import { DomainName } from './signing';
import { AccessLocation } from './policy';

export interface PrepareTransactionRequest {
  /** Target chain id (e.g. 'mst-testnet', 'polygon-amoy', 'solana-devnet') */
  chain: string;
  /** Recipient blockchain address */
  to: string;
  /** Amount in standard decimal units (e.g. "0.05") or atomic bigint */
  amount: string | bigint;
  /** Optional transaction memo */
  memo?: string;
}

export interface TransactionPreview {
  /** Resolved target chain ID */
  chain: string;
  /** Cryptographic curve used */
  curve: CurveType;
  /** Sender address derived from user's 3-domain MPC wallet */
  from: string;
  /** Recipient address */
  to: string;
  /** Amount formatted as decimal string */
  amount: string;
  /** Estimated network fee formatted as decimal string */
  fee: string;
  /** Hex-encoded 32-byte hash that will be signed by the 3 domains */
  hashToSign: string;
  /** Epoch expiration timestamp */
  expiresAt: number;
  /** Internal unsigned transaction reference */
  unsignedTx: UnsignedTx;
}

export interface SignAndSendOptions {
  /** User GPS location for Zero-Trust Geofencing and Velocity evaluation */
  location?: AccessLocation;
  /** Client-generated idempotency key to prevent double signing */
  idempotencyKey?: string;
}

export interface SignAndSendResult {
  /** Broadcasted transaction hash */
  txHash: string;
  /** Transaction status ('BROADCASTED' | 'CONFIRMED' | 'FAILED') */
  status: string;
  /** Direct link to block explorer transaction page */
  explorerUrl: string;
  /** The 3 domains that authenticated and contributed signatures */
  domainsSigned: DomainName[];
  /** Block number if confirmed */
  blockNumber?: number;
}

export interface TransactionRecord {
  id: string;
  chain: string;
  txHash: string;
  toAddress: string;
  amount: string;
  status: string;
  createdAt: string;
}

export interface SaralLogger {
  debug?(message: string, ...meta: unknown[]): void;
  info(message: string, ...meta: unknown[]): void;
  warn(message: string, ...meta: unknown[]): void;
  error(message: string, ...meta: unknown[]): void;
}

