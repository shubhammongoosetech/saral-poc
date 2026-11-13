import { ChainConfig, CurveType } from './chain';

export interface PaymentRequest {
  /** Target chain identifier */
  chain: string;
  /** Recipient address */
  to: string;
  /** Amount to transfer as a decimal string or raw bigint (atomic units / wei / lamports) */
  amount: string | bigint;
  /** Optional transaction memo or reference */
  memo?: string;
  /** Optional gas limit override (EVM) */
  gasLimit?: bigint;
  /** Optional max fee per gas override (EVM EIP-1559) */
  maxFeePerGas?: bigint;
  /** Optional priority fee override (EVM EIP-1559) */
  maxPriorityFeePerGas?: bigint;
}

export interface UnsignedTx {
  /** Target chain identifier or numeric ID */
  chainId: string | number;
  /** Cryptographic curve for this transaction */
  curve: CurveType;
  /** Raw unsigned transaction payload bytes */
  rawBytes: Uint8Array;
  /** 32-byte hash/digest to be signed by the 3-domain MPC protocol */
  hashToSign: Uint8Array;
  /** Associated transaction metadata (nonce, fees, blockhash, etc.) */
  metadata: Record<string, unknown>;
  /** Timestamp (epoch ms) after which this unsigned transaction is expired/invalid */
  expiresAt?: number;
}

export interface SignatureResult {
  /** ECDSA / EdDSA r scalar or point representation (hex) */
  r: string;
  /** ECDSA / EdDSA s scalar representation (hex) */
  s: string;
  /** Recovery id / v value for EVM replay protection */
  v?: number;
  /** Parity bit (0 or 1) */
  yParity?: number;
  /** Raw concatenated signature bytes */
  rawBytes: Uint8Array;
}

export interface SignedTx {
  /** Target chain ID */
  chainId: string | number;
  /** Serialized raw signed transaction (hex string or bytes) */
  rawTx: string;
  /** Transaction hash */
  txHash: string;
}

export interface ConfirmationResult {
  confirmed: boolean;
  blockNumber?: number;
  confirmations?: number;
}

export interface FeeEstimate {
  feeAtomic: bigint;
  feeFormatted: string;
  gasPrice?: bigint;
  gasLimit?: bigint;
}

/**
 * Common adapter interface for multi-chain support.
 */
export interface ChainAdapter {
  readonly chain: ChainConfig;

  /** Derives public blockchain address from public key */
  deriveAddress(publicKey: Uint8Array | string): string;

  /** Validates whether an address string matches the chain's format */
  validateAddress(address: string): boolean;

  /** Fetches live balance in atomic units (wei / lamports). Throws on RPC error. */
  getBalance(address: string): Promise<bigint>;

  /** Builds an unsigned transaction, checks balance and nonce from RPC. Throws on error. */
  buildUnsignedTx(req: PaymentRequest, fromAddress: string): Promise<UnsignedTx>;

  /** Attaches aggregated 3-domain MPC signature to the unsigned transaction */
  attachSignature(unsignedTx: UnsignedTx, signature: SignatureResult): SignedTx;

  /** Broadcasts the signed transaction to the blockchain network */
  broadcast(signedTx: SignedTx): Promise<{ txHash: string; status: string }>;

  /** Waits for transaction confirmation */
  waitForConfirmation(
    txHash: string,
    opts?: { timeoutMs?: number; confirmations?: number }
  ): Promise<ConfirmationResult>;

  /** Constructs block explorer URL for a given transaction hash */
  explorerUrl(txHash: string): string;

  /** Estimates fee for a payment request */
  estimateFee(req: PaymentRequest, fromAddress: string): Promise<FeeEstimate>;
}

