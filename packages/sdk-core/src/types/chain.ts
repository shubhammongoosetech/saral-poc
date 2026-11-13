export type ChainType = 'evm' | 'solana';
export type CurveType = 'secp256k1' | 'ed25519';
export type SignatureScheme = 'ecdsa' | 'eddsa';

export interface BaseChainConfig {
  /** Unique chain identifier, e.g. 'mst-testnet', 'polygon-amoy', 'solana-devnet' */
  id: string;
  /** Human-readable chain name */
  name: string;
  /** Primary chain architecture type */
  type: ChainType;
  /** Cryptographic curve associated with this chain */
  curve: CurveType;
  /** Signature scheme used for transaction signing */
  signatureScheme: SignatureScheme;
  /** JSON-RPC endpoint URL */
  rpcUrl: string;
  /** Native token currency symbol */
  symbol: string;
  /** Block explorer base URL */
  explorerUrl: string;
  /** Whether this is a testnet */
  testnet?: boolean;
}

export interface EvmChainConfig extends BaseChainConfig {
  type: 'evm';
  curve: 'secp256k1';
  signatureScheme: 'ecdsa';
  /** Numeric EVM Chain ID */
  chainId: number;
  /** Default EVM transaction type (0 for legacy / EIP-155, 2 for EIP-1559) */
  defaultTxType?: 0 | 2;
}

export interface SolanaChainConfig extends BaseChainConfig {
  type: 'solana';
  curve: 'ed25519';
  signatureScheme: 'eddsa';
  /** Solana cluster identifier */
  cluster: 'devnet' | 'testnet' | 'mainnet-beta';
}

export type ChainConfig = EvmChainConfig | SolanaChainConfig;

