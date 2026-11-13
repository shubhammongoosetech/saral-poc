import { EvmChainConfig, SolanaChainConfig, ChainConfig } from '../types/chain';

export const MST_TESTNET: EvmChainConfig = {
  id: 'mst-testnet',
  name: 'MST Testnet',
  type: 'evm',
  curve: 'secp256k1',
  signatureScheme: 'ecdsa',
  chainId: 91562037,
  rpcUrl: 'https://testnetrpc.mstblockchain.com',
  symbol: 'MSTC',
  explorerUrl: 'https://testnet.mstscan.com',
  testnet: true,
  defaultTxType: 0,
};

export const POLYGON_AMOY: EvmChainConfig = {
  id: 'polygon-amoy',
  name: 'Polygon Amoy',
  type: 'evm',
  curve: 'secp256k1',
  signatureScheme: 'ecdsa',
  chainId: 80002,
  rpcUrl: 'https://rpc-amoy.polygon.technology',
  symbol: 'MATIC',
  explorerUrl: 'https://amoy.polygonscan.com',
  testnet: true,
  defaultTxType: 2,
};

export const SOLANA_DEVNET: SolanaChainConfig = {
  id: 'solana-devnet',
  name: 'Solana Devnet',
  type: 'solana',
  curve: 'ed25519',
  signatureScheme: 'eddsa',
  cluster: 'devnet',
  rpcUrl: 'https://api.devnet.solana.com',
  symbol: 'SOL',
  explorerUrl: 'https://explorer.solana.com',
  testnet: true,
};

export const BUILT_IN_CHAINS: Record<string, ChainConfig> = {
  [MST_TESTNET.id]: MST_TESTNET,
  [POLYGON_AMOY.id]: POLYGON_AMOY,
  [SOLANA_DEVNET.id]: SOLANA_DEVNET,
};

