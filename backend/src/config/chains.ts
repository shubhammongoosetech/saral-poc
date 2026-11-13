export interface BackendChainConfig {
  id: string;
  name: string;
  type: 'evm' | 'solana';
  curve: 'secp256k1' | 'ed25519';
  signatureScheme: 'ecdsa' | 'eddsa';
  chainId?: number;
  rpcUrl: string;
  symbol: string;
  explorerUrl: string;
  defaultTxType?: number;
}

export const BACKEND_CHAINS: Record<string, BackendChainConfig> = {
  'mst-testnet': {
    id: 'mst-testnet',
    name: 'MST Testnet',
    type: 'evm',
    curve: 'secp256k1',
    signatureScheme: 'ecdsa',
    chainId: 91562037,
    rpcUrl: process.env.RPC_URL || 'https://testnetrpc.mstblockchain.com',
    symbol: 'MSTC',
    explorerUrl: 'https://testnet.mstscan.com',
    defaultTxType: 0,
  },
  'polygon-amoy': {
    id: 'polygon-amoy',
    name: 'Polygon Amoy',
    type: 'evm',
    curve: 'secp256k1',
    signatureScheme: 'ecdsa',
    chainId: 80002,
    rpcUrl: 'https://rpc-amoy.polygon.technology',
    symbol: 'MATIC',
    explorerUrl: 'https://amoy.polygonscan.com',
    defaultTxType: 2,
  },
  'solana-devnet': {
    id: 'solana-devnet',
    name: 'Solana Devnet',
    type: 'solana',
    curve: 'ed25519',
    signatureScheme: 'eddsa',
    rpcUrl: 'https://api.devnet.solana.com',
    symbol: 'SOL',
    explorerUrl: 'https://explorer.solana.com',
  },
};

export function getBackendChainConfig(chainIdOrId?: string | number): BackendChainConfig {
  if (!chainIdOrId) {
    return BACKEND_CHAINS['mst-testnet'];
  }

  if (typeof chainIdOrId === 'string' && BACKEND_CHAINS[chainIdOrId]) {
    return BACKEND_CHAINS[chainIdOrId];
  }

  const found = Object.values(BACKEND_CHAINS).find(
    (c) => c.chainId === Number(chainIdOrId) || c.id === String(chainIdOrId)
  );

  if (!found) {
    throw new Error(`Unsupported chain: '${chainIdOrId}'. Supported chains: ${Object.keys(BACKEND_CHAINS).join(', ')}`);
  }

  return found;
}

