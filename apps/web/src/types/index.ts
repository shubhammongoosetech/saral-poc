export type NavigationTab =
  | 'overview'
  | 'network'
  | 'dkg-sessions'
  | 'key-management'
  | 'create-wallet'
  | 'wallets'
  | 'wallet-details'
  | 'proactive-refresh'
  | 'audit-logs'
  | 'settings';

export interface NodeItem {
  nodeId: string;
  domain: string;
  nodeIndex: number;
  endpoint: string;
  status: string;
  latencyMs?: number;
  peerCount?: number;
  publicKeyHex?: string;
}

export interface DomainBlock {
  domain: string;
  coordinator: string;
  totalNodes: number;
  onlineNodes: number;
  nodes: NodeItem[];
}

export interface NetworkData {
  totalNodes: number;
  onlineNodes: number;
  domains: Record<string, DomainBlock>;
}

export interface DKGSessionData {
  sessionId: string;
  committeeId: string;
  epoch: number;
  n: number;
  k: number;
  t: number;
  state: string;
  committee: string[];
  qualifiedSet?: string[];
  masterSigningPublicKey?: string;
  masterSecretCommitment?: string;
  masterPublicKey?: string;
  curve: string;
  completedNodes: number;
  totalNodes: number;
  participants: Record<string, {
    nodeId: string;
    nodeIndex: number;
    contributionDealt: boolean;
    inQualifiedSet: boolean;
    status: string;
  }>;
  createdAt?: string;
  updatedAt?: string;
}

export interface WalletRecord {
  walletId: string;
  name: string;
  blockchain: string;
  network: string;
  keyId: string;
  committeeId: string;
  dkgSessionId: string;
  curve: string;
  publicKeyHex: string;
  address: string;
  status: string;
  signingEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ProtocolEvent {
  id: string;
  time: string;
  type: 'INFO' | 'PROBE' | 'AUTH' | 'WALLET' | 'DKG' | 'ERROR';
  message: string;
}
