/**
 * SARAL Protocol V3 — Architecture SDK Types
 */

export type DomainType = 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';

export interface JsonRpcRequest<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: T;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface NodeStatus {
  nodeId: string;
  domain: string;
  nodeIndex: number;
  publicKeyHex?: string;
  endpoint: string;
  status: 'HEALTHY' | 'UNREACHABLE' | 'DEGRADED' | 'UNKNOWN';
  lastChecked?: string;
  latencyMs?: number;
  peerCount?: number;
}

export interface PeerCoordinatorState {
  domain: string;
  endpoint: string;
  status: 'HEALTHY' | 'UNREACHABLE' | 'DEGRADED' | 'UNKNOWN';
  lastChecked?: string;
  latencyMs?: number;
}

export interface DomainStatus {
  domain: DomainType;
  coordinator: string;
  totalNodes: number;
  onlineNodes: number;
  nodes: NodeStatus[];
  timestamp?: string;
}

export interface NetworkStatus {
  network: string;
  leadDomain: DomainType;
  totalNodes: number;
  onlineNodes: number;
  domains: Record<string, DomainStatus>;
  peerCoordinators: PeerCoordinatorState[];
  timestamp: string;
}

export interface CoordinatorStatus {
  domain: DomainType;
  status: string;
  enrolledNodes: number;
  onlineNodes: number;
  peerCoordinators: PeerCoordinatorState[];
  timestamp: string;
}

export interface NodeProbeResult {
  requestId: string;
  probeId: string;
  sender: string;
  receiverId: string;
  domain: string;
  timestamp: number;
  acknowledged: boolean;
  latencyMs: number;
  signatureHex?: string;
  error?: string;
}

export interface NetworkProbeResponse {
  probeId: string;
  requestId: string;
  senderCoordinator: string;
  probesDispatched: number;
  probesAcknowledged: number;
  averageLatencyMs: number;
  probes: NodeProbeResult[];
  timestamp: string;
}

export interface TopologyInfo {
  coordinatorDomain: DomainType;
  domains: DomainType[];
  localNodes: Array<{
    nodeId: string;
    nodeIndex: number;
    domain: DomainType;
    endpoint: string;
  }>;
  peerCoordinators: string[];
}

export type DeliveryState =
  | 'CREATED'
  | 'QUEUED'
  | 'SENT'
  | 'FORWARDED'
  | 'DELIVERED'
  | 'ACKNOWLEDGED'
  | 'FAILED'
  | 'EXPIRED';

export interface RelaySendRequest {
  sourceNode?: string;
  sourceDomain?: string;
  targetNode: string;
  targetDomain?: string;
  type?: string;
  payload: Record<string, unknown>;
  timeoutMs?: number;
  messageId?: string;
}

export interface RelayAck {
  messageId: string;
  targetNode: string;
  targetDomain: string;
  sourceNode: string;
  sourceDomain: string;
  status: DeliveryState;
  timestamp: number;
  timestampIso?: string;
  latencyMs: number;
  recipientSigHex: string;
  recipientPubKey: string;
  forwardedBy?: string[];
  error?: string;
}

export interface DeliveryRecord {
  messageId: string;
  sourceNode: string;
  sourceDomain: string;
  targetNode: string;
  targetDomain: string;
  state: DeliveryState;
  createdAt: number;
  updatedAt: number;
  hops: string[];
  ack?: RelayAck;
  error?: string;
  retryCount?: number;
}

// AVSS & Proactive Cryptosystems Types (Cachin et al. CCS 2002)

export interface AVSSCreateSessionRequest {
  sessionId?: string;
  committeeId?: string;
  dealerId: string;
  n?: number;
  k: number;
  t: number;
  committee?: string[];
}

export interface AVSSCreateSessionResponse {
  success: boolean;
  sessionId: string;
  committeeId: string;
  dealerId: string;
  n: number;
  k: number;
  t: number;
  committee: string[];
  secretCommitment?: string;
  status: string;
  timestamp: string;
}

export interface AVSSNodeProgress {
  nodeId: string;
  state: string;
  echoCount: number;
  readyCount: number;
  completed: boolean;
  publicShareCommitment?: string;
  publicSecretCommitment?: string;
  error?: string;
}

export interface AVSSSessionStatusResponse {
  sessionId: string;
  status: string;
  completedNodes: number;
  totalNodes: number;
  nodes: Record<string, AVSSNodeProgress>;
  timestamp: string;
}

export interface AVSSParticipantsResponse {
  sessionId?: string;
  committeeId?: string;
  dealerId?: string;
  n?: number;
  k?: number;
  t?: number;
  committee?: string[];
  participants?: Record<string, unknown>;
}

export interface AVSSCommitmentsResponse {
  sessionId: string;
  commitments: string[][];
  secretCommitment: string;
}

export interface AVSSNodeVerificationReport {
  nodeId: string;
  hasRowPoly: boolean;
  hasColPoly: boolean;
  echoCount: number;
  readyCount: number;
  requiredEchos: number;
  requiredReadys: number;
  state: string;
  error?: string;
}

export interface AVSSVerificationStatusResponse {
  sessionId: string;
  nodes: Record<string, AVSSNodeVerificationReport>;
  timestamp: string;
}

export interface ProactiveEpochNodeStatus {
  nodeId: string;
  currentEpoch: number;
  epochState: string;
  shareVersion: number;
  commitmentVersion: number;
  isRefreshing: boolean;
  error?: string;
}

export interface ProactiveEpochStatusResponse {
  domain: string;
  nodes: Record<string, ProactiveEpochNodeStatus>;
  timestamp: string;
}

export interface ProactiveRefreshRequest {
  committeeId: string;
  committee?: string[];
  k: number;
  t: number;
  peerCommitments?: Record<string, string>;
  masterCommitment?: string;
}

export interface ProactiveRefreshResponse {
  success: boolean;
  committeeId: string;
  dispatchedNodes: number;
  totalNodes: number;
  k: number;
  t: number;
  status: string;
  timestamp: string;
}

// ==========================================
// Dealerless Distributed Key Generation (DKG) (Kate et al. 2012 / Cachin et al. 2002)
// ==========================================

export interface DKGStartRequest {
  sessionId?: string;
  committeeId?: string;
  n?: number;
  k?: number;
  t?: number;
  committee?: string[];
}

export interface DKGStartResponse {
  success: boolean;
  sessionId: string;
  committeeId: string;
  state: string;
  n: number;
  k: number;
  t: number;
  committee: string[];
}

export interface DKGParticipantSummary {
  nodeId: string;
  nodeIndex: number;
  contributionDealt: boolean;
  secretCommitment?: string;
  completedSharings: number;
  inQualifiedSet: boolean;
  publicShareCommit?: string;
  status: string;
}

export interface DKGStatusResponse {
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
  participants: Record<string, DKGParticipantSummary>;
  message?: string;
}

export interface DKGParticipantsResponse {
  sessionId: string;
  committeeId: string;
  participants: Record<string, DKGParticipantSummary>;
  qualifiedSet?: string[];
}

export interface DKGPublicKeyResponse {
  sessionId: string;
  committeeId: string;
  masterSigningPublicKey?: string;
  masterSecretCommitment?: string;
  masterPublicKey: string;
  curve: string;
  threshold: number;
  state: string;
}

export interface DKGVerificationStatusResponse {
  sessionId: string;
  committeeId: string;
  verified: boolean;
  state: string;
  masterSigningPublicKey?: string;
  masterSecretCommitment?: string;
  masterPublicKey?: string;
  qualifiedSet?: string[];
  completedNodes: number;
  totalNodes: number;
}

// ==========================================
// Web3 Wallet Management Types
// ==========================================

export type SupportedBlockchain =
  | 'ethereum'
  | 'polygon'
  | 'arbitrum'
  | 'optimism'
  | 'base'
  | 'bitcoin'
  | 'solana'
  | 'passkey-p256';

export type SupportedNetwork = 'mainnet' | 'sepolia' | 'testnet' | 'devnet';

export type SupportedCurve = 'secp256k1' | 'ed25519' | 'nist-p256';

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
  status: 'ADDRESS_CREATED' | 'ACTIVE' | 'DEGRADED';
  signingEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateWalletRequest {
  name: string;
  blockchain: string;
  network: string;
  dkgSessionId: string;
  keyId?: string;
}

export interface WalletAddressResponse {
  walletId: string;
  address: string;
  blockchain: string;
  network: string;
  curve: string;
  publicKeyHex: string;
  dkgSessionId: string;
  committeeId: string;
  status: string;
  signingEnabled: boolean;
}

export interface ChainCurveRequirement {
  blockchain: string;
  requiredCurve: SupportedCurve;
  name: string;
  description: string;
  addressFormat: string;
}





// ─── USER ONBOARDING, WORKING POLICY & MULTI-CHAIN ADDRESS TYPES ────────────

export interface UserProfile {
  id: string;
  name?: string;
  email?: string;
  googleId?: string;
  mobile?: string;
  loginMethod: 'google' | 'mobile';
  createdAt: string;
  updatedAt?: string;
}

export interface WorkingPolicy {
  userId?: string;
  timeRestrictionEnabled: boolean;
  startTime: string;
  endTime: string;
  days: string[];
  timezone: string;
  expiresAt?: string;
  locationRestrictionEnabled: boolean;
  allowedRegion?: string;
  geofenceEnabled?: boolean;
  lat?: number;
  lng?: number;
  radiusMeters?: number;
  updatedAt?: string;
}

export interface PolicyEvaluation {
  allowed: boolean;
  reason?: string;
  timeAllowed: boolean;
  locationAllowed: boolean;
  evaluatedAt: string;
  serverTime: string;
}

export interface MfaEnrollResponse {
  success: boolean;
  secret: string;
  qrUri: string;
  recoveryCodes: string[];
}

export interface MfaVerifyResponse {
  success: boolean;
  token: string;
  method?: string;
  hasPolicy: boolean;
  hasWallet: boolean;
}

export interface UserSession {
  success: boolean;
  user: UserProfile;
  mfaEnrolled: boolean;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
  policy?: WorkingPolicy | null;
}

export interface ChainAddressDetail {
  blockchain: string;
  network: string;
  curve: string;
  address: string;
  status: 'ACTIVE_VERIFIED' | 'AWAITING_DKG_CURVE';
  verified: boolean;
  explorerUrl?: string;
  notes?: string;
}

export interface MultiChainAddresses {
  walletId: string;
  userId: string;
  status: 'READY';
  addresses: {
    mst: ChainAddressDetail;
    solana: ChainAddressDetail;
    bitcoin: ChainAddressDetail;
  };
  policyStatus?: {
    allowed: boolean;
    serverTime: string;
  };
}
