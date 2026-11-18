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
