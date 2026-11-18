import {
  DomainStatus,
  DomainType,
  JsonRpcRequest,
  JsonRpcResponse,
  NetworkProbeResponse,
  NetworkStatus,
  NodeStatus,
  PeerCoordinatorState,
  TopologyInfo,
  CoordinatorStatus,
  RelaySendRequest,
  DeliveryRecord,
} from './types';

export interface SaralClientConfig {
  coordinatorUrl?: string;
  authServerUrl?: string;
  token?: string;
  timeoutMs?: number;
}

export class SaralError extends Error {
  public code: number;
  public data?: unknown;

  constructor(message: string, code: number = -32603, data?: unknown) {
    super(message);
    this.name = 'SaralError';
    this.code = code;
    this.data = data;
  }
}

export class SaralClient {
  public coordinatorUrl: string;
  public authServerUrl: string;
  public token?: string;
  private timeoutMs: number;
  private reqId: number = 1;

  constructor(config: SaralClientConfig = {}) {
    this.coordinatorUrl = config.coordinatorUrl || 'http://localhost:9001';
    this.authServerUrl = config.authServerUrl || 'http://localhost:3001';
    this.token = config.token;
    this.timeoutMs = config.timeoutMs || 8000;
  }

  /**
   * Fetches an asymmetric RS256 Bearer JWT from the Auth Server for dev/testing.
   */
  public async authenticate(subject: string = 'dev-operator', role: string = 'admin'): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await fetch(`${this.authServerUrl.replace(/\/$/, '')}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, role }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        throw new SaralError(`Auth Server error (${resp.status}): ${resp.statusText}`);
      }

      const data = (await resp.json()) as { token: string };
      this.token = data.token;
      return this.token;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Executes a standard JSON-RPC 2.0 call against the target Coordinator.
   */
  public async rpcCall<T = unknown>(method: string, params: unknown = {}, customUrl?: string): Promise<T> {
    const url = (customUrl || this.coordinatorUrl).replace(/\/$/, '');
    const endpoint = url.endsWith('/rpc') ? url : `${url}/rpc`;

    const payload: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: this.reqId++,
      method,
      params,
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!resp.ok) {
        throw new SaralError(`HTTP error from Coordinator (${resp.status}): ${resp.statusText}`);
      }

      const json = (await resp.json()) as JsonRpcResponse<T>;

      if (json.error) {
        throw new SaralError(json.error.message, json.error.code, json.error.data);
      }

      return json.result as T;
    } catch (err: unknown) {
      if (err instanceof SaralError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError(`Network request failed: ${msg}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Returns aggregated 3-domain network status verified through Verifier.
   */
  public async getNetworkStatus(): Promise<NetworkStatus> {
    return this.rpcCall<NetworkStatus>('saral_getNetworkStatus');
  }

  /**
   * Returns the domain status from the coordinator.
   */
  public async getDomainStatus(domainUrl?: string): Promise<DomainStatus> {
    return this.rpcCall<DomainStatus>('saral_getDomainStatus', {}, domainUrl);
  }

  /**
   * Returns coordinator health and connected peers.
   */
  public async getCoordinatorStatus(coordUrl?: string): Promise<CoordinatorStatus> {
    return this.rpcCall<CoordinatorStatus>('saral_getCoordinatorStatus', {}, coordUrl);
  }

  /**
   * Returns all nodes managed by the coordinator's domain.
   */
  public async getNodes(coordUrl?: string): Promise<NodeStatus[]> {
    return this.rpcCall<NodeStatus[]>('saral_getNodes', {}, coordUrl);
  }

  /**
   * Returns peer coordinators discovered across domains.
   */
  public async getPeers(coordUrl?: string): Promise<PeerCoordinatorState[]> {
    return this.rpcCall<PeerCoordinatorState[]>('saral_getPeers', {}, coordUrl);
  }

  /**
   * Returns network topology.
   */
  public async getTopology(coordUrl?: string): Promise<TopologyInfo> {
    return this.rpcCall<TopologyInfo>('saral_getTopology', {}, coordUrl);
  }

  /**
   * Triggers an authenticated network probe through the coordinator and nodes.
   */
  public async probeNetwork(coordUrl?: string): Promise<NetworkProbeResponse> {
    return this.rpcCall<NetworkProbeResponse>('saral_probeNetwork', {}, coordUrl);
  }

  /**
   * Sends an authenticated bidirectional relay message from a source node to a target node.
   */
  public async sendRelayMessage(req: RelaySendRequest, coordUrl?: string): Promise<DeliveryRecord> {
    return this.rpcCall<DeliveryRecord>('saral_sendRelayMessage', req, coordUrl);
  }

  /**
   * Returns recent relay delivery records from the coordinator audit log.
   */
  public async getRelayAuditLog(coordUrl?: string): Promise<DeliveryRecord[]> {
    return this.rpcCall<DeliveryRecord[]>('saral_getRelayAuditLog', {}, coordUrl);
  }

  /**
   * Returns the delivery status of a specific relay message by ID.
   */
  public async getRelayDeliveryStatus(messageId: string, coordUrl?: string): Promise<DeliveryRecord> {
    return this.rpcCall<DeliveryRecord>('saral_getRelayDeliveryStatus', { messageId }, coordUrl);
  }
}

