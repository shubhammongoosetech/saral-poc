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
  AVSSCreateSessionRequest,
  AVSSCreateSessionResponse,
  AVSSSessionStatusResponse,
  AVSSParticipantsResponse,
  AVSSCommitmentsResponse,
  AVSSVerificationStatusResponse,
  ProactiveEpochStatusResponse,
  ProactiveRefreshRequest,
  ProactiveRefreshResponse,
  DKGStartRequest,
  DKGStartResponse,
  DKGStatusResponse,
  DKGParticipantsResponse,
  DKGPublicKeyResponse,
  DKGVerificationStatusResponse,
  WalletRecord,
  CreateWalletRequest,
  WalletAddressResponse,
  UserProfile,
  WorkingPolicy,
  PolicyEvaluation,
  MfaEnrollResponse,
  MfaVerifyResponse,
  UserSession,
  MultiChainAddresses,
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

  // ==========================================
  // AVSS & Proactive Cryptosystems (Cachin et al. CCS 2002)
  // ==========================================

  /**
   * Initializes and starts an Asynchronous Verifiable Secret Sharing (AVSS) session.
   * Parameters must satisfy n - 2*t >= k and k > t.
   */
  public async createAVSSSession(req: AVSSCreateSessionRequest, coordUrl?: string): Promise<AVSSCreateSessionResponse> {
    return this.rpcCall<AVSSCreateSessionResponse>('saral_createAVSSSession', req, coordUrl);
  }

  /**
   * Returns aggregated progress of an AVSS session across committee participants.
   */
  public async getAVSSSessionStatus(sessionId: string, coordUrl?: string): Promise<AVSSSessionStatusResponse> {
    return this.rpcCall<AVSSSessionStatusResponse>('saral_getAVSSSessionStatus', { sessionId }, coordUrl);
  }

  /**
   * Returns active committee participants for an AVSS session.
   */
  public async getAVSSParticipants(sessionId?: string, committeeId?: string, coordUrl?: string): Promise<AVSSParticipantsResponse> {
    return this.rpcCall<AVSSParticipantsResponse>('saral_getAVSSParticipants', { sessionId, committeeId }, coordUrl);
  }

  /**
   * Returns the public Pedersen commitment matrix and secret commitment for a completed session.
   * Note: Raw secret shares are never returned over public APIs.
   */
  public async getAVSSCommitments(sessionId: string, coordUrl?: string): Promise<AVSSCommitmentsResponse> {
    return this.rpcCall<AVSSCommitmentsResponse>('saral_getAVSSCommitments', { sessionId }, coordUrl);
  }

  /**
   * Returns the cryptographic verification status for all committee participants.
   */
  public async getAVSSVerificationStatus(sessionId: string, coordUrl?: string): Promise<AVSSVerificationStatusResponse> {
    return this.rpcCall<AVSSVerificationStatusResponse>('saral_getAVSSVerificationStatus', { sessionId }, coordUrl);
  }

  /**
   * Returns proactive epoch management status across domain nodes.
   */
  public async getProactiveEpochStatus(coordUrl?: string): Promise<ProactiveEpochStatusResponse> {
    return this.rpcCall<ProactiveEpochStatusResponse>('saral_getProactiveEpochStatus', {}, coordUrl);
  }

  /**
   * Requests a proactive share refresh across the committee.
   * Requires k = t + 1 and n > 3*t (Configuration C dual-threshold AVSS is rejected).
   */
  public async requestProactiveRefresh(req: ProactiveRefreshRequest, coordUrl?: string): Promise<ProactiveRefreshResponse> {
    return this.rpcCall<ProactiveRefreshResponse>('saral_requestProactiveRefresh', req, coordUrl);
  }

  /**
   * Returns current proactive refresh status.
   */
  public async getRefreshStatus(committeeId?: string, coordUrl?: string): Promise<ProactiveEpochStatusResponse> {
    return this.rpcCall<ProactiveEpochStatusResponse>('saral_getRefreshStatus', { committeeId }, coordUrl);
  }

  // ==========================================
  // Dealerless Distributed Key Generation (DKG)
  // ==========================================

  /**
   * Initiates a dealerless DKG across the specified committee.
   * Parameters must satisfy n > 3*t, n - 2*t >= k, and k >= t + 1.
   */
  public async startDkg(req: DKGStartRequest, coordUrl?: string): Promise<DKGStartResponse> {
    return this.rpcCall<DKGStartResponse>('saral_startDkg', req, coordUrl);
  }

  /**
   * Returns current DKG progress across the committee.
   */
  public async getDkgStatus(sessionId?: string, coordUrl?: string): Promise<DKGStatusResponse> {
    return this.rpcCall<DKGStatusResponse>('saral_getDkgStatus', { sessionId }, coordUrl);
  }

  /**
   * Returns participants and qualified set information for a DKG session.
   */
  public async getDkgParticipants(sessionId?: string, coordUrl?: string): Promise<DKGParticipantsResponse> {
    return this.rpcCall<DKGParticipantsResponse>('saral_getDkgParticipants', { sessionId }, coordUrl);
  }

  /**
   * Returns the agreed master public key for a completed DKG session.
   */
  public async getDkgPublicKey(sessionId?: string, coordUrl?: string): Promise<DKGPublicKeyResponse> {
    return this.rpcCall<DKGPublicKeyResponse>('saral_getDkgPublicKey', { sessionId }, coordUrl);
  }

  /**
   * Returns cryptographic verification status of the DKG session.
   */
  public async getDkgVerificationStatus(sessionId?: string, coordUrl?: string): Promise<DKGVerificationStatusResponse> {
    return this.rpcCall<DKGVerificationStatusResponse>('saral_getDkgVerificationStatus', { sessionId }, coordUrl);
  }

  // ==========================================
  // Web3 Wallet Management
  // ==========================================

  /**
   * Creates a persistent public wallet metadata record on the target coordinator.
   * Enforces strict curve compatibility validation:
   * - Ethereum / EVM: requires secp256k1
   * - Bitcoin Taproot: requires secp256k1 (BIP-340)
   * - Solana: requires Ed25519
   * - Passkey / WebAuthn Account: supports NIST P-256
   */
  public async createWallet(req: CreateWalletRequest, coordUrl?: string): Promise<WalletRecord> {
    return this.rpcCall<WalletRecord>('saral_createWallet', req, coordUrl);
  }

  /**
   * Returns all public wallet records stored across the coordinator.
   */
  public async getWallets(coordUrl?: string): Promise<WalletRecord[]> {
    return this.rpcCall<WalletRecord[]>('saral_getWallets', {}, coordUrl);
  }

  /**
   * Returns a specific wallet record by its wallet ID.
   */
  public async getWalletById(walletId: string, coordUrl?: string): Promise<WalletRecord> {
    return this.rpcCall<WalletRecord>('saral_getWalletById', { walletId }, coordUrl);
  }

  /**
   * Returns verified address and cryptographic metadata for a wallet.
   */
  public async getWalletAddress(walletId: string, coordUrl?: string): Promise<WalletAddressResponse> {
    return this.rpcCall<WalletAddressResponse>('saral_getWalletAddress', { walletId }, coordUrl);
  }

  // ==========================================
  // User Authentication, MFA & Working Policy
  // ==========================================

  private async authHttp<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.authServerUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };
    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const res = await fetch(url, { ...options, headers });
    const json = await res.json();
    if (!res.ok || json.success === false) {
      throw new SaralError(json.error || `HTTP ${res.status}: ${res.statusText}`, res.status, json);
    }
    return json as T;
  }

  public async loginWithGoogle(credential: string): Promise<{
    user: UserProfile;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const data = await this.authHttp<any>('/auth/google', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
    if (data.token) this.token = data.token;
    return data;
  }

  public async requestPhoneOtp(mobile: string): Promise<{
    success: boolean;
    mobile: string;
    cooldownSeconds: number;
    devOtp?: string;
  }> {
    return this.authHttp<any>('/auth/otp/request', {
      method: 'POST',
      body: JSON.stringify({ mobile }),
    });
  }

  public async verifyPhoneOtp(mobile: string, otp: string): Promise<{
    user: UserProfile;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const data = await this.authHttp<any>('/auth/otp/verify', {
      method: 'POST',
      body: JSON.stringify({ mobile, otp }),
    });
    if (data.token) this.token = data.token;
    return data;
  }

  public async linkAccount(targetMethod: 'google' | 'mobile', identifier: string): Promise<{ success: boolean; user: UserProfile }> {
    return this.authHttp<any>('/auth/link-account', {
      method: 'POST',
      body: JSON.stringify({ targetMethod, identifier }),
    });
  }

  public async enrollMfa(): Promise<MfaEnrollResponse> {
    return this.authHttp<MfaEnrollResponse>('/mfa/enroll', { method: 'POST' });
  }

  public async verifyMfa(code: string): Promise<MfaVerifyResponse> {
    const data = await this.authHttp<MfaVerifyResponse>('/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    if (data.token) this.token = data.token;
    return data;
  }

  public async getSession(): Promise<UserSession> {
    return this.authHttp<UserSession>('/auth/session', { method: 'GET' });
  }

  public async getWorkingPolicy(): Promise<{ success: boolean; policy: WorkingPolicy | null }> {
    return this.authHttp<{ success: boolean; policy: WorkingPolicy | null }>('/wallet/policy', { method: 'GET' });
  }

  public async updateWorkingPolicy(policy: Partial<WorkingPolicy>): Promise<{ success: boolean; policy: WorkingPolicy }> {
    return this.authHttp<any>('/wallet/policy', {
      method: 'PUT',
      body: JSON.stringify(policy),
    });
  }

  public async evaluateWorkingPolicy(lat?: number, lng?: number): Promise<PolicyEvaluation> {
    return this.authHttp<PolicyEvaluation>('/wallet/policy/evaluate', {
      method: 'POST',
      body: JSON.stringify({ lat, lng }),
    });
  }

  public async getWalletStatus(): Promise<{
    hasWallet: boolean;
    walletId: string | null;
    status: string;
    hasPolicy: boolean;
    mfaVerified: boolean;
  }> {
    return this.authHttp<any>('/wallet/status', { method: 'GET' });
  }

  public async createWalletOnboarding(lat?: number, lng?: number): Promise<{
    success: boolean;
    isNew: boolean;
    walletId: string;
    status: string;
    addresses: MultiChainAddresses['addresses'];
  }> {
    return this.authHttp<any>('/wallet/create', {
      method: 'POST',
      body: JSON.stringify({ lat, lng }),
    });
  }

  public async getMultiChainAddresses(lat?: number, lng?: number): Promise<MultiChainAddresses> {
    const query = lat !== undefined && lng !== undefined ? `?lat=${lat}&lng=${lng}` : '';
    return this.authHttp<MultiChainAddresses>(`/wallet/addresses${query}`, { method: 'GET' });
  }
}

