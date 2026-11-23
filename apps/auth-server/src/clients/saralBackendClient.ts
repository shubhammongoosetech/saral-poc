import crypto from 'crypto';
import { KeyManager } from '../auth/token';
import { DomainName, DOMAINS_MAP } from '../config/env';

export class SaralBackendError extends Error {
  public code: number;
  public data?: unknown;
  public correlationId?: string;

  constructor(message: string, code: number = -32603, data?: unknown, correlationId?: string) {
    super(message);
    this.name = 'SaralBackendError';
    this.code = code;
    this.data = data;
    this.correlationId = correlationId;
  }
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params: Record<string, unknown>;
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

export interface DkgStartParams {
  sessionId?: string;
  committeeId?: string;
  n?: number;
  k?: number;
  t?: number;
  committee?: string[];
  walletId?: string;
  keyId?: string;
  userId?: string;
  curve?: string;
  chainFamily?: string;
}

export interface DkgStartResponse {
  success: boolean;
  sessionId: string;
  committeeId: string;
  state: string;
  n: number;
  k: number;
  t: number;
  committee: string[];
}

export interface DkgStatusResponse {
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
  curve?: string;
  completedNodes: number;
  totalNodes: number;
  status?: string;
  message?: string;
}

export interface DkgPublicKeyResponse {
  sessionId: string;
  committeeId: string;
  masterPublicKey: string;
  curve: string;
  threshold: number;
  state: string;
}

export interface DerivePublicKeyParams {
  walletId: string;
  userId: string;
  keyId?: string;
  dkgSessionId?: string;
  committeeId?: string;
  curve?: string;
  chainFamily?: string;
  epoch?: number;
}

export interface DerivePublicKeyResponse {
  success: boolean;
  walletId: string;
  keyId: string;
  sessionId: string;
  committeeId: string;
  epoch: number;
  curve: string;
  threshold: number;
  masterPublicKey: string;
  derivedAddress?: string;
}

export interface CoordinatorStatusResponse {
  domain: string;
  status: string;
  enrolledNodes: number;
  onlineNodes: number;
  timestamp: string;
}

function isDomainName(val: unknown): val is DomainName {
  return val === 'foundation' || val === 'public' || val === 'private';
}

export class SaralBackendClient {
  public coordinatorUrls: Record<DomainName, string>;
  private internalToken: string;
  private timeoutMs: number;
  private reqSeq: number = 1;

  constructor(
    config: {
      coordinatorUrl?: string;
      coordinatorUrls?: Partial<Record<DomainName, string>>;
      internalToken?: string;
      timeoutMs?: number;
    } = {}
  ) {
    const defaultFoundation =
      config.coordinatorUrl ||
      process.env.FOUNDATION_COORDINATOR_URL ||
      process.env.COORDINATOR_URL ||
      DOMAINS_MAP?.foundation?.coordinatorUrl ||
      'http://localhost:9001';

    this.coordinatorUrls = {
      foundation: (config.coordinatorUrls?.foundation || defaultFoundation).replace(/\/$/, ''),
      public: (
        config.coordinatorUrls?.public ||
        process.env.PUBLIC_COORDINATOR_URL ||
        DOMAINS_MAP?.public?.coordinatorUrl ||
        'http://localhost:9002'
      ).replace(/\/$/, ''),
      private: (
        config.coordinatorUrls?.private ||
        process.env.PRIVATE_COORDINATOR_URL ||
        DOMAINS_MAP?.private?.coordinatorUrl ||
        'http://localhost:9003'
      ).replace(/\/$/, ''),
    };

    this.internalToken = config.internalToken || process.env.SARAL_INTERNAL_TOKEN || '';
    this.timeoutMs = config.timeoutMs || 8000;
  }

  public get coordinatorUrl(): string {
    return this.coordinatorUrls.foundation;
  }

  public set coordinatorUrl(url: string) {
    this.coordinatorUrls.foundation = url.replace(/\/$/, '');
  }

  public getCoordinatorUrl(domain: DomainName = 'foundation'): string {
    return this.coordinatorUrls[domain] || this.coordinatorUrls.foundation;
  }

  public async rpcCall<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    customToken?: string,
    domain: DomainName = 'foundation'
  ): Promise<T> {
    const correlationId = `corr-${crypto.randomUUID()}`;
    const baseUrl = this.getCoordinatorUrl(domain);
    const endpoint = baseUrl.endsWith('/rpc') ? baseUrl : `${baseUrl}/rpc`;

    // Issue genuine EdDSA token for service authorization
    let bearerToken = customToken;
    if (!bearerToken) {
      try {
        bearerToken = KeyManager.getInstance().issueToken('auth-server', 'operator', true);
      } catch (_) {}
    }

    const payload: JsonRpcRequest = {
      jsonrpc: '2.0',
      id: `${this.reqSeq++}-${correlationId}`,
      method,
      params,
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Correlation-ID': correlationId,
    };

    if (bearerToken) {
      headers['Authorization'] = `Bearer ${bearerToken}`;
    }
    if (this.internalToken) {
      headers['X-Saral-Internal-Token'] = this.internalToken;
    }

    let lastError: Error | null = null;
    const maxRetries = 2;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
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
          throw new SaralBackendError(
            `HTTP error from Go Coordinator [${domain}] (${resp.status}): ${resp.statusText}`,
            -32000,
            undefined,
            correlationId
          );
        }

        const json = (await resp.json()) as JsonRpcResponse<T>;

        if (json.error) {
          throw new SaralBackendError(
            json.error.message,
            json.error.code,
            json.error.data,
            correlationId
          );
        }

        return json.result as T;
      } catch (err: any) {
        lastError = err;
        if (err instanceof SaralBackendError && err.code !== -32000) {
          // Application-level RPC error; do not retry
          throw err;
        }
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, 100 * (attempt + 1)));
        }
      } finally {
        clearTimeout(timeout);
      }
    }

    throw lastError || new SaralBackendError(`Go Coordinator [${domain}] connection failed after retries`, -32603);
  }

  /**
   * Helper that executes the same operation across all 3 domains in parallel.
   * Rejects immediately if ANY domain fails (Strict Fail-Closed).
   */
  public async runOnAllDomains<T>(
    fn: (domain: DomainName) => Promise<T>
  ): Promise<Record<DomainName, T>> {
    const domains: DomainName[] = ['foundation', 'public', 'private'];
    const entries = await Promise.all(
      domains.map(async (d) => {
        const val = await fn(d);
        return [d, val] as const;
      })
    );
    return Object.fromEntries(entries) as Record<DomainName, T>;
  }

  /**
   * Orchestrates DKG across committee nodes for an explicitly designated domain.
   */
  public async startDkg(
    domain: DomainName,
    params: DkgStartParams
  ): Promise<DkgStartResponse> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }
    return this.rpcCall<DkgStartResponse>('saral_startDkg', params as Record<string, unknown>, undefined, domain);
  }

  /**
   * Retrieves status and node completion counts for an active DKG session on an explicit domain.
   */
  public async getDkgStatus(
    domain: DomainName,
    sessionId: string
  ): Promise<DkgStatusResponse> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }
    return this.rpcCall<DkgStatusResponse>('saral_getDkgStatus', { sessionId }, undefined, domain);
  }

  /**
   * Retrieves public key from completed DKG session on an explicit domain.
   */
  public async getDkgPublicKey(
    domain: DomainName,
    sessionId: string
  ): Promise<DkgPublicKeyResponse> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }
    return this.rpcCall<DkgPublicKeyResponse>('saral_getDkgPublicKey', { sessionId }, undefined, domain);
  }

  /**
   * Marks an incomplete/failed DKG session as ABORTED on an explicit domain.
   */
  public async abortDkg(
    domain: DomainName,
    sessionId: string
  ): Promise<{ success: boolean; sessionId: string; state: string }> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }
    return this.rpcCall('saral_abortDkg', { sessionId }, undefined, domain);
  }

  /**
   * Recomputes domain aggregate signing public key Y_domain from verified distributed key shares
   * on an explicit domain WITHOUT EVER exposing or reconstructing the complete private scalar x.
   */
  public async derivePublicKey(
    domain: DomainName,
    params: DerivePublicKeyParams
  ): Promise<DerivePublicKeyResponse> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }

    // Generate scoped authorization token binding user and wallet identities
    const scopedToken = KeyManager.getInstance().issueScopedToken({
      sub: params.userId,
      userId: params.userId,
      walletId: params.walletId,
      keyId: params.keyId,
      dkgSessionId: params.dkgSessionId,
      committeeId: params.committeeId,
      curve: params.curve,
      epoch: params.epoch,
      operation: 'derive_public_key',
    });

    return this.rpcCall<DerivePublicKeyResponse>(
      'saral_derivePublicKey',
      (params as unknown) as Record<string, unknown>,
      scopedToken,
      domain
    );
  }

  public async getCoordinatorStatus(domain: DomainName = 'foundation'): Promise<CoordinatorStatusResponse> {
    return this.rpcCall<CoordinatorStatusResponse>('saral_getCoordinatorStatus', {}, undefined, domain);
  }

  public async getNetworkStatus(domain: DomainName = 'foundation'): Promise<unknown> {
    return this.rpcCall('saral_getNetworkStatus', {}, undefined, domain);
  }

  public async getDomainStatus(domain: DomainName = 'foundation'): Promise<unknown> {
    return this.rpcCall('saral_getDomainStatus', {}, undefined, domain);
  }

  public async probeCoordinatorHealth(domain: DomainName): Promise<{ status: string; domain: string; enrolledNodes: number }> {
    if (!domain || !isDomainName(domain)) {
      throw new Error(`[saralBackendClient] DomainName is strictly required: got "${domain}"`);
    }
    const url = `${this.getCoordinatorUrl(domain)}/health`;
    const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) {
      throw new Error(`Coordinator ${domain} health check failed with status ${res.status}`);
    }
    return res.json() as Promise<{ status: string; domain: string; enrolledNodes: number }>;
  }
}

export const saralBackendClient = new SaralBackendClient();
export default saralBackendClient;
