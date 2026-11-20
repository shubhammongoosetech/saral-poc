import crypto from 'crypto';
import { KeyManager } from '../auth/token';

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
}

export interface CoordinatorStatusResponse {
  domain: string;
  status: string;
  enrolledNodes: number;
  onlineNodes: number;
  timestamp: string;
}

export class SaralBackendClient {
  private coordinatorUrl: string;
  private internalToken: string;
  private timeoutMs: number;
  private reqSeq: number = 1;

  constructor(config: { coordinatorUrl?: string; internalToken?: string; timeoutMs?: number } = {}) {
    this.coordinatorUrl = (config.coordinatorUrl || process.env.COORDINATOR_URL || 'http://localhost:9001').replace(/\/$/, '');
    this.internalToken = config.internalToken || process.env.SARAL_INTERNAL_TOKEN || '';
    this.timeoutMs = config.timeoutMs || 8000;
  }

  public async rpcCall<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    customToken?: string
  ): Promise<T> {
    const correlationId = `corr-${crypto.randomUUID()}`;
    const endpoint = this.coordinatorUrl.endsWith('/rpc') ? this.coordinatorUrl : `${this.coordinatorUrl}/rpc`;

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
            `HTTP error from Go Coordinator (${resp.status}): ${resp.statusText}`,
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

    throw lastError || new SaralBackendError('Go Coordinator connection failed after retries', -32603);
  }

  /**
   * Orchestrates first-time DKG across committee nodes.
   */
  public async startDkg(params: DkgStartParams = {}): Promise<DkgStartResponse> {
    return this.rpcCall<DkgStartResponse>('saral_startDkg', params as Record<string, unknown>);
  }

  /**
   * Retrieves public key from completed DKG session.
   */
  public async getDkgPublicKey(sessionId: string): Promise<DkgPublicKeyResponse> {
    return this.rpcCall<DkgPublicKeyResponse>('saral_getDkgPublicKey', { sessionId });
  }

  /**
   * Recomputes returning user's aggregate signing public key Y from verified distributed key shares
   * WITHOUT EVER exposing or reconstructing the complete private scalar x.
   */
  public async derivePublicKey(params: DerivePublicKeyParams): Promise<DerivePublicKeyResponse> {
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
      scopedToken
    );
  }

  public async getCoordinatorStatus(): Promise<CoordinatorStatusResponse> {
    return this.rpcCall<CoordinatorStatusResponse>('saral_getCoordinatorStatus');
  }

  public async getNetworkStatus(): Promise<unknown> {
    return this.rpcCall('saral_getNetworkStatus');
  }

  public async getDomainStatus(): Promise<unknown> {
    return this.rpcCall('saral_getDomainStatus');
  }
}

export const saralBackendClient = new SaralBackendClient();
export default saralBackendClient;
