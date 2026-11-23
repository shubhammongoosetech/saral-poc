import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { KeyManager } from '../auth/token';
import { WalletDomain } from '../config/wallet';
import { isKnownInsecureSecret } from '../config/auth';

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
  userId?: string;
  keyId?: string;
  curve?: 'secp256k1' | 'ed25519';
  chainFamily?: 'mst' | 'solana' | 'bitcoin';
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
}

export interface NodeStatusResponse {
  nodeId?: string;
  domain: string;
  status: string;
  enrolledNodes: number;
  onlineNodes: number;
  timestamp: string;
}

export type CoordinatorStatusResponse = NodeStatusResponse;

export class SaralBackendClient {
  private nodeUrls: Record<WalletDomain, string>;
  private internalToken: string;
  private timeoutMs: number;
  private reqSeq: number = 1;

  constructor(config: {
    nodeUrl?: string;
    nodeUrls?: Partial<Record<WalletDomain, string>>;
    coordinatorUrl?: string;
    coordinatorUrls?: Partial<Record<WalletDomain, string>>;
    internalToken?: string;
    timeoutMs?: number;
  } = {}) {
    this.nodeUrls = {
      foundation: config.nodeUrls?.foundation || config.nodeUrl || config.coordinatorUrls?.foundation || config.coordinatorUrl || process.env.SARAL_NODE_FOUNDATION_URL || process.env.SARAL_NODE_URL || process.env.COORDINATOR_URL || 'http://localhost:8001',
      public: config.nodeUrls?.public || config.coordinatorUrls?.public || process.env.SARAL_NODE_PUBLIC_URL || process.env.COORDINATOR_PUBLIC_URL || 'http://localhost:8006',
      private: config.nodeUrls?.private || config.coordinatorUrls?.private || process.env.SARAL_NODE_PRIVATE_URL || process.env.COORDINATOR_PRIVATE_URL || 'http://localhost:8011',
    };

    let token = config.internalToken || process.env.SARAL_INTERNAL_TOKEN || '';
    if (!token || isKnownInsecureSecret(token)) {
      const candidates = [
        process.env.SARAL_INTERNAL_TOKEN_FILE,
        '/run/secrets/saral_internal_token',
        path.resolve(process.cwd(), 'infra/secrets/internal_token.secret'),
        path.resolve(__dirname, '../../../infra/secrets/internal_token.secret'),
      ].filter(Boolean) as string[];
      for (const p of candidates) {
        try {
          if (fs.existsSync(p)) {
            const val = fs.readFileSync(p, 'utf8').trim();
            if (val && !isKnownInsecureSecret(val)) {
              token = val;
              break;
            }
          }
        } catch (_) {}
      }
    }
    this.internalToken = token;
    this.timeoutMs = config.timeoutMs || 15000;
  }

  public async rpcCall<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    customToken?: string,
    maxRetries = 2,
    domain: WalletDomain = 'foundation',
  ): Promise<T> {
    const correlationId = `corr-${crypto.randomUUID()}`;
    const nodeUrl = this.nodeUrls[domain].replace(/\/$/, '');
    const endpoint = nodeUrl.endsWith('/rpc') ? nodeUrl : `${nodeUrl}/rpc`;

    // Issue genuine EdDSA token for service authorization
    const bearerToken = customToken ?? KeyManager.getInstance().issueToken('auth-server', 'operator', true);

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

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const resp = await fetch(endpoint, {
          method: 'POST',
          headers,
          redirect: 'error',
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (!resp.ok) {
          throw new SaralBackendError(
            `HTTP error from SARAL Node (${resp.status}): ${resp.statusText}`,
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

    throw lastError || new SaralBackendError('SARAL Node connection failed after retries', -32603);
  }

  /**
   * Orchestrates first-time DKG across committee nodes.
   */
  public async startDkg(params: DkgStartParams = {}, domain: WalletDomain = 'foundation'): Promise<DkgStartResponse> {
    const token = params.userId && KeyManager.getInstance().issueScopedToken({
      sub: params.userId,
      userId: params.userId,
      walletId: params.walletId,
      keyId: params.keyId,
      dkgSessionId: params.sessionId,
      committeeId: params.committeeId,
      curve: params.curve,
      chainFamily: params.chainFamily,
      operation: 'start_dkg',
      policySatisfied: true,
      epoch: 1,
      exp: Math.floor(Date.now() / 1000) + 120,
    });
    return this.rpcCall<DkgStartResponse>('saral_startDkg', params as Record<string, unknown>, token, 0, domain);
  }

  /**
   * Retrieves status and node completion counts for an active DKG session.
   */
  public async getDkgStatus(sessionId: string, domain: WalletDomain = 'foundation'): Promise<DkgStatusResponse> {
    return this.rpcCall<DkgStatusResponse>('saral_getDkgStatus', { sessionId }, undefined, 0, domain);
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
  public async derivePublicKey(params: DerivePublicKeyParams, domain: WalletDomain = 'foundation'): Promise<DerivePublicKeyResponse> {
    // Generate scoped authorization token binding user and wallet identities
    const scopedToken = KeyManager.getInstance().issueScopedToken({
      sub: params.userId,
      userId: params.userId,
      walletId: params.walletId,
      keyId: params.keyId,
      dkgSessionId: params.dkgSessionId,
      committeeId: params.committeeId,
      curve: params.curve,
      chainFamily: params.chainFamily,
      epoch: params.epoch,
      operation: 'derive_public_key',
      policySatisfied: true,
      exp: Math.floor(Date.now() / 1000) + 120,
    });

    return this.rpcCall<DerivePublicKeyResponse>(
      'saral_derivePublicKey',
      (params as unknown) as Record<string, unknown>,
      scopedToken,
      0,
      domain,
    );
  }

  public async getNodeStatus(domain: WalletDomain = 'foundation'): Promise<NodeStatusResponse> {
    return this.rpcCall<NodeStatusResponse>('saral_getNodeStatus', {}, undefined, 0, domain);
  }

  public async getCoordinatorStatus(): Promise<CoordinatorStatusResponse> {
    return this.getNodeStatus();
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
