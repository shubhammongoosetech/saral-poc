/**
 * Internal JSON-RPC 2.0 client for Domain Coordinator communication.
 * Enables Auth Server to trigger DKG and fetch public keys without external SDK dependency.
 */

export interface DKGStartRequest {
  committeeId: string;
}

export interface DKGStartResponse {
  sessionId: string;
  committeeId: string;
  status: string;
}

export interface DKGPublicKeyResponse {
  sessionId: string;
  masterPublicKey?: string;
  masterSigningPublicKey?: string;
  status: string;
}

export class CoordinatorClient {
  public coordinatorUrl: string;
  public token?: string;
  private reqId = 1;

  constructor(coordinatorUrl: string = 'http://localhost:9001') {
    this.coordinatorUrl = coordinatorUrl;
  }

  public async rpcCall<T = unknown>(method: string, params: unknown = {}): Promise<T> {
    const url = this.coordinatorUrl.replace(/\/$/, '');
    const endpoint = url.endsWith('/rpc') ? url : `${url}/rpc`;

    const payload = {
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
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!resp.ok) {
        throw new Error(`HTTP error from Coordinator (${resp.status}): ${resp.statusText}`);
      }

      const json = (await resp.json()) as any;
      if (json.error) {
        throw new Error(json.error.message || 'Coordinator JSON-RPC error');
      }

      return json.result as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  public async startDkg(req: DKGStartRequest): Promise<DKGStartResponse> {
    return this.rpcCall<DKGStartResponse>('saral_startDkg', req);
  }

  public async getDkgPublicKey(sessionId?: string): Promise<DKGPublicKeyResponse> {
    return this.rpcCall<DKGPublicKeyResponse>('saral_getDkgPublicKey', { sessionId });
  }
}

