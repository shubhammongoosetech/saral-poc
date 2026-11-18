import { DKGSessionData, WalletRecord, NetworkData } from '../types';

export class ApiService {
  private coordUrl: string;
  private authUrl: string;
  private token?: string;

  constructor(coordUrl: string = 'http://localhost:9001', authUrl: string = 'http://localhost:3001') {
    this.coordUrl = coordUrl;
    this.authUrl = authUrl;
  }

  public setCoordinatorUrl(url: string) {
    this.coordUrl = url;
  }

  public setToken(token: string) {
    this.token = token;
  }

  public async authenticate(subject: string = 'dev-operator', role: string = 'admin'): Promise<string> {
    const resp = await fetch(`${this.authUrl.replace(/\/$/, '')}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, role }),
    });
    if (!resp.ok) {
      throw new Error(`Auth server error (${resp.status}): ${resp.statusText}`);
    }
    const data = await resp.json();
    this.token = data.token;
    return data.token;
  }

  public async rpcCall<T = any>(method: string, params: any = {}): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const resp = await fetch(`${this.coordUrl.replace(/\/$/, '')}/rpc`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method,
        params,
      }),
    });

    if (!resp.ok) {
      throw new Error(`HTTP Error (${resp.status}): ${resp.statusText}`);
    }

    const json = await resp.json();
    if (json.error) {
      throw new Error(json.error.message || `RPC Error code: ${json.error.code}`);
    }

    return json.result;
  }

  // Network API
  public async getNetworkStatus(): Promise<NetworkData> {
    return this.rpcCall<NetworkData>('saral_getNetworkStatus', {});
  }

  public async probeNetwork(): Promise<any> {
    return this.rpcCall('saral_probeNetwork', {});
  }

  // DKG API
  public async startDkg(params: { n: number; k: number; t: number; committeeId: string }): Promise<any> {
    return this.rpcCall('saral_startDkg', params);
  }

  public async getDkgStatus(sessionId?: string): Promise<DKGSessionData> {
    return this.rpcCall<DKGSessionData>('saral_getDkgStatus', sessionId ? { sessionId } : {});
  }

  public async getDkgPublicKey(sessionId?: string): Promise<any> {
    return this.rpcCall('saral_getDkgPublicKey', sessionId ? { sessionId } : {});
  }

  // Wallet API
  public async createWallet(params: {
    name: string;
    blockchain: string;
    network: string;
    dkgSessionId: string;
  }): Promise<WalletRecord> {
    return this.rpcCall<WalletRecord>('saral_createWallet', params);
  }

  public async getWallets(): Promise<WalletRecord[]> {
    return this.rpcCall<WalletRecord[]>('saral_getWallets', {});
  }

  public async getWalletById(walletId: string): Promise<WalletRecord> {
    return this.rpcCall<WalletRecord>('saral_getWalletById', { walletId });
  }

  // Proactive Refresh
  public async requestProactiveRefresh(params: { committeeId: string; k: number; t: number }): Promise<any> {
    return this.rpcCall('saral_requestProactiveRefresh', params);
  }
}

export const apiService = new ApiService();
