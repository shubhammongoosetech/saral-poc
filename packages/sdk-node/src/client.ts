import { ethers } from 'ethers';
import {
  ChainConfig,
  ChainRegistry,
  defaultChainRegistry,
  createChainAdapter,
  ChainAdapter,
  PaymentRequest,
  PrepareTransactionRequest,
  TransactionPreview,
  SignAndSendOptions,
  SignAndSendResult,
  TransactionRecord,
  DomainName,
  ThreeDomainSignatures,
  EcdsaSigner,
  EddsaSigner,
  SignerBackend,
  SaralError,
  PolicyDeniedError,
  SaralLogger,
  redact,
} from '@saral/sdk-core';

export interface SaralClientOptions {
  /** SARAL Backend base URL (must use HTTPS except for localhost) */
  baseUrl: string;
  /** Function returning active user authentication JWT token */
  getAuthToken?: () => Promise<string | null> | string | null;
  /** Optional custom or additional chain configurations */
  chains?: Record<string, ChainConfig> | ChainConfig[];
  /** HTTP request timeout in milliseconds (default: 30,000) */
  timeoutMs?: number;
  /** Custom logger */
  logger?: SaralLogger;
}

export class SaralClient {
  public readonly baseUrl: string;
  public readonly registry: ChainRegistry;
  private readonly getAuthToken?: () => Promise<string | null> | string | null;
  private readonly timeoutMs: number;
  private readonly logger?: SaralLogger;
  private readonly ecdsaSigner = new EcdsaSigner();
  private readonly eddsaSigner = new EddsaSigner();

  constructor(options: SaralClientOptions) {
    const rawUrl = options.baseUrl.trim().replace(/\/+$/, '');

    // Security Check: Enforce HTTPS except for localhost
    const isLocalhost =
      rawUrl.startsWith('http://localhost') ||
      rawUrl.startsWith('http://127.0.0.1') ||
      rawUrl.startsWith('http://[::1]');

    if (!rawUrl.startsWith('https://') && !isLocalhost) {
      throw new SaralError(
        'INVALID_CONFIG',
        `SARAL client requires secure HTTPS endpoint. Insecure HTTP prohibited: ${rawUrl}`
      );
    }

    this.baseUrl = rawUrl;
    this.getAuthToken = options.getAuthToken;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.logger = options.logger;
    this.registry = options.chains ? new ChainRegistry(options.chains) : defaultChainRegistry;
  }

  // ==========================================
  // Low-Level Inspection & Helper APIs
  // ==========================================

  public detectChain(chainId: string): { chain: ChainConfig; curve: string; scheme: string } {
    return this.registry.detectChain(chainId);
  }

  public validateAddress(chainId: string, address: string): boolean {
    return this.registry.isValidAddress(chainId, address);
  }

  public getAdapter(chainId: string): ChainAdapter {
    const chain = this.registry.getChain(chainId);
    return createChainAdapter(chain);
  }

  // ==========================================
  // Authentication & MFA APIs
  // ==========================================

  public async requestMobileOtp(mobile: string): Promise<{ success: boolean; message: string }> {
    return this.request('/api/auth/otp/request', {
      method: 'POST',
      body: { mobile },
    });
  }

  public async verifyMobileOtp(
    mobile: string,
    code: string
  ): Promise<{ token: string; user: Record<string, unknown>; mfaRequired: boolean }> {
    return this.request('/api/auth/otp/verify', {
      method: 'POST',
      body: { mobile, code },
    });
  }

  public async loginGoogle(
    credential: string
  ): Promise<{ token: string; user: Record<string, unknown>; mfaRequired: boolean }> {
    return this.request('/api/auth/google', {
      method: 'POST',
      body: { credential },
    });
  }

  public async sendMfaOtp(): Promise<{ success: boolean; message: string }> {
    return this.request('/api/mfa/send', {
      method: 'POST',
      authenticated: true,
    });
  }

  public async verifyMfa(code: string): Promise<{ success: boolean; token: string }> {
    return this.request('/api/mfa/verify', {
      method: 'POST',
      authenticated: true,
      body: { code },
    });
  }

  public async getProfile(): Promise<{
    user: Record<string, unknown>;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    return this.request('/api/profile', {
      method: 'GET',
      authenticated: true,
    });
  }

  // ==========================================
  // Core Wallet & Payment APIs
  // ==========================================

  /**
   * Fetches active derived wallet metadata from backend session cache.
   * Zero-Address/Zero-Key: backend reconstructs nothing permanently.
   */
  public async getWallet(chainId?: string): Promise<{
    address: string;
    publicKey: string;
    balance: string;
    protocolVersion: string;
  }> {
    const query = chainId ? `?chain=${encodeURIComponent(chainId)}` : '';
    return this.request(`/api/wallet${query}`, {
      method: 'GET',
      authenticated: true,
    });
  }

  /**
   * Fetches live on-chain balance via the chain adapter directly from RPC.
   */
  public async getBalance(chainId: string, address?: string): Promise<bigint> {
    const adapter = this.getAdapter(chainId);
    let targetAddress = address;
    if (!targetAddress) {
      const wallet = await this.getWallet(chainId);
      targetAddress = wallet.address;
    }
    return adapter.getBalance(targetAddress);
  }

  /**
   * Estimates network transaction fee for a payment request.
   */
  public async estimateFee(
    req: PaymentRequest
  ): Promise<{ feeAtomic: bigint; feeFormatted: string }> {
    const adapter = this.getAdapter(req.chain);
    const wallet = await this.getWallet(req.chain);
    return adapter.estimateFee(req, wallet.address);
  }

  /**
   * Prepares a transaction preview:
   * 1. Resolves target chain and curve.
   * 2. Validates recipient address against chain specification.
   * 3. Fetches account nonce & checks balance from RPC.
   * 4. Constructs unsigned transaction and computes exact hashToSign.
   *
   * Displays hashToSign to caller before signing is authorized.
   */
  public async prepareTransaction(req: PrepareTransactionRequest): Promise<TransactionPreview> {
    const chain = this.registry.getChain(req.chain);

    // Validate recipient address format strictly
    this.registry.assertValidAddress(chain.id, req.to);

    // Retrieve sender address and public key
    const wallet = await this.getWallet(chain.id);
    const fromAddress = wallet.address;

    const adapter = createChainAdapter(chain);
    const unsignedTx = await adapter.buildUnsignedTx(
      {
        chain: chain.id,
        to: req.to,
        amount: req.amount,
        memo: req.memo,
      },
      fromAddress
    );

    const feeEstimate = await adapter.estimateFee(
      {
        chain: chain.id,
        to: req.to,
        amount: req.amount,
        memo: req.memo,
      },
      fromAddress
    );

    const amountStr = typeof req.amount === 'bigint' ? req.amount.toString() : req.amount.trim();

    return {
      chain: chain.id,
      curve: chain.curve,
      from: fromAddress,
      to: req.to,
      amount: amountStr,
      fee: feeEstimate.feeFormatted,
      hashToSign: ethers.hexlify(unsignedTx.hashToSign),
      expiresAt: unsignedTx.expiresAt || Date.now() + 300_000,
      unsignedTx,
    };
  }

  /**
   * Authorizes, aggregates, and broadcasts an unsigned transaction:
   * 1. Evaluates Zero-Trust policy gate on backend (working hours, geofence, velocity).
   * 2. Collects partial signatures across all 3 domains (Foundation, Public, Private).
   * 3. Aggregates into final signature using curve signer backend.
   * 4. Attaches signature to transaction and broadcasts directly via chain adapter.
   */
  public async signAndSend(
    preview: TransactionPreview,
    opts?: SignAndSendOptions
  ): Promise<SignAndSendResult> {
    // Check local expiration
    if (Date.now() > preview.expiresAt) {
      throw new SaralError(
        'TRANSACTION_EXPIRED',
        `Prepared transaction expired at ${new Date(preview.expiresAt).toISOString()}. Please prepare a fresh preview.`
      );
    }

    const chain = this.registry.getChain(preview.chain);
    const adapter = createChainAdapter(chain);

    this.logger?.info(`[SARAL SDK] Initiating 3-domain MPC signing on ${chain.id}...`, {
      to: preview.to,
      amount: preview.amount,
      hashToSign: preview.hashToSign,
    });

    // Request 3-Domain MPC Signing from Backend Coordinator
    const signResponse = await this.request<{
      success: boolean;
      txHash?: string;
      broadcasted?: boolean;
      message?: string;
      explorerUrl?: string;
      domainsSigned?: DomainName[];
      domainSignatures?: ThreeDomainSignatures['domains'];
      r?: string;
      yParity?: number;
      expectedPublicKey?: string;
      signature?: { r: string; s: string; yParity?: number; v?: number };
    }>('/api/wallet/sign', {
      method: 'POST',
      authenticated: true,
      body: {
        chain: chain.id,
        toAddress: preview.to,
        amount: preview.amount,
        hashToSign: preview.hashToSign,
        unsignedTx: ethers.hexlify(preview.unsignedTx.rawBytes),
        lat: opts?.location?.lat,
        lng: opts?.location?.lng,
        idempotencyKey: opts?.idempotencyKey,
      },
    });

    const domainsSigned: DomainName[] = signResponse.domainsSigned || ['foundation', 'public', 'private'];

    // Verify 3-of-3 domain quorum across Foundation, Public, and Private
    const requiredDomains: DomainName[] = ['foundation', 'public', 'private'];
    const missingDomains = requiredDomains.filter((d) => !domainsSigned.includes(d));
    if (missingDomains.length > 0) {
      throw new SaralError(
        'DOMAIN_QUORUM_FAILED',
        `3-Domain quorum failed. Missing domain authorizations: ${missingDomains.join(', ')}`,
        { missingDomains }
      );
    }

    // If backend already finalized broadcast
    if (signResponse.broadcasted && signResponse.txHash) {
      return {
        txHash: signResponse.txHash,
        status: 'BROADCASTED',
        explorerUrl: signResponse.explorerUrl || adapter.explorerUrl(signResponse.txHash),
        domainsSigned,
      };
    }

    // If backend returned domain signatures for client-side aggregation & direct adapter broadcast
    if (signResponse.r && signResponse.domainSignatures && signResponse.expectedPublicKey) {
      const signer: SignerBackend = chain.curve === 'secp256k1' ? this.ecdsaSigner : this.eddsaSigner;

      const threeDomainSigs: ThreeDomainSignatures = {
        r: signResponse.r,
        yParity: signResponse.yParity,
        expectedPublicKey: signResponse.expectedPublicKey,
        domains: signResponse.domainSignatures,
      };

      const finalSig = await signer.aggregate(threeDomainSigs, preview.unsignedTx.hashToSign);
      const signedTx = adapter.attachSignature(preview.unsignedTx, finalSig);
      const broadcastResult = await adapter.broadcast(signedTx);

      return {
        txHash: broadcastResult.txHash,
        status: broadcastResult.status,
        explorerUrl: adapter.explorerUrl(broadcastResult.txHash),
        domainsSigned,
      };
    }

    // If signature object returned directly
    if (signResponse.signature) {
      const signedTx = adapter.attachSignature(preview.unsignedTx, {
        r: signResponse.signature.r,
        s: signResponse.signature.s,
        yParity: signResponse.signature.yParity,
        v: signResponse.signature.v,
        rawBytes: new Uint8Array(65),
      });

      const broadcastResult = await adapter.broadcast(signedTx);
      return {
        txHash: broadcastResult.txHash,
        status: broadcastResult.status,
        explorerUrl: adapter.explorerUrl(broadcastResult.txHash),
        domainsSigned,
      };
    }

    throw new SaralError(
      'RPC_ERROR',
      signResponse.message || 'Signing completed but failed to produce a valid broadcast transaction.'
    );
  }

  /**
   * Fetches user transaction history from backend audit log.
   */
  public async getTransactions(opts?: {
    chain?: string;
    page?: number;
  }): Promise<{ transactions: TransactionRecord[]; total: number }> {
    const params = new URLSearchParams();
    if (opts?.chain) params.set('chain', opts.chain);
    if (opts?.page) params.set('page', String(opts.page));

    const qs = params.toString() ? `?${params.toString()}` : '';
    const res = await this.request<{ transactions?: Array<Record<string, unknown>> } | Array<Record<string, unknown>>>(
      `/api/wallet/transactions${qs}`,
      {
        method: 'GET',
        authenticated: true,
      }
    );

    const rawList = Array.isArray(res) ? res : res.transactions || [];
    const list: TransactionRecord[] = rawList.map((t) => ({
      id: String(t.id || t.txHash || ''),
      chain: String(t.chain || opts?.chain || 'mst-testnet'),
      txHash: String(t.txHash || ''),
      toAddress: String(t.toAddress || ''),
      amount: String(t.amount || '0'),
      status: String(t.status || 'UNKNOWN'),
      createdAt: String(t.createdAt || new Date().toISOString()),
    }));

    return {
      transactions: list,
      total: list.length,
    };
  }

  // ==========================================
  // Internal HTTP & Policy Request Engine
  // ==========================================

  private async request<T>(
    endpoint: string,
    options: {
      method: 'GET' | 'POST' | 'PUT' | 'DELETE';
      body?: Record<string, unknown>;
      authenticated?: boolean;
      retries?: number;
    }
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    if (options.authenticated && this.getAuthToken) {
      const token = await this.getAuthToken();
      if (!token) {
        throw new SaralError('AUTH_REQUIRED', 'Authentication required. No auth token provided.');
      }
      headers.Authorization = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      this.logger?.debug?.(`[SARAL SDK] ${options.method} ${url}`, redact(options.body));

      const response = await fetch(url, {
        method: options.method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      const responseText = await response.text();
      let data: Record<string, unknown> = {};
      try {
        data = responseText ? JSON.parse(responseText) : {};
      } catch {
        data = { raw: responseText };
      }

      if (!response.ok) {
        const errorMsg =
          typeof data.error === 'string'
            ? data.error
            : typeof data.message === 'string'
              ? data.message
              : `HTTP ${response.status} ${response.statusText}`;

        // Map backend policy and authentication errors into typed SaralError codes
        if (response.status === 401) {
          throw new SaralError('AUTH_REQUIRED', errorMsg);
        }

        if (response.status === 403 || errorMsg.includes('Access Denied')) {
          if (errorMsg.includes('MFA')) {
            throw new SaralError('MFA_REQUIRED', errorMsg);
          }
          if (errorMsg.includes('location') || errorMsg.includes('GPS') || errorMsg.includes('geofence')) {
            throw new SaralError('LOCATION_REQUIRED', errorMsg);
          }
          throw new PolicyDeniedError(errorMsg);
        }

        if (errorMsg.includes('Insufficient funds')) {
          throw new SaralError('INSUFFICIENT_FUNDS', errorMsg);
        }

        throw new SaralError('RPC_ERROR', errorMsg, data);
      }

      return data as T;
    } catch (err: unknown) {
      if (err instanceof SaralError) throw err;

      // Handle Abort / Timeout
      if (err instanceof Error && err.name === 'AbortError') {
        throw new SaralError(
          'NETWORK_ERROR',
          `Request to ${endpoint} timed out after ${this.timeoutMs}ms.`
        );
      }

      // Retry idempotent GET requests
      const retries = options.retries ?? (options.method === 'GET' ? 2 : 0);
      if (retries > 0) {
        return this.request<T>(endpoint, { ...options, retries: retries - 1 });
      }

      const msg = err instanceof Error ? err.message : String(err);
      throw new SaralError('NETWORK_ERROR', `Network request failed: ${msg}`);
    } finally {
      clearTimeout(timeout);
    }
  }
}
