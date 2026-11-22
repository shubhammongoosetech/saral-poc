import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export interface TokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  mfaVerified: boolean;
  domainRole?: string;
  nonce?: string;
  userId?: string;
  walletId?: string;
  keyId?: string;
  dkgSessionId?: string;
  committeeId?: string;
  chainFamily?: string;
  curve?: string;
  epoch?: number;
  operation?: string;
  [key: string]: unknown;
}

export interface JwkKey {
  kty: string;
  crv: string;
  kid: string;
  alg: string;
  use: string;
  x: string;
}

export interface JwksResponse {
  keys: JwkKey[];
}

function base64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

export function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>, privateKey: crypto.KeyObject): string {
  const h64 = base64url(JSON.stringify(header));
  const p64 = base64url(JSON.stringify(payload));
  const data = Buffer.from(`${h64}.${p64}`);
  const sig = crypto.sign(null, data, privateKey);
  const s64 = sig.toString('base64url');
  return `${h64}.${p64}.${s64}`;
}

export function verifyJwt<T = TokenClaims>(token: string, publicKey: crypto.KeyObject): T {
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 dot-separated segments');
  }
  const [h64, p64, s64] = parts;
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;

  try {
    header = JSON.parse(Buffer.from(h64, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(p64, 'base64url').toString('utf8'));
  } catch (err: any) {
    throw new Error(`Malformed JWT JSON: ${err.message}`);
  }

  // Strict EdDSA algorithm check
  if (header.alg !== 'EdDSA') {
    throw new Error(`Invalid token algorithm ${header.alg}: only EdDSA is permitted`);
  }

  const data = Buffer.from(`${h64}.${p64}`);
  const sig = Buffer.from(s64, 'base64url');
  const valid = crypto.verify(null, data, publicKey, sig);
  if (!valid) {
    throw new Error('Invalid token signature');
  }

  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(payload.exp) || (payload.exp as number) <= now) {
    throw new Error('Token expired');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now + 10) {
    throw new Error('Token not yet valid');
  }

  return payload as T;
}

export class KeyManager {
  private static instance: KeyManager;
  public privateKey!: crypto.KeyObject;
  public publicKey!: crypto.KeyObject;
  public privateKeyPem: string = '';
  public publicKeyPem: string = '';
  public activeKid: string;
  public issuer: string;
  public audience: string;
  private readonly accountAudience = 'saral-wallet-account';

  private constructor() {
    this.activeKid = process.env.SARAL_JWT_ACTIVE_KID || 'saral-auth-ed25519-2026-01';
    this.issuer = process.env.SARAL_JWT_ISSUER || 'saral-auth-server';
    this.audience = process.env.SARAL_JWT_AUDIENCE || 'saral-domain-coordinators';

    const rawKeyDir = process.env.KEY_DIR || '';
    const candidates = [
      rawKeyDir,
      rawKeyDir ? path.resolve(process.cwd(), rawKeyDir) : '',
      rawKeyDir ? path.resolve(__dirname, '../../..', rawKeyDir) : '',
      path.resolve(__dirname, '../../../infra/config'),
      path.resolve(process.cwd(), 'infra/config'),
      path.resolve(process.cwd(), '../../infra/config'),
    ].filter(Boolean);

    let keyDir = '';
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        const privPath = path.join(c, 'auth_ed25519_private_key.pem');
        const pubPath = path.join(c, 'auth_ed25519_public_key.pem');
        if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
          keyDir = c;
          break;
        }
      }
    }
    if (rawKeyDir && !keyDir) throw new Error('Configured authentication signing key pair is missing');

    let loaded = false;

    if (keyDir && fs.existsSync(keyDir)) {
      const privPath = path.join(keyDir, 'auth_ed25519_private_key.pem');
      const pubPath = path.join(keyDir, 'auth_ed25519_public_key.pem');

      if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
        try {
          const privContent = fs.readFileSync(privPath, 'utf8');
          const pubContent = fs.readFileSync(pubPath, 'utf8');
          const privKey = crypto.createPrivateKey(privContent);
          const pubKey = crypto.createPublicKey(pubContent);

          if (privKey.asymmetricKeyType === 'ed25519' && crypto.createPublicKey(privKey).equals(pubKey)) {
            this.privateKey = privKey;
            this.publicKey = pubKey;
            this.privateKeyPem = privContent;
            this.publicKeyPem = pubContent;
            loaded = true;
          }
        } catch (_) {}
        if (!loaded) throw new Error('Configured authentication signing keys are invalid');
      }
    }

    if (!loaded) {
      // Generate genuine Ed25519 keypair
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      this.privateKey = privateKey;
      this.publicKey = publicKey;

      this.privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
      this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

    }
  }

  public static getInstance(): KeyManager {
    if (!KeyManager.instance) {
      KeyManager.instance = new KeyManager();
    }
    return KeyManager.instance;
  }

  public getJwks(): JwksResponse {
    const jwk = this.publicKey.export({ format: 'jwk' }) as any;
    return {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          kid: this.activeKid,
          alg: 'EdDSA',
          use: 'sig',
          x: jwk.x,
        },
      ],
    };
  }

  public issueToken(subject: string = 'dev-operator-1', role: string = 'admin', mfaVerified: boolean = true): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: TokenClaims = {
      sub: subject,
      iss: this.issuer,
      aud: this.audience,
      iat: now,
      exp: now + 3600, // 1 hour expiry
      mfaVerified,
      domainRole: role,
      nonce: crypto.randomBytes(16).toString('hex'),
    };

    const header = {
      alg: 'EdDSA',
      typ: 'JWT',
      kid: this.activeKid,
    };

    return signJwt(header, payload as Record<string, unknown>, this.privateKey);
  }

  public issueScopedToken(claims: Partial<TokenClaims> & { sub: string }): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: TokenClaims = {
      iss: this.issuer,
      aud: this.audience,
      iat: now,
      exp: now + 3600,
      mfaVerified: true,
      domainRole: 'operator',
      nonce: crypto.randomBytes(16).toString('hex'),
      ...claims,
    };

    const header = {
      alg: 'EdDSA',
      typ: 'JWT',
      kid: this.activeKid,
    };

    return signJwt(header, payload as Record<string, unknown>, this.privateKey);
  }

  public verifyToken(token: string): TokenClaims {
    return verifyJwt<TokenClaims>(token, this.publicKey);
  }

  public issueAccountToken(userId: string, mfaVerified: boolean): string {
    const durationSeconds = mfaVerified ? 3600 : 300;
    return this.issueScopedToken({
      sub: userId,
      aud: this.accountAudience,
      exp: Math.floor(Date.now() / 1000) + durationSeconds,
      mfaVerified,
    });
  }

  public verifyAccountToken(token: string): TokenClaims {
    const claims = this.verifyToken(token);
    if (claims.iss !== this.issuer || claims.aud !== this.accountAudience ||
        claims.domainRole !== 'operator' || typeof claims.sub !== 'string' || !claims.sub ||
        typeof claims.mfaVerified !== 'boolean' || typeof claims.nonce !== 'string') {
      throw new Error('Invalid account session');
    }
    return claims;
  }

}
