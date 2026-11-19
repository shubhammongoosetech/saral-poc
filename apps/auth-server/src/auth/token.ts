import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';

export interface TokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  mfaVerified: boolean;
  domainRole?: string;
  nonce?: string;
}

export class KeyManager {
  private static instance: KeyManager;
  public privateKeyPem: string = '';
  public publicKeyPem: string = '';

  private constructor() {
    const keyDir = process.env.KEY_DIR || '';
    let loaded = false;

    if (keyDir && fs.existsSync(keyDir)) {
      const privPath = path.join(keyDir, 'auth_private_key.pem');
      const pubPath = path.join(keyDir, 'auth_public_key.pem');
      if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
        this.privateKeyPem = fs.readFileSync(privPath, 'utf8');
        this.publicKeyPem = fs.readFileSync(pubPath, 'utf8');
        loaded = true;
      }
    }

    if (!loaded) {
      // Generate fresh RSA-2048 keypair cryptographically
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });

      this.privateKeyPem = privateKey;
      this.publicKeyPem = publicKey;

      if (keyDir && fs.existsSync(keyDir)) {
        try {
          fs.writeFileSync(path.join(keyDir, 'auth_private_key.pem'), this.privateKeyPem, { mode: 0o600 });
          fs.writeFileSync(path.join(keyDir, 'auth_public_key.pem'), this.publicKeyPem, { mode: 0o644 });
        } catch {
          // Ignore if directory read-only
        }
      }
    }
  }

  public static getInstance(): KeyManager {
    if (!KeyManager.instance) {
      KeyManager.instance = new KeyManager();
    }
    return KeyManager.instance;
  }

  public issueToken(subject: string = 'dev-operator-1', role: string = 'admin', mfaVerified: boolean = true): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: TokenClaims = {
      sub: subject,
      iss: 'saral-auth-server',
      aud: 'saral-domain-coordinators',
      iat: now,
      exp: now + 3600, // 1 hour expiry
      mfaVerified,
      domainRole: role,
      nonce: crypto.randomBytes(16).toString('hex'),
    };

    return jwt.sign(payload, this.privateKeyPem, {
      algorithm: 'RS256',
    });
  }

  public verifyToken(token: string): TokenClaims {
    return jwt.verify(token, this.publicKeyPem, {
      algorithms: ['RS256'],
    }) as TokenClaims;
  }
}
