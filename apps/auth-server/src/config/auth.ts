import fs from 'fs';
import crypto from 'crypto';

let dynamicAdminSecret: string | null = null;

const INSECURE_DEFAULT_SECRETS = new Set([
  'saral-mesh-admin-secret-2026',
  'saral-internal-secure-token-2026-v3',
  'saral-mesh-secure-internal-token-v3',
  'admin',
  'secret',
  'password',
  'default',
]);

export function isKnownInsecureSecret(s: string): boolean {
  return INSECURE_DEFAULT_SECRETS.has(s.trim().toLowerCase());
}

export function isLocalAuthEnabled(): boolean {
  const mode = process.env.NODE_ENV ?? 'development';
  return (mode === 'development' || mode === 'local' || mode === 'test') &&
    process.env.ENABLE_DEV_AUTH === 'true';
}

export function canDisplayDevOtp(): boolean {
  return process.env.NODE_ENV === 'test' || isLocalAuthEnabled();
}

export function matchesSecret(provided: unknown, expected: string | null): boolean {
  if (typeof provided !== 'string' || !expected) return false;
  const hash = (value: string) => crypto.createHash('sha256').update(value).digest();
  return crypto.timingSafeEqual(hash(provided), hash(expected));
}

export function getAdminSecret(): string | null {
  if (dynamicAdminSecret) {
    return dynamicAdminSecret;
  }

  // 1. Docker secret file
  const secretPath = process.env.SARAL_ADMIN_KEY_FILE || '/run/secrets/saral_admin_key';
  try {
    if (fs.existsSync(secretPath)) {
      const content = fs.readFileSync(secretPath, 'utf8').trim();
      if (content && !isKnownInsecureSecret(content)) {
        dynamicAdminSecret = content;
        return content;
      }
    }
  } catch (_) {}

  // 2. Env variable
  const envKey = process.env.SARAL_ADMIN_KEY || process.env.ADMIN_SECRET;
  if (envKey) {
    const trimmed = envKey.trim();
    if (trimmed && !isKnownInsecureSecret(trimmed)) {
      dynamicAdminSecret = trimmed;
      return trimmed;
    }
  }

  return null;
}

export function setDynamicAdminSecret(secret: string): void {
  dynamicAdminSecret = secret;
}
