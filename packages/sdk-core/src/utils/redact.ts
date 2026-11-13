const SENSITIVE_KEYS = new Set([
  'authorization',
  'token',
  'refreshtoken',
  'jwt',
  'secret',
  'privatekey',
  'keyshare',
  'seed',
  'password',
  'otp',
]);

/**
 * Redacts sensitive fields (auth tokens, secrets, private keys) from objects and logs.
 */
export function redact<T>(data: T): T {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') {
    // Redact Bearer tokens
    if (data.toLowerCase().startsWith('bearer ')) {
      return 'Bearer [REDACTED]' as unknown as T;
    }
    // Redact 64-char hex strings if suspected secret
    return data;
  }
  if (Array.isArray(data)) {
    return data.map((item) => redact(item)) as unknown as T;
  }
  if (typeof data === 'object') {
    const copy: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        copy[key] = '[REDACTED]';
      } else {
        copy[key] = redact(value);
      }
    }
    return copy as T;
  }
  return data;
}

