export interface DecodedClaims {
  userId?: string;
  email?: string;
  mobile?: string;
  mfaVerified: boolean;
  exp: number;
}

/**
 * Decodes the JWT payload on the client without cryptographic signature verification.
 * Used strictly for UI gating and timer scheduling.
 */
export function decodeJwtClaims(token: string | null | undefined): DecodedClaims | null {
  if (!token || typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    const parsed = JSON.parse(jsonPayload);

    if (typeof parsed !== 'object' || parsed === null) return null;

    const exp = typeof parsed.exp === 'number' ? parsed.exp : 0;
    const mfaVerified = Boolean(parsed.mfaVerified);
    const userId = parsed.id || parsed.userId || parsed.sub || undefined;

    return {
      userId,
      email: parsed.email,
      mobile: parsed.mobile,
      mfaVerified,
      exp,
    };
  } catch {
    return null;
  }
}

/**
 * Checks if the JWT is expired based on its `exp` claim (in seconds).
 */
export function isTokenExpired(exp: number): boolean {
  if (!exp) return true;
  const nowInSec = Math.floor(Date.now() / 1000);
  return exp <= nowInSec;
}
