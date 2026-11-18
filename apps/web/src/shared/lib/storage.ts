const TOKEN_KEY = 'saral_session_token';
const MFA_SENT_KEY_PREFIX = 'saral_mfa_sent_';

/**
 * Pure 32-bit FNV-1a non-reversible cryptographic-style string hash.
 * Never stores or leaks any portion or slice of the raw token.
 */
export function hashTokenToFingerprint(token: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < token.length; i++) {
    hash ^= token.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

export const SESSION_STORE = {
  getToken(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },

  setToken(token: string): void {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {}
  },

  clearToken(): void {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {}
  },

  getMfaCodeSentAt(token: string): number | null {
    if (!token) return null;
    try {
      const fp = hashTokenToFingerprint(token);
      const val = sessionStorage.getItem(`${MFA_SENT_KEY_PREFIX}${fp}`);
      return val ? parseInt(val, 10) : null;
    } catch {
      return null;
    }
  },

  setMfaCodeSent(token: string): void {
    if (!token) return;
    try {
      const fp = hashTokenToFingerprint(token);
      sessionStorage.setItem(`${MFA_SENT_KEY_PREFIX}${fp}`, String(Date.now()));
    } catch {}
  },

  canSendMfa(token: string, cooldownSec = 30): boolean {
    const sentAt = this.getMfaCodeSentAt(token);
    if (!sentAt) return true;
    const elapsedSec = (Date.now() - sentAt) / 1000;
    return elapsedSec >= cooldownSec;
  },

  getRemainingMfaCooldown(token: string, cooldownSec = 30): number {
    const sentAt = this.getMfaCodeSentAt(token);
    if (!sentAt) return 0;
    const elapsedSec = Math.floor((Date.now() - sentAt) / 1000);
    return Math.max(0, cooldownSec - elapsedSec);
  },

  /**
   * Cleans all stored MFA marker timestamps across sessionStorage.
   * Called immediately after MFA verification succeeds.
   */
  clearMfaMarkers(): void {
    try {
      const keysToRemove: string[] = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && key.startsWith(MFA_SENT_KEY_PREFIX)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach((k) => sessionStorage.removeItem(k));
    } catch {}
  },

  /**
   * Removes legacy insecure localStorage session keys.
   */
  cleanLegacyStorage(): void {
    try {
      localStorage.removeItem('saral_token');
      localStorage.removeItem('saral_user');
      localStorage.removeItem('saral_theme'); // Old key; 'saral-theme' is used for modern theme
    } catch {}
  },
};
