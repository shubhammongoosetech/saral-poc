import { describe, it, expect, beforeEach } from 'vitest';
import { SESSION_STORE } from './storage';

describe('SESSION_STORE', () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
  });

  it('sets and retrieves session token from sessionStorage', () => {
    expect(SESSION_STORE.getToken()).toBeNull();
    SESSION_STORE.setToken('mock_jwt_token_123');
    expect(SESSION_STORE.getToken()).toBe('mock_jwt_token_123');
    expect(sessionStorage.getItem('saral_session_token')).toBe('mock_jwt_token_123');
  });

  it('clears session token', () => {
    SESSION_STORE.setToken('mock_jwt_token_123');
    SESSION_STORE.clearToken();
    expect(SESSION_STORE.getToken()).toBeNull();
  });

  it('cleans legacy localStorage keys on boot', () => {
    localStorage.setItem('saral_token', 'legacy_token');
    localStorage.setItem('saral_user', JSON.stringify({ email: 'leak@example.com' }));
    localStorage.setItem('saral_theme', 'dark');
    localStorage.setItem('saral-theme', 'light'); // Modern key to preserve

    SESSION_STORE.cleanLegacyStorage();

    expect(localStorage.getItem('saral_token')).toBeNull();
    expect(localStorage.getItem('saral_user')).toBeNull();
    expect(localStorage.getItem('saral_theme')).toBeNull();
    expect(localStorage.getItem('saral-theme')).toBe('light');
  });
});
