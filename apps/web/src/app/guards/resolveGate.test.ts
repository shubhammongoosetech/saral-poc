import { describe, it, expect } from 'vitest';
import { resolveGate, isRouteAllowed } from './resolveGate';

describe('resolveGate', () => {
  it('redirects anonymous status to /login', () => {
    expect(resolveGate('anonymous')).toBe('/login');
  });

  it('redirects needs-mfa status to /mfa', () => {
    expect(resolveGate('needs-mfa')).toBe('/mfa');
  });

  it('redirects needs-policy status to /working-policy', () => {
    expect(resolveGate('needs-policy')).toBe('/working-policy');
  });

  it('redirects ready status to /wallet', () => {
    expect(resolveGate('ready')).toBe('/wallet');
  });

  it('defaults loading status to /login', () => {
    expect(resolveGate('loading')).toBe('/login');
  });
});

describe('isRouteAllowed', () => {
  it('allows only /login for anonymous users', () => {
    expect(isRouteAllowed('anonymous', '/login')).toBe(true);
    expect(isRouteAllowed('anonymous', '/mfa')).toBe(false);
    expect(isRouteAllowed('anonymous', '/wallet')).toBe(false);
    expect(isRouteAllowed('anonymous', '/settings')).toBe(false);
  });

  it('allows only /mfa for needs-mfa users', () => {
    expect(isRouteAllowed('needs-mfa', '/mfa')).toBe(true);
    expect(isRouteAllowed('needs-mfa', '/login')).toBe(false);
    expect(isRouteAllowed('needs-mfa', '/wallet')).toBe(false);
    expect(isRouteAllowed('needs-mfa', '/working-policy')).toBe(false);
  });

  it('allows only /working-policy for needs-policy users', () => {
    expect(isRouteAllowed('needs-policy', '/working-policy')).toBe(true);
    expect(isRouteAllowed('needs-policy', '/wallet')).toBe(false);
    expect(isRouteAllowed('needs-policy', '/activity')).toBe(false);
    expect(isRouteAllowed('needs-policy', '/login')).toBe(false);
  });

  it('allows wallet, activity, settings, review, and working-policy for ready users', () => {
    expect(isRouteAllowed('ready', '/wallet')).toBe(true);
    expect(isRouteAllowed('ready', '/activity')).toBe(true);
    expect(isRouteAllowed('ready', '/settings')).toBe(true);
    expect(isRouteAllowed('ready', '/review')).toBe(true);
    expect(isRouteAllowed('ready', '/working-policy')).toBe(true);
    expect(isRouteAllowed('ready', '/login')).toBe(false);
    expect(isRouteAllowed('ready', '/mfa')).toBe(false);
  });

  it('denies all routes while loading', () => {
    expect(isRouteAllowed('loading', '/wallet')).toBe(false);
    expect(isRouteAllowed('loading', '/login')).toBe(false);
    expect(isRouteAllowed('loading', '/mfa')).toBe(false);
  });
});
