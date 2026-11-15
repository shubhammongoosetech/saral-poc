import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { RequireAuth } from './RequireAuth';
import { RequireMfa } from './RequireMfa';
import { RequirePolicy } from './RequirePolicy';
import { PublicOnly } from './PublicOnly';
import { resolveGate, SessionStatus } from './resolveGate';
import * as useSessionModule from '@/features/auth/useSession';

// Helper component that outputs current location for assertions
function LocationTracker() {
  const location = useLocation();
  return <div data-testid="current-location">{location.pathname}</div>;
}

function RootRedirect() {
  const { status } = useSessionModule.useSession();
  if (status === 'loading') {
    return <div data-testid="loading-state">Loading</div>;
  }
  return <Navigate to={resolveGate(status)} replace />;
}

function renderTestRouter(initialPath: string) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <LocationTracker />
      <Routes>
        <Route path="/" element={<RootRedirect />} />

        {/* PublicOnly: /login */}
        <Route element={<PublicOnly />}>
          <Route path="/login" element={<div data-testid="login-content">Login</div>} />
        </Route>

        {/* RequireMfa: /mfa */}
        <Route element={<RequireMfa />}>
          <Route path="/mfa" element={<div data-testid="mfa-content">MFA</div>} />
        </Route>

        {/* RequirePolicy: /working-policy */}
        <Route element={<RequirePolicy />}>
          <Route path="/working-policy" element={<div data-testid="policy-content">Policy</div>} />
        </Route>

        {/* RequireAuth: /wallet, /activity, /settings, /review */}
        <Route element={<RequireAuth />}>
          <Route path="/wallet" element={<div data-testid="wallet-content">Wallet</div>} />
          <Route path="/activity" element={<div data-testid="activity-content">Activity</div>} />
          <Route path="/settings" element={<div data-testid="settings-content">Settings</div>} />
          <Route path="/review" element={<div data-testid="review-content">Review</div>} />
        </Route>

        {/* Catch-all route */}
        <Route path="*" element={<RootRedirect />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('32-Case Table-Driven Route Guards Matrix', () => {
  const statuses: SessionStatus[] = ['anonymous', 'needs-mfa', 'needs-policy', 'ready'];
  const testUrls = [
    '/login',
    '/mfa',
    '/working-policy',
    '/review',
    '/wallet',
    '/activity',
    '/settings',
    '/unknown-secret-route',
  ];

  // Matrix expected destinations mapping
  const expectedDestinations: Record<SessionStatus, Record<string, string>> = {
    anonymous: {
      '/login': '/login',
      '/mfa': '/login',
      '/working-policy': '/login',
      '/review': '/login',
      '/wallet': '/login',
      '/activity': '/login',
      '/settings': '/login',
      '/unknown-secret-route': '/login',
    },
    'needs-mfa': {
      '/login': '/mfa',
      '/mfa': '/mfa',
      '/working-policy': '/mfa',
      '/review': '/mfa',
      '/wallet': '/mfa',
      '/activity': '/mfa',
      '/settings': '/mfa',
      '/unknown-secret-route': '/mfa',
    },
    'needs-policy': {
      '/login': '/working-policy',
      '/mfa': '/working-policy',
      '/working-policy': '/working-policy',
      '/review': '/working-policy',
      '/wallet': '/working-policy',
      '/activity': '/working-policy',
      '/settings': '/working-policy',
      '/unknown-secret-route': '/working-policy',
    },
    ready: {
      '/login': '/wallet',
      '/mfa': '/wallet',
      '/working-policy': '/working-policy', // Allowed for editing policy
      '/review': '/review',
      '/wallet': '/wallet',
      '/activity': '/activity',
      '/settings': '/settings',
      '/unknown-secret-route': '/wallet',
    },
    loading: {
      '/wallet': '/wallet',
    },
  };

  statuses.forEach((status) => {
    testUrls.forEach((url) => {
      it(`status: [${status}] on URL: [${url}] -> redirects/stays at [${expectedDestinations[status][url]}]`, () => {
        vi.spyOn(useSessionModule, 'useSession').mockReturnValue({
          status,
          user: status === 'ready' ? { id: 'usr_1', login_method: 'mobile', created_at: '' } : null,
          token: status !== 'anonymous' ? 'mock-token' : null,
          lastAccessCheck: null,
          setLastAccessCheck: vi.fn(),
          setSessionToken: vi.fn(),
          handleMfaVerified: vi.fn(),
          markPolicyConfigured: vi.fn(),
          logout: vi.fn(),
          refreshProfile: vi.fn(),
        });

        const expected = expectedDestinations[status][url];
        const { unmount } = renderTestRouter(url);

        const locationEls = screen.getAllByTestId('current-location');
        const lastLocation = locationEls[locationEls.length - 1].textContent;

        expect(lastLocation).toBe(expected);
        unmount();
      });
    });
  });
});

describe('Loading & Redirection Invariant Checks', () => {
  it('never mounts protected children while status is loading', () => {
    vi.spyOn(useSessionModule, 'useSession').mockReturnValue({
      status: 'loading',
      user: null,
      token: null,
      lastAccessCheck: null,
      setLastAccessCheck: vi.fn(),
      setSessionToken: vi.fn(),
      handleMfaVerified: vi.fn(),
      markPolicyConfigured: vi.fn(),
      logout: vi.fn(),
      refreshProfile: vi.fn(),
    });

    renderTestRouter('/wallet');
    expect(screen.queryByTestId('wallet-content')).toBeNull();
    expect(screen.queryByTestId('activity-content')).toBeNull();
    expect(screen.queryByTestId('settings-content')).toBeNull();
    expect(screen.queryByTestId('login-content')).toBeNull();
  });

  it('never mounts protected children while redirecting anonymous to login', () => {
    vi.spyOn(useSessionModule, 'useSession').mockReturnValue({
      status: 'anonymous',
      user: null,
      token: null,
      lastAccessCheck: null,
      setLastAccessCheck: vi.fn(),
      setSessionToken: vi.fn(),
      handleMfaVerified: vi.fn(),
      markPolicyConfigured: vi.fn(),
      logout: vi.fn(),
      refreshProfile: vi.fn(),
    });

    renderTestRouter('/wallet');
    expect(screen.queryByTestId('wallet-content')).toBeNull();
    expect(screen.getByTestId('login-content')).toBeDefined();
  });
});
