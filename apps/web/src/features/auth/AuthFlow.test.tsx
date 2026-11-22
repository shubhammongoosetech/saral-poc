import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PublicOnly } from '@/app/guards/PublicOnly';
import { RequireAuth } from '@/app/guards/RequireAuth';
import { RequireMfa } from '@/app/guards/RequireMfa';
import { RequirePolicy } from '@/app/guards/RequirePolicy';
import { SESSION_STORE } from '@/shared/lib/storage';
import { LoginForm } from './LoginForm';
import { Mfa } from './Mfa';
import { SessionProvider } from './useSession';

const user = { id: 'user-1', login_method: 'google', created_at: '' };

function token(mfaVerified: boolean) {
  const exp = Math.floor(Date.now() / 1_000) + 600;
  return `header.${btoa(JSON.stringify({ sub: user.id, mfaVerified, exp }))}.signature`;
}

function renderSession(path: string) {
  const queryClient = new QueryClient();
  const router = createMemoryRouter([{
    element: <SessionProvider><Outlet /></SessionProvider>,
    children: [
      { element: <PublicOnly />, children: [{ path: '/login', element: <LoginForm /> }] },
      { element: <RequireMfa />, children: [{ path: '/mfa', element: <Mfa /> }] },
      { element: <RequirePolicy />, children: [{ path: '/working-policy', element: <h1>Set working policy</h1> }] },
      { element: <RequireAuth />, children: [{ path: '/wallet', element: <h1>Wallet overview</h1> }] },
    ],
  }], { initialEntries: [path] });

  render(<QueryClientProvider client={queryClient}><RouterProvider router={router} /></QueryClientProvider>);
}

function mockApi(respond: (path: string, request?: RequestInit) => Response) {
  const request = vi.fn(async (path: string, init?: RequestInit) => respond(path, init));
  vi.stubGlobal('fetch', request);
  return request;
}

async function enterAuthenticatorCode(code: string) {
  const input = screen.getByRole<HTMLInputElement>('textbox', { name: 'Digit 1' });
  await waitFor(() => expect(input.disabled).toBe(false));
  fireEvent.paste(input, { clipboardData: { getData: () => code } });
}

afterEach(() => {
  cleanup();
  SESSION_STORE.clearToken();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('auth flow', () => {
  it.each([
    { developmentBuild: true, developmentOtpEnabled: false },
    { developmentBuild: false, developmentOtpEnabled: true },
  ])('uses the configured Google ID and only offers OTP with both development settings enabled', async ({ developmentBuild, developmentOtpEnabled }) => {
    vi.stubEnv('DEV', developmentBuild);
    const initialize = vi.fn();
    vi.stubGlobal('google', { accounts: { id: { initialize, renderButton: vi.fn() } } });
    mockApi((path) => {
      expect(path).toBe('/api/auth/login-options');
      return Response.json({ googleClientId: 'configured-client.apps.googleusercontent.com', developmentOtpEnabled });
    });

    renderSession('/login');

    await waitFor(() => expect(initialize).toHaveBeenCalledWith(expect.objectContaining({
      client_id: 'configured-client.apps.googleusercontent.com',
    })));
    expect(screen.queryByLabelText('Mobile number')).toBeNull();
  });

  it('shows a development phone code after explicit opt-in and waits for the user to enter it', async () => {
    vi.stubEnv('DEV', true);
    const api = mockApi((path) => {
      if (path === '/api/auth/login-options') {
        return Response.json({ googleClientId: null, developmentOtpEnabled: true });
      }
      expect(path).toBe('/api/auth/otp/request');
      return Response.json({ success: true, devOtp: '123456' });
    });

    renderSession('/login');
    fireEvent.change(await screen.findByLabelText('Mobile number'), { target: { value: '9876543210' } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    await screen.findByText('123456');
    expect(screen.getByRole<HTMLInputElement>('textbox', { name: 'Digit 1' }).value).toBe('');
    expect(api).toHaveBeenCalledTimes(2);
  });

  it.each([
    { hasPolicy: false, destination: 'Set working policy' },
    { hasPolicy: true, destination: 'Wallet overview' },
  ])('keeps the first-factor session after a typo and then opens $destination', async ({ hasPolicy, destination }) => {
    const primary = token(false);
    const verified = token(true);
    SESSION_STORE.setToken(primary);
    const api = mockApi((path, request) => {
      if (path === '/api/mfa/status') return Response.json({ success: true, enrolled: true });
      if (path === '/api/mfa/verify') {
        const { otp } = JSON.parse(request!.body as string);
        if (otp === '123456') {
          return Response.json({ code: 'MFA_CODE_INVALID', error: 'Invalid authenticator code' }, { status: 400 });
        }
        return Response.json({ success: true, token: verified, hasPolicy });
      }
      if (path === '/api/profile') return Response.json({ user, hasPolicy });
      throw new Error(`Unexpected request ${path}`);
    });

    renderSession('/mfa');
    await enterAuthenticatorCode('123456');
    await screen.findByText('Invalid authenticator code');
    expect(SESSION_STORE.getToken()).toBe(primary);
    await enterAuthenticatorCode('654321');
    await screen.findByRole('heading', { name: destination });
    expect(SESSION_STORE.getToken()).toBe(verified);
    expect(api.mock.calls.some(([path]) => path === '/api/auth/logout')).toBe(false);
  });

  it('restores a returning wallet session after a temporary profile error', async () => {
    const verified = token(true);
    SESSION_STORE.setToken(verified);
    let attempt = 0;
    mockApi((path) => {
      expect(path).toBe('/api/profile');
      return ++attempt === 1
        ? Response.json({ error: 'Temporarily unavailable' }, { status: 503 })
        : Response.json({ user, hasPolicy: true });
    });

    renderSession('/wallet');
    await screen.findByText('Unable to restore your session. Try again.');
    expect(SESSION_STORE.getToken()).toBe(verified);
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await screen.findByRole('heading', { name: 'Wallet overview' });
    expect(SESSION_STORE.getToken()).toBe(verified);
  });
});
