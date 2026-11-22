import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { User } from '@/shared/api/types';
import { authApi, profileApi } from '@/shared/api/endpoints';
import { setAuthErrorHandler } from '@/shared/api/client';
import { SESSION_STORE } from '@/shared/lib/storage';
import { decodeJwtClaims, isTokenExpired } from '@/shared/lib/jwt';
import { SessionStatus } from '@/app/guards/resolveGate';
import { HttpError } from '@/services/httpClient';
import { Alert } from '@/shared/ui/Alert';
import { Button } from '@/shared/ui/Button';

interface SessionContextType {
  status: SessionStatus;
  user: User | null;
  token: string | null;
  lastAccessCheck: { allowed: boolean; reason?: string } | null;
  setLastAccessCheck: (res: { allowed: boolean; reason?: string } | null) => void;
  setSessionToken: (newToken: string, newUser?: User) => Promise<void>;
  handleMfaVerified: (newToken: string, hasPolicy: boolean, destination?: string) => Promise<void>;
  markPolicyConfigured: () => void;
  logout: (notice?: string) => void;
  refreshProfile: () => Promise<boolean>;
}

const SessionContext = createContext<SessionContextType | undefined>(undefined);

const IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes idle auto-lock
const BROADCAST_CHANNEL_NAME = 'saral_session_channel';
const CROSS_TAB_LOGOUT_KEY = 'saral_logout_event';

export const SessionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [status, setStatus] = useState<SessionStatus>('loading');
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [sessionUnavailable, setSessionUnavailable] = useState(false);

  const [lastAccessCheck, setLastAccessCheck] = useState<{ allowed: boolean; reason?: string } | null>(null);

  const expTimerRef = useRef<number | null>(null);
  const idleTimerRef = useRef<number | null>(null);
  const broadcastRef = useRef<BroadcastChannel | null>(null);

  const clearTimers = useCallback(() => {
    if (expTimerRef.current) {
      window.clearTimeout(expTimerRef.current);
      expTimerRef.current = null;
    }
    if (idleTimerRef.current) {
      window.clearTimeout(idleTimerRef.current);
      idleTimerRef.current = null;
    }
  }, []);

  const logout = useCallback(
    (_notice?: string) => {
      clearTimers();
      if (SESSION_STORE.getToken()) void authApi.logout();
      SESSION_STORE.clearToken();
      SESSION_STORE.clearMfaMarkers();
      queryClient.clear();
      setToken(null);
      setUser(null);
      setLastAccessCheck(null);
      setSessionUnavailable(false);
      setStatus('anonymous');

      // Cross-tab notification: carries only a pure logout signal, never any token
      try {
        broadcastRef.current?.postMessage({ type: 'LOGOUT' });
      } catch {}
      try {
        localStorage.setItem(CROSS_TAB_LOGOUT_KEY, String(Date.now()));
        localStorage.removeItem(CROSS_TAB_LOGOUT_KEY);
      } catch {}

      navigate('/login', { replace: true });
    },
    [clearTimers, navigate, queryClient]
  );

  const scheduleExpTimer = useCallback(
    (expSec: number) => {
      if (expTimerRef.current) {
        window.clearTimeout(expTimerRef.current);
      }
      const nowSec = Math.floor(Date.now() / 1000);
      const remainingMs = Math.min(2147483647, Math.max(0, (expSec - nowSec) * 1000));

      expTimerRef.current = window.setTimeout(() => {
        logout('Session expired');
      }, remainingMs);
    },
    [logout]
  );

  const resetIdleTimer = useCallback(() => {
    if (idleTimerRef.current) {
      window.clearTimeout(idleTimerRef.current);
    }
    if (status === 'anonymous' || status === 'loading') return;

    idleTimerRef.current = window.setTimeout(() => {
      logout('Session locked due to inactivity');
    }, IDLE_TIMEOUT_MS);
  }, [logout, status]);

  // Set up idle listeners
  useEffect(() => {
    if (status === 'anonymous' || status === 'loading') return;

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    const handleActivity = () => resetIdleTimer();

    events.forEach((evt) => window.addEventListener(evt, handleActivity, { passive: true }));
    resetIdleTimer();

    return () => {
      events.forEach((evt) => window.removeEventListener(evt, handleActivity));
      if (idleTimerRef.current) window.clearTimeout(idleTimerRef.current);
    };
  }, [resetIdleTimer, status]);

  // Set up cross-tab broadcast & storage events
  useEffect(() => {
    try {
      const channel = new BroadcastChannel(BROADCAST_CHANNEL_NAME);
      broadcastRef.current = channel;

      channel.onmessage = (msg) => {
        if (msg.data?.type === 'LOGOUT') {
          clearTimers();
          SESSION_STORE.clearToken();
          SESSION_STORE.clearMfaMarkers();
          queryClient.clear();
          setToken(null);
          setUser(null);
          setLastAccessCheck(null);
          setStatus('anonymous');
          navigate('/login', { replace: true });
        }
      };
    } catch {}

    const handleStorage = (e: StorageEvent) => {
      if (e.key === CROSS_TAB_LOGOUT_KEY) {
        clearTimers();
        SESSION_STORE.clearToken();
        SESSION_STORE.clearMfaMarkers();
        queryClient.clear();
        setToken(null);
        setUser(null);
        setLastAccessCheck(null);
        setStatus('anonymous');
        navigate('/login', { replace: true });
      }
    };
    window.addEventListener('storage', handleStorage);

    return () => {
      window.removeEventListener('storage', handleStorage);
      try {
        broadcastRef.current?.close();
      } catch {}
    };
  }, [clearTimers, navigate, queryClient]);

  // Wire Axios interceptor hooks
  useEffect(() => {
    setAuthErrorHandler({
      onUnauthorized: () => logout('Session expired'),
      onMfaRequired: () => {
        setStatus('needs-mfa');
        navigate('/mfa', { replace: true });
      },
    });
  }, [logout, navigate]);

  // Bootstrap session on app start
  const bootstrapSession = useCallback(async () => {
    setSessionUnavailable(false);
    SESSION_STORE.cleanLegacyStorage();
    const storedToken = SESSION_STORE.getToken();

    if (!storedToken) {
      setStatus('anonymous');
      return;
    }

    const claims = decodeJwtClaims(storedToken);
    if (!claims || isTokenExpired(claims.exp)) {
      SESSION_STORE.clearToken();
      setStatus('anonymous');
      return;
    }

    setToken(storedToken);
    scheduleExpTimer(claims.exp);

    // If MFA has NOT been verified in this session token
    if (!claims.mfaVerified) {
      setStatus('needs-mfa');
      return;
    }

    // Token has passed MFA: fetch profile once to check policy
    try {
      const profile = await profileApi.getProfile();
      if (storedToken !== SESSION_STORE.getToken()) return;
      setUser(profile.user);

      if (!profile.hasPolicy) {
        setStatus('needs-policy');
      } else {
        setStatus('ready');
      }
    } catch (err: unknown) {
      if (storedToken !== SESSION_STORE.getToken()) return;
      if (err instanceof HttpError && err.code === 'MFA_REQUIRED') return;
      if (err instanceof HttpError && err.status === 401) logout('Session expired');
      else setSessionUnavailable(true);
    }
  }, [logout, scheduleExpTimer]);

  useEffect(() => {
    bootstrapSession();
  }, [bootstrapSession]);

  // Called after step 1 login (Google or Mobile OTP)
  const setSessionToken = useCallback(
    async (newToken: string, newUser?: User) => {
      if (SESSION_STORE.getToken() !== newToken) queryClient.clear();
      SESSION_STORE.setToken(newToken);
      setToken(newToken);
      setUser(newUser || null);
      setLastAccessCheck(null);

      const claims = decodeJwtClaims(newToken);

      if (claims?.mfaVerified) {
        setStatus('loading');
        await bootstrapSession();
      } else {
        if (claims?.exp) scheduleExpTimer(claims.exp);
        setStatus('needs-mfa');
        navigate('/mfa', { replace: true });
      }
    },
    [bootstrapSession, navigate, queryClient, scheduleExpTimer]
  );

  // Called after step 2 MFA verification
  const handleMfaVerified = useCallback(
    async (newToken: string, hasPolicy: boolean, destination?: string) => {
      SESSION_STORE.setToken(newToken);
      // Clean up previous OTP request timestamps now that MFA is verified
      SESSION_STORE.clearMfaMarkers();
      setToken(newToken);
      setSessionUnavailable(false);

      const claims = decodeJwtClaims(newToken);
      if (claims?.exp) scheduleExpTimer(claims.exp);

      if (!hasPolicy) {
        setStatus('needs-policy');
        navigate('/working-policy', { replace: true });
        return;
      }

      setStatus('ready');
      navigate(destination || '/wallet', { replace: true });
      void profileApi.getProfile().then((profile) => {
        if (newToken === SESSION_STORE.getToken() && profile.user) setUser(profile.user);
      }).catch(() => {});
    },
    [navigate, scheduleExpTimer]
  );

  const markPolicyConfigured = useCallback(() => {
    setStatus('ready');
  }, []);

  const refreshProfile = useCallback(async (): Promise<boolean> => {
    const originalToken = SESSION_STORE.getToken();
    try {
      const profile = await profileApi.getProfile();
      if (originalToken !== SESSION_STORE.getToken()) return false;
      if (profile.user) setUser(profile.user);
      if (!profile.hasPolicy) {
        setStatus('needs-policy');
        return false;
      } else {
        setStatus('ready');
        return true;
      }
    } catch {
      return false;
    }
  }, []);

  return (
    <SessionContext.Provider
      value={{
        status,
        user,
        token,
        lastAccessCheck,
        setLastAccessCheck,
        setSessionToken,
        handleMfaVerified,
        markPolicyConfigured,
        logout,
        refreshProfile,
      }}
    >
      {status === 'loading' && sessionUnavailable ? (
        <main className="min-h-screen bg-bg px-6 flex items-center justify-center">
          <div className="w-full max-w-sm flex flex-col gap-4">
            <Alert variant="error">Unable to restore your session. Try again.</Alert>
            <Button onClick={bootstrapSession}>Retry</Button>
            <Button variant="secondary" onClick={() => logout()}>Log out</Button>
          </div>
        </main>
      ) : children}
    </SessionContext.Provider>
  );
};

export function useSession(): SessionContextType {
  const ctx = useContext(SessionContext);
  if (!ctx) {
    throw new Error('useSession must be used within a SessionProvider');
  }
  return ctx;
}
