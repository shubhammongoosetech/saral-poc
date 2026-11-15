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
import { profileApi } from '@/shared/api/endpoints';
import { setAuthErrorHandler } from '@/shared/api/client';
import { SESSION_STORE } from '@/shared/lib/storage';
import { decodeJwtClaims, isTokenExpired } from '@/shared/lib/jwt';
import { SessionStatus } from '@/app/guards/resolveGate';

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

  // In-memory access check state: null means 'unknown', which is NOT denied.
  // Geolocation is NEVER requested automatically on navigation/refresh.
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
      SESSION_STORE.clearToken();
      SESSION_STORE.clearMfaMarkers();
      queryClient.clear();
      setToken(null);
      setUser(null);
      setLastAccessCheck(null);
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
      setUser(profile.user);

      if (!profile.hasPolicy) {
        setStatus('needs-policy');
      } else {
        setStatus('ready');
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status?: number } };
      if (axiosErr.response?.status === 401) {
        logout('Session expired');
      } else {
        setStatus('anonymous');
      }
    }
  }, [logout, scheduleExpTimer]);

  useEffect(() => {
    bootstrapSession();
  }, [bootstrapSession]);

  // Called after step 1 login (Google or Mobile OTP)
  const setSessionToken = useCallback(
    async (newToken: string, newUser?: User) => {
      SESSION_STORE.setToken(newToken);
      setToken(newToken);
      if (newUser) setUser(newUser);

      const claims = decodeJwtClaims(newToken);
      if (claims?.exp) scheduleExpTimer(claims.exp);

      if (claims?.mfaVerified) {
        try {
          const profile = await profileApi.getProfile();
          if (profile.user) setUser(profile.user);
          if (!profile.hasPolicy) {
            setStatus('needs-policy');
            navigate('/working-policy', { replace: true });
          } else {
            setStatus('ready');
            navigate('/wallet', { replace: true });
          }
        } catch {
          setStatus('needs-policy');
          navigate('/working-policy', { replace: true });
        }
      } else {
        setStatus('needs-mfa');
        navigate('/mfa', { replace: true });
      }
    },
    [navigate, scheduleExpTimer]
  );

  // Called after step 2 MFA verification
  const handleMfaVerified = useCallback(
    async (newToken: string, hasPolicy: boolean, destination?: string) => {
      SESSION_STORE.setToken(newToken);
      // Clean up previous OTP request timestamps now that MFA is verified
      SESSION_STORE.clearMfaMarkers();
      setToken(newToken);

      const claims = decodeJwtClaims(newToken);
      if (claims?.exp) scheduleExpTimer(claims.exp);

      if (!hasPolicy) {
        setStatus('needs-policy');
        navigate('/working-policy', { replace: true });
        return;
      }

      try {
        const profile = await profileApi.getProfile();
        if (profile.user) setUser(profile.user);
      } catch {}

      setStatus('ready');
      navigate(destination || '/wallet', { replace: true });
    },
    [navigate, scheduleExpTimer]
  );

  const markPolicyConfigured = useCallback(() => {
    setStatus('ready');
  }, []);

  const refreshProfile = useCallback(async (): Promise<boolean> => {
    try {
      const profile = await profileApi.getProfile();
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
      {children}
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
