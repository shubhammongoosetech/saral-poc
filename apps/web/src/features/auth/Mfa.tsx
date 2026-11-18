import React, { useState, useEffect, useCallback, useRef } from 'react';
import { mfaApi, walletApi } from '@/shared/api/endpoints';
import { useSession } from './useSession';
import { getCurrentCoords } from '@/shared/hooks/useLocation';
import { SESSION_STORE } from '@/shared/lib/storage';
import { mapApiError } from '@/shared/lib/format';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { Button } from '@/shared/ui/Button';
import { Alert } from '@/shared/ui/Alert';
import { OtpInput } from '@/shared/ui/OtpInput';

export const Mfa: React.FC = () => {
  const { token, handleMfaVerified, logout, setLastAccessCheck } = useSession();

  const [code, setCode] = useState('');
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [cooldown, setCooldown] = useState(() => {
    return token ? SESSION_STORE.getRemainingMfaCooldown(token) : 0;
  });
  const [error, setError] = useState<string | null>(null);

  const initialSentRef = useRef(false);

  // Send MFA code
  const sendCode = useCallback(async () => {
    if (!token) return;
    try {
      setLoading(true);
      setError(null);
      setDevOtp(null);
      const res = await mfaApi.sendMfaOtp();
      SESSION_STORE.setMfaCodeSent(token);
      setCooldown(30);

      if (import.meta.env.DEV && res.devOtp) {
        setDevOtp(res.devOtp);
        setCode(res.devOtp);
      }
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to send code'));
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Auto-send exactly ONCE per login token
  useEffect(() => {
    if (!token || initialSentRef.current) return;
    initialSentRef.current = true;

    if (SESSION_STORE.canSendMfa(token)) {
      sendCode();
    } else {
      setCooldown(SESSION_STORE.getRemainingMfaCooldown(token));
    }
  }, [sendCode, token]);

  // Cooldown countdown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const interval = setInterval(() => {
      if (token) {
        const remaining = SESSION_STORE.getRemainingMfaCooldown(token);
        setCooldown(remaining);
      } else {
        setCooldown((c) => Math.max(0, c - 1));
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [cooldown, token]);

  const handleVerify = async (e?: React.FormEvent, directCode?: string) => {
    if (e) e.preventDefault();
    const codeToVerify = directCode || code;
    if (codeToVerify.length !== 6) {
      setError('6 digits required');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await mfaApi.verifyMfaOtp(codeToVerify);

      // Immediately store the MFA-verified token so subsequent authenticated requests carry mfaVerified: true
      SESSION_STORE.setToken(res.token);

      if (!res.hasPolicy) {
        await handleMfaVerified(res.token, false);
        return;
      }

      // Check access with geolocation before proceeding to wallet
      const coords = await getCurrentCoords();
      const check = await walletApi.checkAccess(coords.lat, coords.lng);
      setLastAccessCheck(check);

      if (check.allowed) {
        await handleMfaVerified(res.token, true);
      } else {
        setError(check.reason || 'Access allowed only during your working time and location.');
      }
    } catch (err: unknown) {
      setError(mapApiError(err, 'Invalid code'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <div className="w-full flex flex-col gap-5">
        <h1 className="text-xl font-semibold text-text text-center tracking-tight">Enter code</h1>

        {error && <Alert variant="error">{error}</Alert>}

        <form onSubmit={(e) => handleVerify(e)} noValidate className="flex flex-col gap-4">
          <OtpInput
            value={code}
            onChange={setCode}
            onComplete={(val) => handleVerify(undefined, val)}
            disabled={loading}
          />

          {import.meta.env.DEV && devOtp && (
            <div className="flex items-center gap-2 p-2 rounded bg-surface-2 border border-border text-xs font-mono">
              <span className="text-accent font-semibold">Dev only:</span>
              <span className="text-text">{devOtp}</span>
            </div>
          )}

          <Button type="submit" loading={loading} disabled={code.length !== 6} fullWidth>
            Verify
          </Button>

          <div className="flex items-center justify-between text-xs pt-1">
            {cooldown > 0 ? (
              <span className="text-muted">Resend in {cooldown}s</span>
            ) : (
              <button
                type="button"
                className="text-accent hover:underline font-medium"
                onClick={sendCode}
                disabled={loading}
              >
                Resend
              </button>
            )}

            <button
              type="button"
              className="text-muted hover:text-text transition-colors"
              onClick={() => logout()}
            >
              Log out
            </button>
          </div>
        </form>
      </div>
    </AuthLayout>
  );
};

export default Mfa;
