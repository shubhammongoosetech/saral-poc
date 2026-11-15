import React, { useState, useEffect, useRef } from 'react';
import { authApi } from '@/shared/api/endpoints';
import { useSession } from './useSession';
import { Input } from '@/shared/ui/Input';
import { Button } from '@/shared/ui/Button';
import { Field } from '@/shared/ui/Field';
import { Alert } from '@/shared/ui/Alert';
import { OtpInput } from '@/shared/ui/OtpInput';
import { mapApiError } from '@/shared/lib/format';

interface GoogleAccountsWindow {
  google?: {
    accounts?: {
      id?: {
        initialize: (config: { client_id: string; callback: (res: { credential: string }) => void }) => void;
        renderButton: (element: HTMLElement, options: Record<string, unknown>) => void;
      };
    };
  };
}

export const LoginForm: React.FC = () => {
  const { setSessionToken } = useSession();

  const [mobile, setMobile] = useState('');
  const [code, setCode] = useState('');
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [codeSent, setCodeSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const googleBtnRef = useRef<HTMLDivElement>(null);

  // Initialize Google OAuth
  useEffect(() => {
    const clientId =
      import.meta.env.VITE_GOOGLE_CLIENT_ID ||
      'your-google-client-id.apps.googleusercontent.com';

    const handleGoogleCredential = async (response: { credential: string }) => {
      try {
        setLoading(true);
        setError(null);
        const res = await authApi.loginWithGoogle(response.credential);
        await setSessionToken(res.token, res.user);
      } catch (err: unknown) {
        setError(mapApiError(err, 'Google authentication failed'));
      } finally {
        setLoading(false);
      }
    };

    const getGoogle = () => (window as unknown as GoogleAccountsWindow).google;

    const initGoogle = () => {
      const google = getGoogle();
      if (google?.accounts?.id && googleBtnRef.current) {
        google.accounts.id.initialize({
          client_id: clientId,
          callback: handleGoogleCredential,
        });
        google.accounts.id.renderButton(googleBtnRef.current, {
          theme: 'outline',
          size: 'large',
          width: 320,
          text: 'continue_with',
        });
      }
    };

    if (getGoogle()?.accounts?.id) {
      initGoogle();
    } else {
      const interval = setInterval(() => {
        if (getGoogle()?.accounts?.id) {
          clearInterval(interval);
          initGoogle();
        }
      }, 200);
      return () => clearInterval(interval);
    }
  }, [setSessionToken]);

  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mobile.trim()) {
      setError('Mobile number required');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setDevOtp(null);
      const res = await authApi.requestOtp(mobile.trim());
      setCodeSent(true);
      if (import.meta.env.DEV && res.devOtp) {
        setDevOtp(res.devOtp);
        setCode(res.devOtp);
      }
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to send code'));
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e?: React.FormEvent, directCode?: string) => {
    if (e) e.preventDefault();
    const codeToVerify = directCode || code;
    if (codeToVerify.length !== 6) {
      setError('6 digits required');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await authApi.verifyOtp(mobile.trim(), codeToVerify);
      await setSessionToken(res.token, res.user);
    } catch (err: unknown) {
      setError(mapApiError(err, 'Invalid code'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full flex flex-col gap-5">
      <h1 className="text-xl font-semibold text-text text-center tracking-tight">Sign in</h1>

      {error && <Alert variant="error">{error}</Alert>}

      {/* Google Sign In container */}
      <div className="flex justify-center min-h-[44px]">
        <div ref={googleBtnRef} />
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 h-px bg-border" />
        <span className="text-xs text-muted uppercase tracking-wider">or</span>
        <div className="flex-1 h-px bg-border" />
      </div>

      {!codeSent ? (
        <form onSubmit={handleSendCode} noValidate className="flex flex-col gap-4">
          <Field label="Mobile number" htmlFor="mobileInput">
            <Input
              id="mobileInput"
              type="tel"
              placeholder="+91 98765 43210"
              value={mobile}
              onChange={(e) => setMobile(e.target.value)}
              disabled={loading}
              autoComplete="tel"
            />
          </Field>

          <Button type="submit" loading={loading} disabled={!mobile.trim()} fullWidth>
            Continue
          </Button>
        </form>
      ) : (
        <form onSubmit={(e) => handleVerifyCode(e)} noValidate className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-muted">Code</span>
            <button
              type="button"
              className="text-xs text-accent hover:underline"
              onClick={() => {
                setCodeSent(false);
                setDevOtp(null);
                setCode('');
              }}
            >
              Change number
            </button>
          </div>

          <OtpInput
            value={code}
            onChange={setCode}
            onComplete={(val) => handleVerifyCode(undefined, val)}
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
        </form>
      )}
    </div>
  );
};
