import React, { useState, useEffect, useRef } from 'react';
import { authApi } from '@/shared/api/endpoints';
import { useSession } from './useSession';
import { Input } from '@/shared/ui/Input';
import { Button } from '@/shared/ui/Button';
import { Field } from '@/shared/ui/Field';
import { Alert } from '@/shared/ui/Alert';
import { OtpInput } from '@/shared/ui/OtpInput';
import { mapApiError } from '@/shared/lib/format';
import type { LoginOptions } from '@/services/authApi';

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
  const [options, setOptions] = useState<LoginOptions | null>(null);
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const [optionsAttempt, setOptionsAttempt] = useState(0);
  const signingIn = useRef(false);

  const googleBtnRef = useRef<HTMLDivElement>(null);
  const developmentOtpEnabled = import.meta.env.DEV && options?.developmentOtpEnabled === true;
  const googleClientId = options?.googleClientId;

  useEffect(() => {
    const controller = new AbortController();
    setOptionsError(null);
    authApi.getLoginOptions(controller.signal).then((loginOptions) => {
      if (!controller.signal.aborted) setOptions(loginOptions);
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) setOptionsError(mapApiError(error, 'Unable to load sign-in options'));
    });
    return () => controller.abort();
  }, [optionsAttempt]);

  // Initialize Google OAuth
  useEffect(() => {
    if (!googleClientId) return;

    const handleGoogleCredential = async (response: { credential: string }) => {
      if (signingIn.current) return;
      signingIn.current = true;
      try {
        setLoading(true);
        setError(null);
        const res = await authApi.loginWithGoogle(response.credential);
        await setSessionToken(res.token, res.user);
      } catch (err: unknown) {
        setError(mapApiError(err, 'Google authentication failed'));
      } finally {
        signingIn.current = false;
        setLoading(false);
      }
    };

    const getGoogle = () => (window as unknown as GoogleAccountsWindow).google;

    const initGoogle = () => {
      const google = getGoogle();
      if (google?.accounts?.id && googleBtnRef.current) {
        google.accounts.id.initialize({
          client_id: googleClientId,
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
  }, [googleClientId, setSessionToken]);

  const handleMobileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // Extract only digits
    let digits = e.target.value.replace(/\D/g, '');
    // If pasted with India country code prefix (+91 / 91) and 12 digits, strip country code
    if (digits.length === 12 && digits.startsWith('91')) {
      digits = digits.slice(2);
    } else if (digits.length === 11 && digits.startsWith('0')) {
      digits = digits.slice(1);
    }
    // Limit to exactly 10 digits
    const cleaned = digits.slice(0, 10);
    setMobile(cleaned);
    if (error) setError(null);
  };

  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!developmentOtpEnabled || signingIn.current) return;
    const cleanMobile = mobile.trim();
    if (!cleanMobile) {
      setError('Mobile number required');
      return;
    }
    if (cleanMobile.length !== 10) {
      setError('Please enter a valid 10-digit mobile number');
      return;
    }
    if (!/^[6-9]\d{9}$/.test(cleanMobile)) {
      setError('Mobile number must be a valid 10-digit number starting with 6, 7, 8, or 9');
      return;
    }

    signingIn.current = true;
    try {
      setLoading(true);
      setError(null);
      setDevOtp(null);
      const res = await authApi.requestOtp(cleanMobile);
      setCodeSent(true);
      setDevOtp(res.devOtp ?? null);
    } catch (err: unknown) {
      setError(mapApiError(err, 'Failed to send code'));
    } finally {
      signingIn.current = false;
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e?: React.FormEvent, directCode?: string) => {
    if (e) e.preventDefault();
    if (!developmentOtpEnabled || signingIn.current) return;
    const codeToVerify = directCode || code;
    if (codeToVerify.length !== 6) {
      setError('6 digits required');
      return;
    }

    signingIn.current = true;
    try {
      setLoading(true);
      setError(null);
      const res = await authApi.verifyOtp(mobile.trim(), codeToVerify);
      await setSessionToken(res.token, res.user);
    } catch (err: unknown) {
      setError(mapApiError(err, 'Invalid code'));
    } finally {
      signingIn.current = false;
      setLoading(false);
    }
  };

  return (
    <div className="w-full flex flex-col gap-5">
      <h1 className="text-xl font-semibold text-text text-center tracking-tight">Sign in</h1>

      {error && <Alert variant="error">{error}</Alert>}
      {optionsError && (
        <>
          <Alert variant="error">{optionsError}</Alert>
          <Button onClick={() => setOptionsAttempt((attempt) => attempt + 1)} variant="secondary">Retry</Button>
        </>
      )}
      {!options && !optionsError && <p role="status" className="text-sm text-muted">Loading sign-in options…</p>}

      {googleClientId && (
        <div className="flex justify-center min-h-[44px]">
          <div ref={googleBtnRef} />
        </div>
      )}
      {options && !googleClientId && <Alert variant="error">Google sign-in is unavailable.</Alert>}

      {developmentOtpEnabled && <p className="text-sm text-muted">Development phone sign-in</p>}

      {developmentOtpEnabled && (!codeSent ? (
        <form onSubmit={handleSendCode} noValidate className="flex flex-col gap-4">
          <Field
            label="Mobile number"
            htmlFor="mobileInput"
            hint={
              mobile.length > 0 && mobile.length < 10
                ? `${mobile.length}/10 digits entered`
                : undefined
            }
          >
            <div className="relative flex items-center">
              <span className="absolute left-3 text-sm font-medium text-muted select-none pointer-events-none">
                +91
              </span>
              <Input
                id="mobileInput"
                type="tel"
                inputMode="numeric"
                pattern="[0-9]*"
                placeholder="9876543210"
                value={mobile}
                onChange={handleMobileChange}
                maxLength={10}
                className="pl-12 font-mono tracking-wide"
                disabled={loading}
                autoComplete="tel"
              />
            </div>
          </Field>

          <Button
            type="submit"
            loading={loading}
            disabled={loading || mobile.length !== 10}
            fullWidth
          >
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

          {devOtp && (
            <div
              onClick={() => setCode(devOtp)}
              className="flex items-center justify-between p-2 rounded bg-surface-2 border border-border text-xs font-mono cursor-pointer hover:border-accent transition-colors"
              title="Click to auto-fill code"
            >
              <div className="flex items-center gap-2">
                <span className="text-accent font-semibold">Dev OTP:</span>
                <span className="text-text font-bold tracking-wider">{devOtp}</span>
              </div>
              <span className="text-[10px] text-muted uppercase">Auto-filled</span>
            </div>
          )}

          <Button type="submit" loading={loading} disabled={code.length !== 6} fullWidth>
            Verify
          </Button>
        </form>
      ))}
    </div>
  );
};
