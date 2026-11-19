import React, { useState, useEffect } from 'react';
import { mfaApi, walletApi } from '@/shared/api/endpoints';
import { useSession } from './useSession';
import { getCurrentCoords } from '@/shared/hooks/useLocation';
import { SESSION_STORE } from '@/shared/lib/storage';
import { mapApiError } from '@/shared/lib/format';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { Button } from '@/shared/ui/Button';
import { Alert } from '@/shared/ui/Alert';
import { OtpInput } from '@/shared/ui/OtpInput';
import { CopyButton } from '@/shared/ui/CopyButton';

export const Mfa: React.FC = () => {
  const { token, handleMfaVerified, logout, setLastAccessCheck } = useSession();

  const [enrolled, setEnrolled] = useState<boolean | null>(null);
  const [secret, setSecret] = useState<string>('');
  const [qrUri, setQrUri] = useState<string>('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [code, setCode] = useState('');
  const [recoveryInput, setRecoveryInput] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize MFA state: check if user is already enrolled
  useEffect(() => {
    if (!token) return;
    let mounted = true;

    const initMfa = async () => {
      try {
        setLoading(true);
        setError(null);

        const status = await mfaApi.getStatus();
        if (!mounted) return;

        if (status.enrolled) {
          setEnrolled(true);
          // Returning user: trigger challenge / fetch dev OTP if configured
          try {
            const res = await mfaApi.sendMfaOtp();
            if (import.meta.env.DEV && res.devOtp) {
              setDevOtp(res.devOtp);
              setCode(res.devOtp);
            }
          } catch (_) {}
        } else {
          setEnrolled(false);
          // New user: initiate enrollment
          const enrollData = await mfaApi.enroll();
          if (!mounted) return;
          setSecret(enrollData.secret);
          setQrUri(enrollData.qrUri);
          setRecoveryCodes(enrollData.recoveryCodes || []);
          if (import.meta.env.DEV && enrollData.devOtp) {
            setDevOtp(enrollData.devOtp);
            setCode(enrollData.devOtp);
          }
        }
      } catch (err: unknown) {
        if (mounted) {
          setError(mapApiError(err, 'Failed to initialize two-factor authentication'));
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    initMfa();

    return () => {
      mounted = false;
    };
  }, [token]);

  const handleVerify = async (e?: React.FormEvent, directCode?: string) => {
    if (e) e.preventDefault();

    const codeToVerify = useRecovery ? recoveryInput.trim().toUpperCase() : directCode || code;

    if (!useRecovery && codeToVerify.length !== 6) {
      setError('6 digits required');
      return;
    }
    if (useRecovery && !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(codeToVerify)) {
      setError('Recovery code must match XXXX-XXXX format');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await mfaApi.verifyMfaOtp(codeToVerify);

      // Store the upgraded token carrying mfaVerified: true
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
      setError(mapApiError(err, 'Verification failed. Please check the code and try again.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <div className="w-full flex flex-col gap-5">
        <div className="text-center">
          <h1 className="text-xl font-semibold text-text tracking-tight">
            {enrolled === false ? 'Set up Authenticator' : 'Two-Factor Authentication'}
          </h1>
          <p className="text-xs text-muted mt-1">
            {enrolled === false
              ? 'Scan this QR code with Google Authenticator or your preferred TOTP app.'
              : useRecovery
              ? 'Enter one of your 8-character backup recovery codes.'
              : 'Enter the 6-digit verification code from your authenticator app.'}
          </p>
        </div>

        {error && <Alert variant="error">{error}</Alert>}

        {/* First-time Enrollment View */}
        {enrolled === false && (
          <div className="flex flex-col gap-4">
            {qrUri && (
              <div className="flex flex-col items-center justify-center p-3 rounded-xl bg-surface-2 border border-border">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(qrUri)}`}
                  alt="MFA QR Code"
                  className="w-40 h-40 rounded-lg bg-white p-2"
                />
              </div>
            )}

            {secret && (
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-surface-2 border border-border text-xs font-mono">
                <div className="flex flex-col">
                  <span className="text-[10px] text-muted uppercase tracking-wider">Manual Setup Key</span>
                  <span className="font-semibold text-text tracking-wider">{secret}</span>
                </div>
                <CopyButton text={secret} variant="pill" />
              </div>
            )}

            {recoveryCodes.length > 0 && (
              <details className="text-xs text-muted border border-border rounded-lg p-2.5 bg-surface-2">
                <summary className="cursor-pointer font-medium text-text select-none">
                  Save Backup Recovery Codes ({recoveryCodes.length})
                </summary>
                <p className="text-[11px] text-muted my-2">
                  Save these single-use codes in a safe place. You can use them to recover access if you lose your authenticator.
                </p>
                <div className="grid grid-cols-2 gap-1.5 font-mono">
                  {recoveryCodes.map((c, i) => (
                    <div key={i} className="p-1.5 bg-surface-1 rounded border border-border text-center text-text font-medium">
                      {c}
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}

        {/* Verification Form */}
        <form onSubmit={(e) => handleVerify(e)} noValidate className="flex flex-col gap-4">
          {!useRecovery ? (
            <OtpInput
              value={code}
              onChange={setCode}
              onComplete={(val) => handleVerify(undefined, val)}
              disabled={loading}
            />
          ) : (
            <div>
              <label className="text-xs font-medium text-muted block mb-1">Backup Recovery Code</label>
              <input
                type="text"
                placeholder="XXXX-XXXX"
                value={recoveryInput}
                onChange={(e) => setRecoveryInput(e.target.value.toUpperCase())}
                disabled={loading}
                className="w-full text-center tracking-widest font-mono text-base px-3 py-2 rounded-lg border border-border bg-surface-2 text-text focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
          )}

          {import.meta.env.DEV && devOtp && !useRecovery && (
            <div className="flex items-center gap-2 p-2 rounded bg-surface-2 border border-border text-xs font-mono">
              <span className="text-accent font-semibold">Dev TOTP:</span>
              <span className="text-text">{devOtp}</span>
            </div>
          )}

          <Button
            type="submit"
            loading={loading}
            disabled={useRecovery ? recoveryInput.trim().length < 9 : code.length !== 6}
            fullWidth
          >
            {enrolled === false ? 'Verify and Activate' : 'Verify'}
          </Button>

          <div className="flex items-center justify-between text-xs pt-1">
            {enrolled === true ? (
              <button
                type="button"
                className="text-accent hover:underline font-medium"
                onClick={() => {
                  setUseRecovery(!useRecovery);
                  setError(null);
                }}
              >
                {useRecovery ? 'Use authenticator code' : 'Use a recovery code'}
              </button>
            ) : (
              <span className="text-muted">SARAL Multi-Factor Security</span>
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
