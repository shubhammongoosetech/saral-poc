import React, { useState, useEffect, useRef } from 'react';
import { mfaApi } from '@/shared/api/endpoints';
import { useSession } from './useSession';
import { SESSION_STORE } from '@/shared/lib/storage';
import { mapApiError } from '@/shared/lib/format';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { Button } from '@/shared/ui/Button';
import { Alert } from '@/shared/ui/Alert';
import { OtpInput } from '@/shared/ui/OtpInput';
import { CopyButton } from '@/shared/ui/CopyButton';
import { QrCode } from '@/shared/ui/QrCode';

export const Mfa: React.FC = () => {
  const { token, handleMfaVerified, logout } = useSession();

  const [enrolled, setEnrolled] = useState<boolean | null>(null);
  const [secret, setSecret] = useState<string>('');
  const [qrUri, setQrUri] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [code, setCode] = useState('');
  const [recoveryInput, setRecoveryInput] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [developmentOtpEnabled, setDevelopmentOtpEnabled] = useState(false);
  const [devOtp, setDevOtp] = useState<string | null>(null);
  const [loadingDevOtp, setLoadingDevOtp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const verifying = useRef(false);
  const validRecoveryCode = /^(?:[A-Z0-9]{4}-[A-Z0-9]{4}|[A-F0-9]{4}(?:-[A-F0-9]{4}){4})$/;

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

        const showDevOtp = import.meta.env.DEV && status.developmentOtpEnabled === true;
        setDevelopmentOtpEnabled(showDevOtp);
        if (status.enrolled) {
          setEnrolled(true);
        } else {
          setEnrolled(false);
          // New user: initiate enrollment
          const enrollData = await mfaApi.enroll();
          if (!mounted) return;
          setSecret(enrollData.secret);
          setQrUri(enrollData.qrUri);
          setRecoveryCodes(enrollData.recoveryCodes || []);
          if (showDevOtp) setDevOtp(enrollData.devOtp ?? null);
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

  const showDevelopmentCode = async () => {
    const originalToken = SESSION_STORE.getToken();
    setLoadingDevOtp(true);
    setError(null);
    try {
      const result = await mfaApi.sendMfaOtp();
      if (SESSION_STORE.getToken() === originalToken) setDevOtp(result.devOtp ?? null);
    } catch (error: unknown) {
      if (SESSION_STORE.getToken() === originalToken) {
        setError(mapApiError(error, 'Unable to load a development code'));
      }
    } finally {
      setLoadingDevOtp(false);
    }
  };

  const handleVerify = async (e?: React.FormEvent, directCode?: string) => {
    if (e) e.preventDefault();
    if (enrolled === null || verifying.current) return;

    const codeToVerify = useRecovery ? recoveryInput.trim().toUpperCase() : directCode || code;

    if (!useRecovery && codeToVerify.length !== 6) {
      setError('6 digits required');
      return;
    }
    if (useRecovery && !validRecoveryCode.test(codeToVerify)) {
      setError('Enter a recovery code exactly as shown in your saved codes.');
      return;
    }

    verifying.current = true;
    const originalToken = SESSION_STORE.getToken();
    try {
      setLoading(true);
      setError(null);
      const res = await mfaApi.verifyMfaOtp(codeToVerify);
      if (SESSION_STORE.getToken() !== originalToken) return;

      await handleMfaVerified(res.token, res.hasPolicy);
    } catch (err: unknown) {
      setError(mapApiError(err, 'Verification failed. Please check the code and try again.'));
    } finally {
      verifying.current = false;
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
              ? 'Scan the QR code or enter the setup key in your authenticator app.'
              : useRecovery
              ? 'Enter one of your saved recovery codes.'
              : 'Enter the 6-digit verification code from your authenticator app.'}
          </p>
        </div>

        {error && <Alert variant="error">{error}</Alert>}

        {/* First-time Enrollment View */}
        {enrolled === false && (
          <div className="flex flex-col gap-4">
            {qrUri && <QrCode value={qrUri} label="Authenticator setup QR code" size={180} />}
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
              disabled={loading || enrolled === null}
            />
          ) : (
            <div>
              <label htmlFor="recovery-code" className="text-xs font-medium text-muted block mb-1">Backup Recovery Code</label>
              <input
                id="recovery-code"
                type="text"
                placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"
                maxLength={23}
                value={recoveryInput}
                onChange={(e) => setRecoveryInput(e.target.value.toUpperCase())}
                disabled={loading}
                className="w-full text-center tracking-widest font-mono text-base px-3 py-2 rounded-lg border border-border bg-surface-2 text-text focus:outline-none focus:ring-2 focus:ring-accent"
              />
            </div>
          )}

          {developmentOtpEnabled && !useRecovery && (
            <div className="flex flex-col gap-2">
              {enrolled && (
                <Button type="button" variant="secondary" size="sm" onClick={showDevelopmentCode} loading={loadingDevOtp}>
                  Show development code
                </Button>
              )}
              {devOtp && (
                <div
                  onClick={() => setCode(devOtp)}
                  className="flex items-center justify-between p-2 rounded bg-surface-2 border border-border text-xs font-mono cursor-pointer hover:border-accent transition-colors"
                  title="Click to auto-fill code"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-accent font-semibold">Dev MFA Code:</span>
                    <span className="text-text font-bold tracking-wider">{devOtp}</span>
                  </div>
                  <span className="text-[10px] text-muted uppercase">Auto-filled</span>
                </div>
              )}
            </div>
          )}

          <Button
            type="submit"
            loading={loading}
            disabled={enrolled === null || (useRecovery ? !validRecoveryCode.test(recoveryInput.trim()) : code.length !== 6)}
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
