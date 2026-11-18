import React, { useState, useEffect, useRef } from 'react';
import { useSession } from '../../context/SessionContext';
import { authApi } from '../../services/authApi';
import { AuthLayout } from '../layout/AuthLayout';

export const MfaView: React.FC = () => {
  const { mfaEnrolled, verifyMfa, logout } = useSession();

  const [enrollData, setEnrollData] = useState<{
    secret: string;
    qrUri: string;
    recoveryCodes: string[];
  } | null>(null);

  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const enrollInitiatedRef = useRef(false);

  // If not enrolled, initiate enrollment once
  useEffect(() => {
    if (!mfaEnrolled && !enrollData && !enrollInitiatedRef.current) {
      enrollInitiatedRef.current = true;
      setLoading(true);
      authApi
        .enrollMfa()
        .then((data) => {
          setEnrollData(data);
          setError(null);
        })
        .catch((err) => {
          setError(err.message || 'Failed to initiate MFA enrollment');
          enrollInitiatedRef.current = false;
        })
        .finally(() => setLoading(false));
    }
  }, [mfaEnrolled, enrollData]);

  const selectRecoveryCode = (recoveryCode: string) => {
    setUseRecovery(true);
    setCode(recoveryCode);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = code.trim();
    if (!clean) {
      setError(useRecovery ? 'Recovery code required (XXXX-XXXX)' : '6-digit authenticator code required');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      await verifyMfa(clean);
    } catch (err: any) {
      setError(err.message || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  const copyRecoveryCodes = () => {
    if (!enrollData) return;
    navigator.clipboard.writeText(enrollData.recoveryCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  return (
    <AuthLayout
      subtitle={
        !mfaEnrolled
          ? 'Secure your SARAL account with an Authenticator app (Google Authenticator, Authy, or 1Password)'
          : 'Enter your 6-digit authenticator code or single-use recovery code'
      }
    >
      <div className="flex flex-col gap-5">
        <h1 className="text-xl font-bold text-text text-center tracking-tight">
          {!mfaEnrolled ? 'Set Up Two-Factor Authentication' : 'Second-Factor Verification'}
        </h1>

        {error && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium">
            {error}
          </div>
        )}

        {/* Enrollment Instructions & QR */}
        {!mfaEnrolled && enrollData && (
          <div className="flex flex-col gap-4 p-4 rounded-xl bg-surface-2 border border-border">
            <div className="flex flex-col items-center gap-2">
              <span className="text-xs font-semibold text-text text-center">
                Scan with Authenticator App
              </span>
              {/* Simulated QR Code Canvas / Visual representation */}
              <div className="w-36 h-36 bg-surface p-2 rounded-xl border border-border flex items-center justify-center text-center">
                <div className="flex flex-col items-center justify-center gap-1">
                  <div className="w-24 h-24 bg-surface-2 rounded-lg border border-border/80 flex items-center justify-center">
                    <span className="text-[10px] font-mono text-muted text-center p-1 break-all">
                      [QR: {enrollData.secret.slice(0, 8)}...]
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Manual Secret Key */}
            <div className="flex flex-col gap-1">
              <span className="text-[11px] text-muted font-medium">Manual Entry Key:</span>
              <div className="p-2 rounded-lg bg-surface border border-border font-mono text-xs text-accent font-semibold tracking-wider text-center select-all">
                {enrollData.secret}
              </div>
            </div>

            {/* Recovery Codes */}
            <div className="flex flex-col gap-1.5 pt-2 border-t border-border">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-muted font-medium">One-Time Recovery Codes:</span>
                <button
                  type="button"
                  onClick={copyRecoveryCodes}
                  className="text-[11px] text-accent font-semibold hover:underline"
                >
                  {copiedCodes ? 'Copied!' : 'Copy All'}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-1.5 p-2 rounded-lg bg-surface border border-border font-mono text-[11px] text-text text-center select-all">
                {enrollData.recoveryCodes.map((c, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => selectRecoveryCode(c)}
                    title="Click to use this recovery code"
                    className="p-1 rounded hover:bg-accent/10 hover:text-accent transition-colors cursor-pointer text-center font-mono"
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Challenge Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="mfaInput" className="text-xs font-semibold text-text">
                {useRecovery ? 'Recovery Code' : '6-Digit Authenticator Code'}
              </label>
              {mfaEnrolled && (
                <button
                  type="button"
                  onClick={() => {
                    setUseRecovery(!useRecovery);
                    setCode('');
                    setError(null);
                  }}
                  className="text-xs text-accent hover:underline"
                >
                  {useRecovery ? 'Use Authenticator Code' : 'Use Recovery Code'}
                </button>
              )}
            </div>

            <input
              id="mfaInput"
              type="text"
              placeholder={useRecovery ? 'XXXX-XXXX' : '123456'}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              maxLength={useRecovery ? 9 : 6}
              className="w-full h-11 px-4 bg-surface border border-border rounded-xl text-center text-lg font-mono font-bold tracking-widest text-text placeholder:text-muted/50 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all"
              disabled={loading}
              autoComplete="one-time-code"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !code.trim()}
            className="w-full h-11 bg-accent text-accent-contrast rounded-xl text-sm font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 shadow-xs cursor-pointer flex items-center justify-center gap-2"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-accent-contrast border-t-transparent rounded-full animate-spin" />
            ) : (
              <span>Confirm & Continue</span>
            )}
          </button>
        </form>

        <div className="flex justify-center text-xs pt-1 border-t border-border">
          <button
            type="button"
            onClick={logout}
            className="text-muted hover:text-text transition-colors cursor-pointer"
          >
            Log out & cancel
          </button>
        </div>
      </div>
    </AuthLayout>
  );
};
