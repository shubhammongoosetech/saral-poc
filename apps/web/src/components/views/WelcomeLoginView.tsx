import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';
import { AuthLayout } from '../layout/AuthLayout';

export const WelcomeLoginView: React.FC = () => {
  const { loginWithGoogle, requestOtp } = useSession();

  const [mobile, setMobile] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleMobileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    let digits = e.target.value.replace(/\D/g, '');
    if (digits.length === 12 && digits.startsWith('91')) {
      digits = digits.slice(2);
    } else if (digits.length === 11 && digits.startsWith('0')) {
      digits = digits.slice(1);
    }
    setMobile(digits.slice(0, 10));
    if (error) setError(null);
  };

  const handlePhoneSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mobile.length !== 10) {
      setError('Please enter a valid 10-digit mobile number');
      return;
    }
    if (!/^[6-9]\d{9}$/.test(mobile)) {
      setError('Mobile number must start with 6, 7, 8, or 9');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      await requestOtp(mobile);
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch OTP');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleClick = async () => {
    try {
      setLoading(true);
      setError(null);
      // Generate standard test credential or initiate Google popup
      const mockCredential = `google-jwt-${Date.now()}`;
      await loginWithGoogle(mockCredential);
    } catch (err: any) {
      setError(err.message || 'Google authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout subtitle="Institutional-Grade Key Infrastructure with Zero Single Point of Failure">
      <div className="flex flex-col gap-5">
        <h1 className="text-xl font-bold text-text text-center tracking-tight">
          Welcome to SARAL Wallet
        </h1>

        {error && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium">
            {error}
          </div>
        )}

        {/* Option A: Google Sign In */}
        <button
          type="button"
          onClick={handleGoogleClick}
          disabled={loading}
          className="w-full h-11 bg-surface border border-border rounded-xl flex items-center justify-center gap-3 text-sm font-semibold text-text hover:bg-surface-2 transition-colors disabled:opacity-50 shadow-xs cursor-pointer"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path
              fill="#4285F4"
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            />
            <path
              fill="#34A853"
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            />
            <path
              fill="#FBBC05"
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
            />
            <path
              fill="#EA4335"
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
            />
          </svg>
          <span>Continue with Google</span>
        </button>

        <div className="flex items-center gap-3">
          <div className="flex-1 h-px bg-border" />
          <span className="text-xs text-muted uppercase tracking-wider font-semibold">or</span>
          <div className="flex-1 h-px bg-border" />
        </div>

        {/* Option B: Mobile Phone OTP */}
        <form onSubmit={handlePhoneSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="mobileInput" className="text-xs font-semibold text-text">
              Phone Number
            </label>
            <div className="relative flex items-center">
              <span className="absolute left-3.5 text-sm font-semibold text-muted select-none pointer-events-none">
                +91
              </span>
              <input
                id="mobileInput"
                type="tel"
                inputMode="numeric"
                pattern="[0-9]*"
                placeholder="9876543210"
                value={mobile}
                onChange={handleMobileChange}
                maxLength={10}
                className="w-full h-11 pl-12 pr-4 bg-surface border border-border rounded-xl text-sm font-mono tracking-wider text-text placeholder:text-muted/60 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all"
                disabled={loading}
                autoComplete="tel"
              />
            </div>
            {mobile.length > 0 && mobile.length < 10 && (
              <span className="text-[11px] text-muted">
                {mobile.length}/10 digits entered
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || mobile.length !== 10}
            className="w-full h-11 bg-accent text-accent-contrast rounded-xl text-sm font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 shadow-xs cursor-pointer flex items-center justify-center gap-2"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-accent-contrast border-t-transparent rounded-full animate-spin" />
            ) : (
              <span>Continue with Phone</span>
            )}
          </button>
        </form>
      </div>
    </AuthLayout>
  );
};
