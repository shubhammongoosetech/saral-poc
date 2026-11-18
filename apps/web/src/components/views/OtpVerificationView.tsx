import React, { useState, useEffect, useRef } from 'react';
import { useSession } from '../../context/SessionContext';
import { AuthLayout } from '../layout/AuthLayout';

export const OtpVerificationView: React.FC = () => {
  const {
    activeOtpMobile,
    setActiveOtpMobile,
    devOtp,
    verifyOtp,
    requestOtp,
  } = useSession();

  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(30);

  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  // Cooldown countdown
  useEffect(() => {
    if (cooldown <= 0) return;
    const interval = setInterval(() => setCooldown((c) => Math.max(0, c - 1)), 1000);
    return () => clearInterval(interval);
  }, [cooldown]);

  const handleInputChange = (index: number, val: string) => {
    const digit = val.replace(/\D/g, '').slice(-1);
    const next = [...code];
    next[index] = digit;
    setCode(next);
    if (error) setError(null);

    // Auto-advance
    if (digit && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Auto-submit when complete
    const full = next.join('');
    if (full.length === 6) {
      submitOtp(full);
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pasted) return;

    const next = [...code];
    for (let i = 0; i < pasted.length; i++) {
      next[i] = pasted[i];
    }
    setCode(next);

    if (pasted.length === 6) {
      submitOtp(pasted);
    } else {
      inputRefs.current[Math.min(pasted.length, 5)]?.focus();
    }
  };

  const submitOtp = async (codeToVerify: string) => {
    if (!activeOtpMobile) return;
    try {
      setLoading(true);
      setError(null);
      await verifyOtp(activeOtpMobile, codeToVerify);
    } catch (err: any) {
      setError(err.message || 'Incorrect verification code');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!activeOtpMobile || cooldown > 0) return;
    try {
      setLoading(true);
      setError(null);
      const res = await requestOtp(activeOtpMobile);
      setCooldown(res.cooldownSeconds || 30);
      setCode(['', '', '', '', '', '']);
      inputRefs.current[0]?.focus();
    } catch (err: any) {
      setError(err.message || 'Failed to resend code');
    } finally {
      setLoading(false);
    }
  };

  const maskedNumber = activeOtpMobile
    ? activeOtpMobile.replace(/(\+\d{2})(\d{2})\d{4}(\d{4})/, '$1 $2**** $3')
    : '+91';

  return (
    <AuthLayout subtitle="Enter the 6-digit verification code sent to your phone">
      <div className="flex flex-col gap-5">
        <div className="flex items-center justify-between">
          <div className="flex flex-col">
            <span className="text-xs text-muted font-medium">Verifying</span>
            <span className="text-sm font-bold text-text font-mono">{maskedNumber}</span>
          </div>
          <button
            type="button"
            onClick={() => setActiveOtpMobile(null)}
            className="text-xs font-semibold text-accent hover:underline cursor-pointer"
          >
            Change number
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium">
            {error}
          </div>
        )}

        {/* 6 OTP Input Boxes */}
        <div className="flex items-center justify-between gap-2" onPaste={handlePaste}>
          {code.map((digit, idx) => (
            <input
              key={idx}
              ref={(el) => (inputRefs.current[idx] = el)}
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={1}
              value={digit}
              onChange={(e) => handleInputChange(idx, e.target.value)}
              onKeyDown={(e) => handleKeyDown(idx, e)}
              disabled={loading}
              className="w-12 h-14 text-center text-xl font-bold font-mono bg-surface border border-border rounded-xl text-text focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all select-none"
            />
          ))}
        </div>

        {/* Dev Helper */}
        {devOtp && (
          <div className="flex items-center justify-between p-2.5 rounded-xl bg-surface-2 border border-border text-xs font-mono">
            <span className="text-accent font-semibold">Dev Auto-fill:</span>
            <button
              type="button"
              onClick={() => {
                const parts = devOtp.split('');
                setCode(parts);
                submitOtp(devOtp);
              }}
              className="text-text hover:underline font-bold"
            >
              Use {devOtp} ➔
            </button>
          </div>
        )}

        <button
          type="button"
          onClick={() => submitOtp(code.join(''))}
          disabled={loading || code.join('').length !== 6}
          className="w-full h-11 bg-accent text-accent-contrast rounded-xl text-sm font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 shadow-xs cursor-pointer flex items-center justify-center gap-2"
        >
          {loading ? (
            <span className="w-4 h-4 border-2 border-accent-contrast border-t-transparent rounded-full animate-spin" />
          ) : (
            <span>Verify & Continue</span>
          )}
        </button>

        <div className="flex items-center justify-between text-xs text-muted pt-2 border-t border-border">
          <span>Didn't receive code?</span>
          {cooldown > 0 ? (
            <span className="font-mono text-muted">Resend in {cooldown}s</span>
          ) : (
            <button
              type="button"
              onClick={handleResend}
              disabled={loading}
              className="font-semibold text-accent hover:underline cursor-pointer"
            >
              Resend Code
            </button>
          )}
        </div>
      </div>
    </AuthLayout>
  );
};
