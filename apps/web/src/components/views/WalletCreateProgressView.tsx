import React, { useState, useEffect, useRef } from 'react';
import { useSession } from '../../context/SessionContext';
import { AuthLayout } from '../layout/AuthLayout';

const STEPS = [
  'User identity authenticated & verified',
  'Contextual working policy enforced',
  '15-Node committee initialized across 3 Domains',
  'Asynchronous Verifiable Secret Sharing (AVSS) in progress',
  'Dealerless DKG polynomial contributions verified',
  'Encrypted distributed key shares committed to node vaults',
  'Multi-chain blockchain public keys audited',
  'Deterministic wallet addresses generated',
];

export const WalletCreateProgressView: React.FC<{ onComplete?: () => void }> = ({ onComplete }) => {
  const { startWalletCreation } = useSession();

  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const initiatedRef = useRef(false);

  const runCreation = () => {
    setError(null);
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev < STEPS.length - 2) return prev + 1;
        return prev;
      });
    }, 450);

    startWalletCreation()
      .then(() => {
        setCurrentStepIndex(STEPS.length - 1);
        clearInterval(interval);
        setTimeout(() => {
          if (onComplete) onComplete();
        }, 800);
      })
      .catch((err) => {
        clearInterval(interval);
        setError(err.message || 'Failed to initialize distributed wallet');
      });

    return () => clearInterval(interval);
  };

  useEffect(() => {
    if (initiatedRef.current) return;
    initiatedRef.current = true;
    return runCreation();
  }, [startWalletCreation]);

  const handleRetry = () => {
    setCurrentStepIndex(0);
    runCreation();
  };

  return (
    <AuthLayout subtitle="Generating institutional-grade distributed key shares across Foundation, Public, and Private domains">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col items-center text-center gap-2">
          <div className="w-12 h-12 rounded-2xl bg-accent/10 border border-accent/20 flex items-center justify-center text-accent">
            <span className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin" />
          </div>
          <h1 className="text-xl font-bold text-text tracking-tight">
            Creating Your Secure SARAL Wallet
          </h1>
          <p className="text-xs text-muted max-w-xs">
            Zero complete private key reconstruction. Keys exist exclusively as distributed polynomial shares.
          </p>
        </div>

        {error && (
          <div className="flex flex-col gap-2.5">
            <div className="p-3.5 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger font-medium leading-relaxed">
              {error}
            </div>
            <button
              type="button"
              onClick={handleRetry}
              className="h-10 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors cursor-pointer flex items-center justify-center gap-1.5"
            >
              Retry Wallet Generation ↻
            </button>
          </div>
        )}

        {/* 8-Step Verification Checklist */}
        <div className="flex flex-col gap-2.5 p-4 rounded-xl bg-surface-2 border border-border">
          {STEPS.map((step, idx) => {
            const isCompleted = idx < currentStepIndex;
            const isCurrent = idx === currentStepIndex;

            return (
              <div key={idx} className="flex items-center gap-3 text-xs">
                {isCompleted ? (
                  <div className="w-5 h-5 rounded-full bg-success text-accent-contrast flex items-center justify-center font-bold text-[10px] shrink-0">
                    ✓
                  </div>
                ) : isCurrent ? (
                  <div className="w-5 h-5 rounded-full border-2 border-accent border-t-transparent animate-spin shrink-0" />
                ) : (
                  <div className="w-5 h-5 rounded-full border border-border bg-surface shrink-0" />
                )}

                <span
                  className={`${
                    isCompleted
                      ? 'text-text font-medium'
                      : isCurrent
                      ? 'text-accent font-semibold'
                      : 'text-muted'
                  }`}
                >
                  {step}
                </span>
              </div>
            );
          })}
        </div>

        {/* Committee Topology Reminder */}
        <div className="flex items-center justify-between text-[11px] text-muted font-mono px-2">
          <span>Committee Threshold:</span>
          <span className="text-text font-semibold">k=5 / n=15 (t=4 Byzantine)</span>
        </div>
      </div>
    </AuthLayout>
  );
};
