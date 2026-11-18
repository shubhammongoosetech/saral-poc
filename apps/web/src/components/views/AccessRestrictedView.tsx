import React, { useState } from 'react';
import { useSession } from '../../context/SessionContext';

export const AccessRestrictedView: React.FC = () => {
  const { accessRestrictionReason, retryAccessCheck, logout, policy } = useSession();
  const [retrying, setRetrying] = useState(false);

  const handleRetry = async () => {
    try {
      setRetrying(true);
      await retryAccessCheck();
    } finally {
      setRetrying(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-6 selection:bg-danger/20 font-sans">
      <div className="w-full max-w-md bg-surface border border-border rounded-2xl p-6 sm:p-8 text-center shadow-sm flex flex-col items-center gap-5">
        <div className="w-14 h-14 rounded-full bg-danger/10 text-danger flex items-center justify-center text-2xl select-none">
          🔒
        </div>

        <div className="flex flex-col gap-1.5">
          <h1 className="text-xl font-bold text-text tracking-tight">Access Restricted</h1>
          <p className="text-xs text-muted leading-relaxed">
            Your contextual working policy has denied access to your SARAL Wallet.
          </p>
        </div>

        {/* Reason Box */}
        <div className="w-full p-4 rounded-xl bg-danger/5 border border-danger/20 text-xs text-danger font-medium text-left flex flex-col gap-1">
          <span className="font-bold uppercase tracking-wider text-[10px]">Reason:</span>
          <p className="font-mono text-[11px] leading-relaxed">
            {accessRestrictionReason || 'Access permitted only during authorized working hours and within the approved geographic zone.'}
          </p>
        </div>

        {/* Policy Summary */}
        {policy && (
          <div className="w-full p-3 rounded-xl bg-surface-2 border border-border text-left flex flex-col gap-1 text-[11px] text-muted">
            <span className="font-semibold text-text">Active Policy Requirements:</span>
            {policy.timeRestrictionEnabled && (
              <span>• Hours: {policy.startTime} - {policy.endTime} ({policy.timezone})</span>
            )}
            {policy.days && (
              <span>• Days: {policy.days.join(', ')}</span>
            )}
            {policy.locationRestrictionEnabled && (
              <span>• Area: {policy.allowedRegion} ({Math.round((policy.radiusMeters || 25000) / 1000)} km radius)</span>
            )}
          </div>
        )}

        <div className="w-full flex gap-3 pt-2">
          <button
            type="button"
            onClick={logout}
            className="flex-1 h-11 border border-border text-text rounded-xl text-xs font-semibold hover:bg-surface-2 transition-colors cursor-pointer"
          >
            Log out
          </button>
          <button
            type="button"
            onClick={handleRetry}
            disabled={retrying}
            className="flex-1 h-11 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors disabled:opacity-50 cursor-pointer flex items-center justify-center gap-1.5"
          >
            {retrying ? 'Checking Policy...' : 'Retry Verification ↻'}
          </button>
        </div>
      </div>
    </div>
  );
};
