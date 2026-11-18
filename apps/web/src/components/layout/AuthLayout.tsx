import React from 'react';

export const AuthLayout: React.FC<{ children: React.ReactNode; subtitle?: string }> = ({
  children,
  subtitle,
}) => {
  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4 selection:bg-accent/20">
      <div className="w-full max-w-md bg-surface border border-border rounded-2xl p-6 sm:p-8 shadow-sm">
        {/* SARAL Brand Header */}
        <div className="flex flex-col items-center gap-2 mb-6">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-accent flex items-center justify-center text-accent-contrast font-bold text-lg select-none shadow-sm">
              S
            </div>
            <span className="text-2xl font-bold text-text tracking-wider select-none font-sans">
              SARAL
            </span>
          </div>
          {subtitle && (
            <p className="text-xs text-muted text-center tracking-tight max-w-xs">
              {subtitle}
            </p>
          )}
        </div>

        {children}
      </div>
    </div>
  );
};
