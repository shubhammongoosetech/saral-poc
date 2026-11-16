import React from 'react';

export const AuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-surface border border-border rounded-xl p-6 sm:p-8 shadow-none">
        <div className="flex items-center justify-center gap-2.5 mb-6">
          <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center text-accent-contrast font-bold text-base select-none">
            S
          </div>
          <span className="text-2xl font-bold text-text tracking-wider select-none">
            SARAL
          </span>
        </div>
        {children}
      </div>
    </div>
  );
};
