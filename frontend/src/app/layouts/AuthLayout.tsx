import React from 'react';

export const AuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm bg-surface border border-border rounded-xl p-6 sm:p-8 shadow-none">
        <div className="flex justify-center mb-6">
          <div className="w-10 h-10 rounded-lg bg-accent flex items-center justify-center text-accent-contrast font-bold text-xl select-none">
            S
          </div>
        </div>
        {children}
      </div>
    </div>
  );
};
