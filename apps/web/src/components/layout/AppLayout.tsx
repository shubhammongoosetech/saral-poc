import React from 'react';
import { useSession } from '../../context/SessionContext';

export const AppLayout: React.FC<{
  children: React.ReactNode;
  activeTab?: 'wallet' | 'settings';
  onTabChange?: (tab: 'wallet' | 'settings') => void;
}> = ({ children, activeTab = 'wallet', onTabChange }) => {
  const { user, logout, policy } = useSession();

  const displayName = user?.name || user?.email || user?.mobile || 'SARAL User';
  const displaySub = user?.email || user?.mobile || '';

  const [theme, setTheme] = React.useState<'dark' | 'light'>('dark');

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.setAttribute('data-theme', next);
  };

  return (
    <div className="min-h-screen bg-bg text-text flex flex-col font-sans selection:bg-accent/20">
      {/* Premium Minimal Header */}
      <header className="h-16 bg-surface border-b border-border px-4 sm:px-8 flex items-center justify-between sticky top-0 z-30 shadow-xs">
        {/* Brand & Network Pill */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent text-accent-contrast flex items-center justify-center font-bold text-base shadow-xs select-none">
            S
          </div>
          <span className="font-bold text-text text-lg tracking-wider select-none">SARAL</span>
          <span className="text-[10px] font-semibold bg-surface-2 text-muted px-2 py-0.5 rounded-full border border-border">
            Testnet
          </span>
        </div>

        {/* Center: Navigation (Wallet vs Settings) */}
        {onTabChange && (
          <div className="hidden sm:flex items-center bg-surface-2 p-1 rounded-xl border border-border">
            <button
              type="button"
              onClick={() => onTabChange('wallet')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === 'wallet'
                  ? 'bg-surface text-accent font-semibold shadow-xs'
                  : 'text-muted hover:text-text'
              }`}
            >
              Wallet
            </button>
            <button
              type="button"
              onClick={() => onTabChange('settings')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === 'settings'
                  ? 'bg-surface text-accent font-semibold shadow-xs'
                  : 'text-muted hover:text-text'
              }`}
            >
              Security & Policy
            </button>
          </div>
        )}

        {/* Right: Policy status, Profile pill, Theme, Logout */}
        <div className="flex items-center gap-3">
          {/* Policy Active Pill */}
          {policy?.timeRestrictionEnabled && (
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-success/10 border border-success/30 text-[11px] text-success font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
              <span>Policy Active ({policy.timezone})</span>
            </div>
          )}

          {/* User Badge */}
          <div className="flex items-center gap-2 pl-2 border-l border-border/80">
            <div className="w-8 h-8 rounded-full bg-surface-2 border border-border flex items-center justify-center text-xs font-bold text-accent">
              {displayName.charAt(0).toUpperCase()}
            </div>
            <div className="hidden lg:flex flex-col text-left">
              <span className="text-xs font-semibold text-text truncate max-w-[130px]">{displayName}</span>
              {displaySub && (
                <span className="text-[10px] text-muted truncate max-w-[130px]">{displaySub}</span>
              )}
            </div>
          </div>

          {/* Theme Toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            className="p-2 rounded-lg text-muted hover:text-text hover:bg-surface-2 transition-colors"
            title="Toggle color theme"
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>

          {/* Logout */}
          <button
            type="button"
            onClick={logout}
            className="text-xs font-medium text-danger hover:bg-danger/10 px-2.5 py-1.5 rounded-lg transition-colors"
          >
            Log out
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 w-full max-w-4xl mx-auto p-4 sm:p-6 md:p-8">
        {children}
      </main>
    </div>
  );
};
