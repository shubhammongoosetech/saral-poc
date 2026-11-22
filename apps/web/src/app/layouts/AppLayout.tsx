import React, { useState } from 'react';
import { NavLink, Link, Outlet, useNavigate } from 'react-router-dom';
import { useSession } from '@/features/auth/useSession';
import { useBreakpoint } from '@/shared/hooks/useBreakpoint';
import { useTheme } from '@/shared/hooks/useTheme';
import { walletApi } from '@/shared/api/endpoints';
import { mapApiError } from '@/shared/lib/format';
import { Avatar } from '@/shared/ui/Avatar';
import {
  IconWallet,
  IconActivity,
  IconSettings,
  IconAlert,
} from '@/shared/ui/icons';

export const AppLayout: React.FC = () => {
  const { user, logout, lastAccessCheck, setLastAccessCheck } = useSession();
  const { isMobile } = useBreakpoint();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();

  const [retryingAccess, setRetryingAccess] = useState(false);

  const displayName = user?.name || user?.email || 'Account 1';
  const displaySub = user?.name && user?.email ? user.email : user?.mobile || '';

  const handleRetryAccess = async () => {
    try {
      setRetryingAccess(true);
      const res = await walletApi.checkAccess();
      setLastAccessCheck(res);
      if (res.allowed) {
        navigate('/wallet');
      }
    } catch (error: unknown) {
      setLastAccessCheck({ allowed: false, reason: mapApiError(error, 'Unable to verify access.') });
    } finally {
      setRetryingAccess(false);
    }
  };

  // If last access check was denied, show "Access restricted" screen
  if (lastAccessCheck && !lastAccessCheck.allowed) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center p-6">
        <div className="w-full max-w-sm bg-surface border border-border rounded-xl p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-danger/10 text-danger flex items-center justify-center mx-auto mb-4">
            <IconAlert size={24} />
          </div>
          <h1 className="text-lg font-semibold text-text mb-2">Access restricted</h1>
          <p className="text-xs text-muted mb-6">
            {lastAccessCheck.reason || 'Outside authorized working hours or location'}
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => logout()}
              className="flex-1 h-10 border border-border text-text rounded-lg text-sm font-medium hover:bg-surface-2 transition-colors"
            >
              Log out
            </button>
            <button
              type="button"
              onClick={handleRetryAccess}
              disabled={retryingAccess}
              className="flex-1 h-10 bg-accent text-accent-contrast rounded-lg text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50"
            >
              {retryingAccess ? 'Checking...' : 'Retry'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg flex">
      {/* Left Sidebar (Tablet & Desktop: >=768px) */}
      {!isMobile && (
        <aside className="w-64 bg-surface border-r border-border hidden md:flex flex-col justify-between shrink-0 h-screen sticky top-0">
          <div>
            {/* Brand Header */}
            <div className="p-5 flex items-center gap-3 border-b border-border/60">
              <div className="w-8 h-8 rounded-lg bg-accent text-accent-contrast flex items-center justify-center font-bold text-base">
                S
              </div>
              <span className="font-semibold text-text text-base">SARAL</span>
              <span className="text-[10px] font-semibold bg-surface-2 text-muted px-2 py-0.5 rounded ml-auto">
                Testnet
              </span>
            </div>

            {/* Navigation Links */}
            <nav className="p-3 flex flex-col gap-1">
              <NavLink
                to="/wallet"
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-accent/10 text-accent font-semibold'
                      : 'text-muted hover:bg-surface-2 hover:text-text'
                  }`
                }
              >
                <IconWallet />
                <span>Wallet</span>
              </NavLink>
              <NavLink
                to="/activity"
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-accent/10 text-accent font-semibold'
                      : 'text-muted hover:bg-surface-2 hover:text-text'
                  }`
                }
              >
                <IconActivity />
                <span>Activity</span>
              </NavLink>
              <NavLink
                to="/settings"
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-accent/10 text-accent font-semibold'
                      : 'text-muted hover:bg-surface-2 hover:text-text'
                  }`
                }
              >
                <IconSettings />
                <span>Settings</span>
              </NavLink>
            </nav>
          </div>

          {/* Footer: User + Theme + Sign Out */}
          <div className="p-4 border-t border-border/60 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted">Theme</span>
              <div className="flex bg-surface-2 p-0.5 rounded-full border border-border">
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`text-xs px-2.5 py-1 rounded-full font-medium transition-colors ${
                    theme === 'light' ? 'bg-surface text-text shadow-sm' : 'text-muted'
                  }`}
                >
                  Light
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`text-xs px-2.5 py-1 rounded-full font-medium transition-colors ${
                    theme === 'dark' ? 'bg-surface text-text shadow-sm' : 'text-muted'
                  }`}
                >
                  Dark
                </button>
              </div>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <Avatar seed={displayName} size="md" />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-text truncate">{displayName}</div>
                {displaySub && (
                  <div className="text-[11px] text-muted truncate" title={displaySub}>
                    {displaySub}
                  </div>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={() => logout()}
              className="w-full h-8 text-xs font-medium text-danger hover:bg-danger/10 rounded-lg transition-colors"
            >
              Log out
            </button>
          </div>
        </aside>
      )}

      {/* Main Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Mobile Topbar (<768px) */}
        {isMobile && (
          <header className="h-14 bg-surface border-b border-border px-4 flex items-center justify-between sticky top-0 z-20 md:hidden">
            {/* Left: SARAL Brand Header */}
            <Link to="/wallet" className="flex items-center gap-2.5 shrink-0">
              <div className="w-7 h-7 rounded-lg bg-accent text-accent-contrast flex items-center justify-center font-bold text-sm">
                S
              </div>
              <span className="font-semibold text-text text-base">SARAL</span>
              <span className="text-[10px] font-semibold bg-surface-2 text-muted px-1.5 py-0.5 rounded">
                Testnet
              </span>
            </Link>

            {/* Right: User Profile */}
            <div className="flex items-center gap-2 min-w-0">
              <div className="flex flex-col items-end min-w-0">
                <span className="font-semibold text-text text-xs truncate max-w-[120px]">
                  {displayName}
                </span>
                {displaySub && (
                  <span className="text-[10px] text-muted truncate max-w-[120px]" title={displaySub}>
                    {displaySub}
                  </span>
                )}
              </div>
              <Avatar seed={displayName} size="sm" />
            </div>
          </header>
        )}

        {/* Content Area */}
        <main className="flex-1 w-full max-w-5xl mx-auto p-4 sm:p-6 md:p-8 pb-20 md:pb-8">
          <Outlet />
        </main>

        {/* Mobile Bottom Tabbar (<768px) */}
        {isMobile && (
          <nav className="fixed bottom-0 inset-x-0 h-14 bg-surface border-t border-border flex items-center justify-around z-20 pb-[env(safe-area-inset-bottom)] md:hidden">
            <NavLink
              to="/wallet"
              className={({ isActive }) =>
                `flex flex-col items-center gap-1 text-[11px] font-medium ${
                  isActive ? 'text-accent font-semibold' : 'text-muted'
                }`
              }
            >
              <IconWallet size={18} />
              <span>Wallet</span>
            </NavLink>
            <NavLink
              to="/activity"
              className={({ isActive }) =>
                `flex flex-col items-center gap-1 text-[11px] font-medium ${
                  isActive ? 'text-accent font-semibold' : 'text-muted'
                }`
              }
            >
              <IconActivity size={18} />
              <span>Activity</span>
            </NavLink>
            <NavLink
              to="/settings"
              className={({ isActive }) =>
                `flex flex-col items-center gap-1 text-[11px] font-medium ${
                  isActive ? 'text-accent font-semibold' : 'text-muted'
                }`
              }
            >
              <IconSettings size={18} />
              <span>Settings</span>
            </NavLink>
          </nav>
        )}
      </div>
    </div>
  );
};
