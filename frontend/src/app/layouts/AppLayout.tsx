import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useSession } from '@/features/auth/useSession';
import { useBreakpoint } from '@/shared/hooks/useBreakpoint';
import { useTheme } from '@/shared/hooks/useTheme';
import { truncateAddress } from '@/shared/lib/format';
import { walletApi } from '@/shared/api/endpoints';
import { getCurrentCoords } from '@/shared/hooks/useLocation';
import { Avatar } from '@/shared/ui/Avatar';
import {
  IconWallet,
  IconActivity,
  IconSettings,
  IconCopy,
  IconCheck,
  IconAlert,
} from '@/shared/ui/icons';

export const AppLayout: React.FC = () => {
  const { user, logout, lastAccessCheck, setLastAccessCheck } = useSession();
  const { isMobile, isDesktop } = useBreakpoint();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();

  const [copied, setCopied] = useState(false);
  const [retryingAccess, setRetryingAccess] = useState(false);

  const displayName = user?.name || 'Account 1';
  const displayAddress = user?.id || '';

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  const handleRetryAccess = async () => {
    try {
      setRetryingAccess(true);
      const coords = await getCurrentCoords();
      const res = await walletApi.checkAccess(coords.lat, coords.lng);
      setLastAccessCheck(res);
      if (res.allowed) {
        navigate('/wallet');
      }
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
      {/* Desktop Left Sidebar (>=1024px) */}
      {isDesktop && (
        <aside className="w-64 bg-surface border-r border-border flex flex-col justify-between shrink-0 h-screen sticky top-0">
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
              <Avatar seed={displayAddress || 'saral'} size="md" />
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-text truncate">{displayName}</div>
                {displayAddress && (
                  <button
                    type="button"
                    onClick={() => handleCopy(displayAddress)}
                    className="flex items-center gap-1.5 text-[11px] font-mono text-muted hover:text-text"
                  >
                    <span>{truncateAddress(displayAddress)}</span>
                    {copied ? <IconCheck size={12} /> : <IconCopy size={12} />}
                  </button>
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
        {/* Mobile / Tablet Topbar */}
        {!isDesktop && (
          <header className="h-14 bg-surface border-b border-border px-4 flex items-center justify-between sticky top-0 z-20">
            <div className="flex items-center gap-2.5">
              <Avatar seed={displayAddress || 'saral'} size="sm" />
              <span className="font-semibold text-text text-sm truncate max-w-[140px]">
                {displayName}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-semibold bg-surface-2 text-muted px-2 py-0.5 rounded">
                Testnet
              </span>
            </div>
          </header>
        )}

        {/* Content Area */}
        <main className="flex-1 w-full max-w-5xl mx-auto p-4 sm:p-6 md:p-8 pb-20 md:pb-8">
          <Outlet />
        </main>

        {/* Mobile Bottom Tabbar (<768px) */}
        {isMobile && (
          <nav className="fixed bottom-0 inset-x-0 h-14 bg-surface border-t border-border flex items-center justify-around z-20 pb-[env(safe-area-inset-bottom)]">
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
