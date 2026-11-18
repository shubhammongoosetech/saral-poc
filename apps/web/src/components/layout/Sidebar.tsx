import React from 'react';
import { NavigationTab } from '../../types';

interface SidebarProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  walletCount?: number;
  dkgSessionCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  walletCount = 0,
  dkgSessionCount = 0,
}) => {
  const navItems: Array<{
    id: NavigationTab;
    label: string;
    icon: string;
    badge?: number | string;
    highlight?: boolean;
  }> = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'network', label: 'Network & Nodes', icon: '🌐' },
    { id: 'dkg-sessions', label: 'DKG Sessions', icon: '🔐', badge: dkgSessionCount > 0 ? dkgSessionCount : undefined },
    { id: 'key-management', label: 'Key Management', icon: '🔑' },
    { id: 'create-wallet', label: 'Create Wallet', icon: '✨', highlight: true },
    { id: 'wallets', label: 'My Wallets', icon: '💼', badge: walletCount > 0 ? walletCount : undefined },
    { id: 'proactive-refresh', label: 'Proactive Refresh', icon: '⚡' },
    { id: 'audit-logs', label: 'Security & Audit Logs', icon: '🛡️' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <aside style={{
      width: '260px',
      backgroundColor: '#0c121e',
      borderRight: '1px solid #1e293b',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
      flexShrink: 0,
    }}>
      {/* Brand Logo Header */}
      <div style={{
        padding: '20px 20px 16px 20px',
        borderBottom: '1px solid #1e293b',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
      }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, #0284c7 0%, #6366f1 100%)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '18px',
          boxShadow: '0 4px 12px rgba(2, 132, 199, 0.3)',
        }}>
          🛡️
        </div>
        <div>
          <div style={{ fontWeight: 800, fontSize: '16px', letterSpacing: '0.5px', color: '#f8fafc' }}>
            SARAL V3
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 500 }}>
            Separation-of-Powers Web3
          </div>
        </div>
      </div>

      {/* Main Navigation Links */}
      <nav style={{ padding: '16px 12px', flex: 1, overflowY: 'auto' }}>
        <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '1px', color: '#64748b', fontWeight: 700, padding: '0 12px 8px 12px' }}>
          Navigation
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 12px',
                  borderRadius: '6px',
                  border: 'none',
                  backgroundColor: isActive
                    ? item.highlight ? '#1d4ed8' : '#1e293b'
                    : 'transparent',
                  color: isActive ? '#ffffff' : '#94a3b8',
                  fontSize: '13px',
                  fontWeight: isActive ? 600 : 500,
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease-in-out',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '15px' }}>{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: '10px',
                    backgroundColor: isActive ? 'rgba(255,255,255,0.2)' : '#1e293b',
                    color: isActive ? '#ffffff' : '#38bdf8',
                  }}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </nav>

      {/* Security Status Footnote */}
      <div style={{
        padding: '14px 16px',
        borderTop: '1px solid #1e293b',
        backgroundColor: '#090d16',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981' }} />
          <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 600 }}>TLS 1.3 / mTLS Mesh</span>
        </div>
        <div style={{ fontSize: '10px', color: '#64748b', lineHeight: '1.4' }}>
          Zero centralized dealer. Master key reconstruction is strictly disabled.
        </div>
      </div>
    </aside>
  );
};
