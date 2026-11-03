import React from 'react';
import { useAuth } from '../hooks/useAuth';

export const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();

  return (
    <header className="navbar">
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <span className="brand">SARAL Wallet</span>
        <span className="brand-tag">Cryptographic Key Management</span>
      </div>
      {isAuthenticated && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            {user?.email || (user?.loginMethod === 'google' ? 'Google Account' : user?.mobile || 'Authenticated')}
          </span>
          <button onClick={logout} className="btn btn-outline btn-sm">
            Logout
          </button>
        </div>
      )}
    </header>
  );
};
