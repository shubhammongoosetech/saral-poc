import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { apiClient as api } from '../../api/client';

interface AccountSectionProps {
  user?: {
    id: string;
    email?: string;
    mobile?: string;
    login_method: string;
    created_at: string;
  };
}

export const AccountSection: React.FC<AccountSectionProps> = ({ user }) => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleSignOutEverywhere = async () => {
    if (!window.confirm('Sign out everywhere? All active sessions will be terminated.')) {
      return;
    }
    try {
      await api.post('/auth/logout');
    } finally {
      logout();
      navigate('/login');
    }
  };

  const loginMethod =
    user?.login_method === 'google'
      ? `Google (${user.email || 'Connected'})`
      : `Mobile (${user?.mobile || 'Verified'})`;

  return (
    <div>
      <h2 className="section-title">Account</h2>

      <div className="two-column-list">
        <div className="two-column-item">
          <span className="label-col">Login method</span>
          <span className="value-col">{loginMethod}</span>
        </div>
        <div className="two-column-item">
          <span className="label-col">Registered</span>
          <span className="value-col">
            {user?.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}
          </span>
        </div>
      </div>

      <button
        type="button"
        onClick={handleSignOutEverywhere}
        className="btn btn-outline btn-danger"
      >
        Sign out everywhere
      </button>
    </div>
  );
};

export default AccountSection;

