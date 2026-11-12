import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { apiClient as api } from '../../api/client';

interface AccountSectionProps {
  user?: {
    id: string;
    name?: string;
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
      ? 'Google Sign-In'
      : 'Mobile OTP';

  return (
    <div>
      <h2 className="section-title">Account</h2>

      <div className="two-column-list">
        {user?.name && (
          <div className="two-column-item">
            <span className="label-col">Name</span>
            <span className="value-col">{user.name}</span>
          </div>
        )}
        {user?.email && (
          <div className="two-column-item">
            <span className="label-col">Email</span>
            <span className="value-col">{user.email}</span>
          </div>
        )}
        {user?.mobile && (
          <div className="two-column-item">
            <span className="label-col">Mobile</span>
            <span className="value-col">{user.mobile}</span>
          </div>
        )}
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

