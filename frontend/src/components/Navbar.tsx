import React from 'react';
import { NavLink, Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export const Navbar: React.FC = () => {
  const { isAuthenticated, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const isAuthRoute = location.pathname === '/login' || location.pathname === '/mfa';
  const showNav = isAuthenticated && !isAuthRoute;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="navbar">
      <Link to="/" className="brand">
        SARAL
      </Link>

      {showNav && (
        <nav className="nav-links">
          <NavLink
            to="/wallet"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Wallet
          </NavLink>
          <NavLink
            to="/activity"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Activity
          </NavLink>
          <NavLink
            to="/settings"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Settings
          </NavLink>
          <button type="button" onClick={handleLogout} className="btn-link nav-link">
            Logout
          </button>
        </nav>
      )}
    </header>
  );
};

export default Navbar;
