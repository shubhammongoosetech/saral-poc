import { useState, useEffect } from 'react';
import { User } from '../api/endpoints';

export function useAuth() {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const saved = localStorage.getItem('saral_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('saral_token');
  });

  const setSession = (newToken: string, newUser: User) => {
    localStorage.setItem('saral_token', newToken);
    localStorage.setItem('saral_user', JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
  };

  const updateToken = (newToken: string) => {
    localStorage.setItem('saral_token', newToken);
    setToken(newToken);
  };

  const logout = () => {
    localStorage.removeItem('saral_token');
    localStorage.removeItem('saral_user');
    setToken(null);
    setUser(null);
    window.location.href = '/login';
  };

  return {
    user,
    token,
    isAuthenticated: !!token,
    setSession,
    updateToken,
    logout,
  };
}
