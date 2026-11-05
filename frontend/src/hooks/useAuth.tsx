import React, { createContext, useContext, useState } from 'react';
import { User } from '../api/endpoints';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  setSession: (newToken: string, newUser: User) => void;
  updateToken: (newToken: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
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
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token,
        setSession,
        updateToken,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
