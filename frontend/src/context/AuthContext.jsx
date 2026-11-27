import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { authApi } from '../api/services';
import {
  clearStoredToken,
  getStoredToken,
  setStoredToken,
} from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return null;
    }

    try {
      const profile = await authApi.me();
      setUser(profile);
      return profile;
    } catch {
      clearStoredToken();
      setUser(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();

    const onUnauthorized = () => {
      clearStoredToken();
      setUser(null);
    };
    window.addEventListener('ransomwatch:unauthorized', onUnauthorized);
    return () => {
      window.removeEventListener('ransomwatch:unauthorized', onUnauthorized);
    };
  }, [loadUser]);

  const login = async (identifier, password) => {
    const data = await authApi.login(identifier, password);
    setStoredToken(data.access_token);
    const profile = await authApi.me();
    setUser(profile);
    return profile;
  };

  const register = async (payload) => {
    return authApi.register(payload);
  };

  const logout = async () => {
    try {
      if (getStoredToken()) {
        await authApi.logout();
      }
    } catch {
      // Token may already be expired; proceed to clear local state cleanly.
    } finally {
      clearStoredToken();
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: Boolean(user),
        isAdmin: user?.role === 'admin',
        login,
        register,
        logout,
        refreshProfile: loadUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside an AuthProvider');
  }
  return ctx;
}
