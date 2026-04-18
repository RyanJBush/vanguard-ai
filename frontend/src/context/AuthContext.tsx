import { createContext, useContext, useEffect, useMemo, useState } from 'react';

import { api } from '../services/api';
import { authStorage } from '../services/authStorage';
import type { UserContext } from '../types/api';

interface AuthState {
  token: string | null;
  user: UserContext | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(authStorage.getToken());
  const [user, setUser] = useState<UserContext | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function hydrate() {
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const me = await api.me(token);
        setUser(me);
      } catch {
        authStorage.clear();
        setToken(null);
      } finally {
        setIsLoading(false);
      }
    }

    void hydrate();
  }, [token]);

  const value = useMemo(
    () => ({
      token,
      user,
      isLoading,
      async login(username: string, password: string) {
        const response = await api.login(username, password);
        authStorage.setToken(response.access_token);
        setToken(response.access_token);
        const me = await api.me(response.access_token);
        setUser(me);
      },
      logout() {
        authStorage.clear();
        setToken(null);
        setUser(null);
      },
    }),
    [isLoading, token, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
