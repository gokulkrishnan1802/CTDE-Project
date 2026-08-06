import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { User } from '../types';
import { userStore, sessionStore } from '../lib/storage';

interface AuthContextValue {
  user: User | null;
  login: (username: string, password: string) => { ok: boolean; error?: string };
  register: (data: { fullName: string; email: string; username: string; password: string }) => { ok: boolean; error?: string };
  logout: () => void;
  deleteAccount: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const sessionId = sessionStore.get();
    if (sessionId) {
      const found = userStore.getAll().find(u => u.id === sessionId);
      if (found) setUser(found);
      else sessionStore.clear();
    }
  }, []);

  const login: AuthContextValue['login'] = (username, password) => {
    const found = userStore.findByUsername(username);
    if (!found) return { ok: false, error: 'Username not found.' };
    if (found.password !== password) return { ok: false, error: 'Incorrect password.' };
    sessionStore.set(found.id);
    setUser(found);
    return { ok: true };
  };

  const register: AuthContextValue['register'] = (data) => {
    if (userStore.findByUsername(data.username)) return { ok: false, error: 'Username already exists.' };
    if (userStore.findByEmail(data.email)) return { ok: false, error: 'Email already registered.' };
    const created = userStore.create(data);
    sessionStore.set(created.id);
    setUser(created);
    return { ok: true };
  };

  const logout = () => {
    sessionStore.clear();
    setUser(null);
  };

  const deleteAccount = () => {
    if (user) {
      userStore.remove(user.id);
      sessionStore.clear();
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, deleteAccount }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
