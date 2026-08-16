import {
  createContext,
  useContext,
  useState,
  useEffect,
  type ReactNode,
} from 'react';

import type { User } from '../types';

import {
  registerUser,
  loginUser,
  getCurrentUser,
  saveAuthToken,
  clearAuthToken,
  getAuthToken,
} from '../services/api';


interface AuthContextValue {
  user: User | null;

  login: (
    email: string,
    password: string
  ) => Promise<{ ok: boolean; error?: string }>;

  register: (
    data: {
      fullName: string;
      email: string;
      username: string;
      password: string;
    }
  ) => Promise<{ ok: boolean; error?: string }>;

  logout: () => void;

  deleteAccount: () => void;
}


const AuthContext = createContext<AuthContextValue | null>(null);


function mapAuthUserToUser(user: {
  id: string;
  full_name: string;
  email: string;
  username: string;
  created_at: string;
}): User {
  return {
    id: user.id,
    fullName: user.full_name,
    email: user.email,
    username: user.username,
    password: '',
    createdAt: user.created_at,
  };
}


export function AuthProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);


  // ── Restore authenticated user when application starts ─────────────────────
  useEffect(() => {
    const restoreSession = async () => {
      const token = getAuthToken();

      if (!token) {
        return;
      }

      try {
        const currentUser = await getCurrentUser();
        setUser(mapAuthUserToUser(currentUser));
      } catch {
        // Token is invalid/expired.
        clearAuthToken();
        setUser(null);
      }
    };

    restoreSession();
  }, []);


  // ── Login ──────────────────────────────────────────────────────────────────
  const login: AuthContextValue['login'] = async (
    email,
    password
  ) => {
    try {
      const response = await loginUser({
        email: email.trim(),
        password,
      });

      saveAuthToken(response.access_token);

      setUser(mapAuthUserToUser(response.user));

      return { ok: true };
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'Login failed.';

      return {
        ok: false,
        error: message,
      };
    }
  };


  // ── Register ───────────────────────────────────────────────────────────────
  const register: AuthContextValue['register'] = async (
    data
  ) => {
    try {
      const response = await registerUser({
        full_name: data.fullName.trim(),
        email: data.email.trim(),
        username: data.username.trim(),
        password: data.password,
      });

      saveAuthToken(response.access_token);

      setUser(mapAuthUserToUser(response.user));

      return { ok: true };
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'Registration failed.';

      return {
        ok: false,
        error: message,
      };
    }
  };


  // ── Logout ─────────────────────────────────────────────────────────────────
  const logout = () => {
    clearAuthToken();
    setUser(null);
  };


  // ── Delete account ─────────────────────────────────────────────────────────
  // Backend delete-account API is not implemented yet.
  // For now, this safely clears the current authentication session.
  const deleteAccount = () => {
    clearAuthToken();
    setUser(null);
  };


  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        register,
        logout,
        deleteAccount,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}


export function useAuth() {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error(
      'useAuth must be used within AuthProvider'
    );
  }

  return ctx;
}