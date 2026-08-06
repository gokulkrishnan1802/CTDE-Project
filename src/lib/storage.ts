import type { User, Investigation, ChatMessage } from '../types';

const USERS_KEY = 'ctde_users';
const SESSION_KEY = 'ctde_session';
const INVESTIGATIONS_KEY = 'ctde_investigations';
const CHAT_KEY_PREFIX = 'ctde_chat_';

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown): void {
  localStorage.setItem(key, JSON.stringify(value));
}

function uid(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// ---- Users ----
export const userStore = {
  getAll: (): User[] => read<User[]>(USERS_KEY, []),
  findByUsername: (username: string): User | undefined =>
    userStore.getAll().find(u => u.username.toLowerCase() === username.toLowerCase()),
  findByEmail: (email: string): User | undefined =>
    userStore.getAll().find(u => u.email.toLowerCase() === email.toLowerCase()),
  create: (data: Omit<User, 'id' | 'createdAt'>): User => {
    const user: User = { ...data, id: uid(), createdAt: new Date().toISOString() };
    const users = userStore.getAll();
    users.push(user);
    write(USERS_KEY, users);
    return user;
  },
  remove: (id: string): void => {
    write(USERS_KEY, userStore.getAll().filter(u => u.id !== id));
  },
  updatePassword: (id: string, password: string): void => {
    const users = userStore.getAll();
    const u = users.find(x => x.id === id);
    if (u) {
      u.password = password;
      write(USERS_KEY, users);
    }
  },
};

// ---- Session ----
export const sessionStore = {
  get: (): string | null => localStorage.getItem(SESSION_KEY),
  set: (userId: string): void => localStorage.setItem(SESSION_KEY, userId),
  clear: (): void => localStorage.removeItem(SESSION_KEY),
};

// ---- Investigations ----
export const investigationStore = {
  getAll: (): Investigation[] => read<Investigation[]>(INVESTIGATIONS_KEY, []),
  getByUser: (userId: string): Investigation[] =>
    investigationStore.getAll().filter(i => i.userId === userId),
  create: (data: Omit<Investigation, 'id' | 'createdAt' | 'userId'> & { userId: string }): Investigation => {
    const inv: Investigation = {
      ...data,
      id: uid(),
      createdAt: new Date().toISOString(),
    };
    const all = investigationStore.getAll();
    all.push(inv);
    write(INVESTIGATIONS_KEY, all);
    return inv;
  },
  getById: (id: string): Investigation | undefined =>
    investigationStore.getAll().find(i => i.id === id),
  remove: (id: string): void => {
    write(INVESTIGATIONS_KEY, investigationStore.getAll().filter(i => i.id !== id));
  },
};

// ---- Chat (per investigation) ----
export const chatStore = {
  get: (investigationId: string): ChatMessage[] =>
    read<ChatMessage[]>(CHAT_KEY_PREFIX + investigationId, []),
  save: (investigationId: string, messages: ChatMessage[]): void =>
    write(CHAT_KEY_PREFIX + investigationId, messages),
  clear: (investigationId: string): void =>
    localStorage.removeItem(CHAT_KEY_PREFIX + investigationId),
};
