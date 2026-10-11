import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Role, User } from "../types";
import { api, tokenStore } from "./api";

export type Perm = "create_task" | "inspect" | "approve" | "manage";

// UI-only convenience: the server enforces every permission independently.
const PERMS: Record<Role, Perm[]> = {
  VIEWER: [],
  DEVELOPER: ["inspect", "create_task"],
  APPROVER: ["inspect", "approve"],
  ADMIN: ["inspect", "create_task", "approve", "manage"],
};

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  can: (p: Perm) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => { tokenStore.clear(); setUser(null); }, []);

  useEffect(() => {
    if (!tokenStore.get()) { setLoading(false); return; }
    api.get<User>("/auth/me").then(setUser).catch(() => tokenStore.clear()).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    window.addEventListener("aesa:unauthorized", logout);
    return () => window.removeEventListener("aesa:unauthorized", logout);
  }, [logout]);

  const login = useCallback(async (username: string, password: string) => {
    const r = await api.post<{ access_token: string; user: User }>("/auth/login", { username, password });
    tokenStore.set(r.access_token);
    setUser(r.user);
  }, []);

  const value = useMemo<AuthState>(() => ({
    user, loading, login, logout, can: (p) => !!user && PERMS[user.role].includes(p),
  }), [user, loading, login, logout]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
