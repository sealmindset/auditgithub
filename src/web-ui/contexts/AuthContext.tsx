"use client";

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { API_BASE } from "@/lib/api";
import { meetsMinimumRole, type RoleName } from "@/lib/rbac";

// ── Types ──────────────────────────────────────────────────────────

export interface AuthUser {
  sub: string;
  email: string;
  name: string;
  role: RoleName;
  access_type: string;
  is_break_glass: boolean;
}

export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  user: AuthUser | null;
  status: AuthStatus;
  isAuthenticated: boolean;
  isLoading: boolean;
  /** Returns true when the current user meets at least `minimumRole`. */
  hasRole: (minimumRole: RoleName) => boolean;
  /** Signs out and redirects to /login. */
  logout: () => Promise<void>;
  /** Re-fetches /auth/me (e.g. after role change). */
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// ── Provider ───────────────────────────────────────────────────────

const SESSION_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<AuthStatus>("loading");
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMe = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        credentials: "include",
      });

      if (res.ok) {
        const data = await res.json();
        setUser({
          sub: data.sub ?? data.id ?? "",
          email: data.email ?? "",
          name: data.name ?? data.email ?? "",
          role: data.role ?? "user",
          access_type: data.access_type ?? "full",
          is_break_glass: data.is_break_glass ?? false,
        });
        setStatus("authenticated");
      } else if (res.status === 401) {
        setUser(null);
        setStatus("unauthenticated");
      } else {
        // Unexpected status – don't change state to avoid logout loops
        console.warn(`[auth] /auth/me returned ${res.status}`);
      }
    } catch (err) {
      // Network error – log but don't change state (prevents logout loops)
      console.warn("[auth] failed to reach /auth/me", err);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchMe();
  }, [fetchMe]);

  // Periodic session check
  useEffect(() => {
    intervalRef.current = setInterval(fetchMe, SESSION_CHECK_INTERVAL);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchMe]);

  const logout = useCallback(async () => {
    try {
      await fetch(`${API_BASE}/auth/logout`, { credentials: "include" });
    } catch {
      // Best-effort – redirect regardless
    }
    setUser(null);
    setStatus("unauthenticated");
    window.location.href = "/login";
  }, []);

  const hasRole = useCallback(
    (minimumRole: RoleName) => {
      if (!user) return false;
      return meetsMinimumRole(user.role, minimumRole);
    },
    [user],
  );

  const value: AuthContextValue = {
    user,
    status,
    isAuthenticated: status === "authenticated",
    isLoading: status === "loading",
    hasRole,
    logout,
    refreshUser: fetchMe,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ── Hook ───────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
