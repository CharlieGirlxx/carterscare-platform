import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import type { DemoRole } from "./DemoContext";

type AppRole = "admin" | "manager" | "support_worker";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  user_metadata?: { display_name?: string; role?: string };
}

export interface AuthSession {
  user: AuthUser;
}

export interface ClientPortalSession {
  client_id: string;
  username: string;
  display_name: string;
}

interface AuthContextType {
  session: AuthSession | null;
  user: AuthUser | null;
  loading: boolean;
  role: AppRole | null;
  isAdmin: boolean;
  isManager: boolean;
  isSupportWorker: boolean;
  isClient: boolean;
  isDemoMode: boolean;
  demoRole: DemoRole | null;
  clientPortalSession: ClientPortalSession | null;
  signIn: (email: string, password: string) => Promise<string>;
  signInClientPortal: (username: string, accessCode: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options?.headers ?? {}) },
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? "Request failed");
  }
  return response.json();
}

function redirectForRole(role: AppRole | null) {
  return role === "support_worker" ? "/worker" : "/";
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState<AppRole | null>(null);

  useEffect(() => {
    request<{ user: AuthUser }>("/api/auth/session")
      .then(({ user }) => {
        setSession({ user });
        setRole(user.user_metadata?.role as AppRole | null);
      })
      .catch(() => {
        setSession(null);
        setRole(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const signIn = async (email: string, password: string) => {
    const { user } = await request<{ user: AuthUser }>("/api/auth/sign-in", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    const nextRole = user.user_metadata?.role as AppRole | null;
    setSession({ user });
    setRole(nextRole);
    return redirectForRole(nextRole);
  };

  const signInClientPortal = async () => {
    throw new Error("Client portal access is not enabled until an account is provisioned");
  };

  const signOut = async () => {
    await request("/api/auth/sign-out", { method: "POST" });
    setSession(null);
    setRole(null);
  };

  const user = session?.user ?? null;
  const isAdmin = role === "admin";
  const isManager = role === "admin" || role === "manager";
  const isSupportWorker = role === "support_worker";

  return (
    <AuthContext.Provider value={{
      session,
      user,
      loading,
      role,
      isAdmin,
      isManager,
      isSupportWorker,
      isClient: false,
      isDemoMode: false,
      demoRole: null,
      clientPortalSession: null,
      signIn,
      signInClientPortal,
      signOut,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
