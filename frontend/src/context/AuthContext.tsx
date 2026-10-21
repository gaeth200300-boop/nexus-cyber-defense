import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  AUTH_EVENT,
  ApiError,
  apiFetch,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  notifyAuthChanged,
  saveTokens
} from "../lib/api";
import type { AuthTokens, User } from "../types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  bootstrapRequired: boolean;
  bootstrapEmail: string;
  selfRegistration: boolean;
  authMethod: string;
  login: (email: string, password: string, totpCode?: string) => Promise<void>;
  register: (email: string, fullName: string, password: string) => Promise<void>;
  bootstrap: (email: string, fullName: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshMe: () => Promise<User | null>;
  setUser: (user: User | null) => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

interface MeResponse {
  user: User;
  auth_method: string;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUserState] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [bootstrapRequired, setBootstrapRequired] = useState(false);
  const [bootstrapEmail, setBootstrapEmail] = useState("");
  const [selfRegistration, setSelfRegistration] = useState(true);
  const [authMethod, setAuthMethod] = useState("password");
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const loadMe = useCallback(async (): Promise<User | null> => {
    if (!getAccessToken() && !getRefreshToken()) return null;
    try {
      const response = await apiFetch<MeResponse>("/auth/me");
      if (mounted.current) {
        setUserState(response.user);
        setAuthMethod(response.auth_method || "password");
      }
      return response.user;
    } catch {
      clearTokens();
      if (mounted.current) setUserState(null);
      return null;
    }
  }, []);

  const checkBootstrap = useCallback(async () => {
    try {
      const response = await apiFetch<{
        bootstrap_required: boolean;
        accounts: number;
        admin_email: string;
        self_registration?: boolean;
      }>("/auth/bootstrap", { auth: false });
      if (!mounted.current) return;
      setBootstrapRequired(response.bootstrap_required);
      setBootstrapEmail(response.admin_email || "");
      setSelfRegistration(response.self_registration ?? true);
    } catch {
      if (mounted.current) setBootstrapRequired(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await checkBootstrap();
      const loaded = await loadMe();
      if (!cancelled && mounted.current) {
        if (!loaded) setUserState(null);
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [checkBootstrap, loadMe]);

  useEffect(() => {
    const handleAuthEvent = () => {
      if (!getAccessToken() && !getRefreshToken()) {
        setUserState(null);
        queryClient.clear();
      }
    };
    window.addEventListener(AUTH_EVENT, handleAuthEvent);
    return () => window.removeEventListener(AUTH_EVENT, handleAuthEvent);
  }, [queryClient]);

  const login = useCallback(
    async (email: string, password: string, totpCode?: string) => {
      const tokens = await apiFetch<AuthTokens>("/auth/login", {
        method: "POST",
        auth: false,
        body: {
          email: email.trim(),
          password,
          totp_code: totpCode?.trim() || undefined
        }
      });
      saveTokens(tokens);
      setUserState(tokens.user);
      setAuthMethod("password");
      setBootstrapRequired(false);
      notifyAuthChanged();
    },
    []
  );

  const bootstrap = useCallback(async (email: string, fullName: string, password: string) => {
    const tokens = await apiFetch<AuthTokens>("/auth/bootstrap", {
      method: "POST",
      auth: false,
      body: { email: email.trim(), full_name: fullName.trim(), password }
    });
    saveTokens(tokens);
    setUserState(tokens.user);
    setBootstrapRequired(false);
    setAuthMethod("password");
    notifyAuthChanged();
  }, []);

  const register = useCallback(
    async (email: string, fullName: string, password: string) => {
      await apiFetch<{ ok: boolean; user: User; message: string }>("/auth/register", {
        method: "POST",
        auth: false,
        body: { email: email.trim(), full_name: fullName.trim(), password }
      });
      // Self-registration returns no tokens; sign the new viewer in right away.
      await login(email, password);
    },
    [login]
  );

  const logout = useCallback(async () => {
    try {
      if (getAccessToken()) await apiFetch<void>("/auth/logout", { method: "POST" });
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500) {
        // Local state is still cleared; logout must never trap the user.
        console.warn("Logout request failed", error);
      }
    } finally {
      clearTokens();
      setUserState(null);
      queryClient.clear();
      notifyAuthChanged();
    }
  }, [queryClient]);

  const refreshMe = useCallback(async () => {
    const next = await loadMe();
    if (next) setBootstrapRequired(false);
    return next;
  }, [loadMe]);

  const setUser = useCallback((next: User | null) => setUserState(next), []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      bootstrapRequired,
      bootstrapEmail,
      selfRegistration,
      authMethod,
      login,
      register,
      bootstrap,
      logout,
      refreshMe,
      setUser
    }),
    [user, loading, bootstrapRequired, bootstrapEmail, selfRegistration, authMethod, login, register, bootstrap, logout, refreshMe, setUser]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
