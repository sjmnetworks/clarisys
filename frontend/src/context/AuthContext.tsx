import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

export type Role = "admin" | "auditor" | "viewer";

export interface User {
  sub: string;
  username: string;
  email: string;
  role: Role;
  scopes: string[];
  tenant_id: string;
  tenant_name: string;
}

interface AuthState {
  user: User | null;
  apiKey: string | null;
  token: string | null;
  login: (apiKey: string) => Promise<void>;
  loginWithCredentials: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string, organization?: string) => Promise<void>;
  loginWithGoogle: (idToken: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const saved = sessionStorage.getItem("clarisys_user");
    return saved ? JSON.parse(saved) : null;
  });
  const [apiKey, setApiKey] = useState<string | null>(
    () => sessionStorage.getItem("clarisys_api_key"),
  );
  const [token, setToken] = useState<string | null>(
    () => sessionStorage.getItem("clarisys_token"),
  );

  const _setSession = useCallback((userData: User, opts: { apiKey?: string; token?: string }) => {
    sessionStorage.setItem("clarisys_user", JSON.stringify(userData));
    if (opts.apiKey) {
      sessionStorage.setItem("clarisys_api_key", opts.apiKey);
      setApiKey(opts.apiKey);
    }
    if (opts.token) {
      sessionStorage.setItem("clarisys_token", opts.token);
      setToken(opts.token);
    }
    setUser(userData);
  }, []);

  // Legacy API key login
  const login = useCallback(async (key: string) => {
    const resp = await fetch("/api/policy/metadata", {
      headers: { "x-api-key": key },
    });
    if (!resp.ok) {
      throw new Error(resp.status === 401 ? "Invalid API key" : `Server error (${resp.status})`);
    }

    const whoami = await fetch("/api/auth/whoami", {
      headers: { "x-api-key": key },
    });
    let userData: User;
    if (whoami.ok) {
      const info = await whoami.json();
      userData = {
        sub: info.sub || "",
        username: info.username || "user",
        email: info.email || "",
        role: deriveRole(info.scopes || []),
        scopes: info.scopes || [],
        tenant_id: info.tenant_id || "",
        tenant_name: info.tenant_name || "",
      };
    } else {
      userData = {
        sub: "",
        username: "pilot-user",
        email: "",
        role: "auditor",
        scopes: ["firewall.evaluate", "firewall.audit"],
        tenant_id: "",
        tenant_name: "",
      };
    }
    _setSession(userData, { apiKey: key });
  }, [_setSession]);

  // Email / password login
  const loginWithCredentials = useCallback(async (email: string, password: string) => {
    const resp = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({ detail: "Login failed" }));
      throw new Error(body.detail || "Login failed");
    }
    const data = await resp.json();
    const userData: User = {
      sub: data.user.sub || "",
      username: data.user.username,
      email: data.user.email,
      role: deriveRole(data.user.scopes || []),
      scopes: data.user.scopes || [],
      tenant_id: data.user.tenant_id || "",
      tenant_name: data.user.tenant_name || "",
    };
    _setSession(userData, { token: data.token });
  }, [_setSession]);

  // Register
  const register = useCallback(async (email: string, username: string, password: string, organization?: string) => {
    const resp = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, username, password, organization: organization || "" }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({ detail: "Registration failed" }));
      throw new Error(body.detail || "Registration failed");
    }
    const data2 = await resp.json();
    const regUser: User = {
      sub: data2.user.sub || "",
      username: data2.user.username,
      email: data2.user.email,
      role: deriveRole(data2.user.scopes || []),
      scopes: data2.user.scopes || [],
      tenant_id: data2.user.tenant_id || "",
      tenant_name: data2.user.tenant_name || "",
    };
    _setSession(regUser, { token: data2.token });
  }, [_setSession]);

  // Google SSO
  const loginWithGoogle = useCallback(async (idToken: string) => {
    const resp = await fetch("/api/auth/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id_token: idToken }),
    });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({ detail: "Google login failed" }));
      throw new Error(body.detail || "Google login failed");
    }
    const data3 = await resp.json();
    const gUser: User = {
      sub: data3.user.sub || "",
      username: data3.user.username,
      email: data3.user.email,
      role: deriveRole(data3.user.scopes || []),
      scopes: data3.user.scopes || [],
      tenant_id: data3.user.tenant_id || "",
      tenant_name: data3.user.tenant_name || "",
    };
    _setSession(gUser, { token: data3.token });
  }, [_setSession]);

  const logout = useCallback(() => {
    sessionStorage.removeItem("clarisys_api_key");
    sessionStorage.removeItem("clarisys_user");
    sessionStorage.removeItem("clarisys_token");
    setApiKey(null);
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, apiKey, token, login, loginWithCredentials, register, loginWithGoogle, logout, isAuthenticated: !!user }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside AuthProvider");
  return ctx;
}

function deriveRole(scopes: string[]): Role {
  if (scopes.includes("firewall.admin")) return "admin";
  if (scopes.includes("firewall.audit")) return "auditor";
  return "viewer";
}
