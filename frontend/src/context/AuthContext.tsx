import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

export type Role = "admin" | "auditor" | "viewer";

export interface User {
  username: string;
  email: string;
  role: Role;
  scopes: string[];
}

interface AuthState {
  user: User | null;
  apiKey: string | null;
  login: (apiKey: string) => Promise<void>;
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

  const login = useCallback(async (key: string) => {
    // Validate key by hitting a lightweight authenticated endpoint
    const resp = await fetch("/api/policy/metadata", {
      headers: { "x-api-key": key },
    });
    if (!resp.ok) {
      throw new Error(resp.status === 401 ? "Invalid API key" : `Server error (${resp.status})`);
    }

    // Derive user info from the whoami-style endpoint
    const whoami = await fetch("/api/auth/whoami", {
      headers: { "x-api-key": key },
    });
    let userData: User;
    if (whoami.ok) {
      const info = await whoami.json();
      userData = {
        username: info.username || "user",
        email: info.email || "",
        role: deriveRole(info.scopes || []),
        scopes: info.scopes || [],
      };
    } else {
      // Fallback: key works but no whoami endpoint yet
      userData = {
        username: "pilot-user",
        email: "",
        role: "auditor",
        scopes: ["firewall.evaluate", "firewall.audit"],
      };
    }

    sessionStorage.setItem("clarisys_api_key", key);
    sessionStorage.setItem("clarisys_user", JSON.stringify(userData));
    setApiKey(key);
    setUser(userData);
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem("clarisys_api_key");
    sessionStorage.removeItem("clarisys_user");
    setApiKey(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, apiKey, login, logout, isAuthenticated: !!user }}
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
