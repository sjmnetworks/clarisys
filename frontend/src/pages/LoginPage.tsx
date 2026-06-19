import { useState, type FormEvent } from "react";
import { useAuth } from "../context/AuthContext";
import { useNavigate, Link } from "react-router-dom";

type AuthMode = "email" | "apikey";

export default function LoginPage() {
  const { login, loginWithCredentials } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<AuthMode>("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleEmailLogin = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await loginWithCredentials(email.trim(), password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleApiKeyLogin = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(apiKey.trim());
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <span className="login-logo">C</span>
          <h1>Clarisys</h1>
          <p>Firewall Compliance Platform</p>
        </div>

        <div className="auth-tabs">
          <button className={mode === "email" ? "active" : ""} onClick={() => { setMode("email"); setError(""); }}>
            Email
          </button>
          <button className={mode === "apikey" ? "active" : ""} onClick={() => { setMode("apikey"); setError(""); }}>
            API Key
          </button>
        </div>

        {mode === "email" ? (
          <>
            <form onSubmit={handleEmailLogin}>
              <div className="form-group">
                <label htmlFor="email">Email</label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  autoFocus
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </div>
              {error && <div className="form-error">{error}</div>}
              <button type="submit" className="btn-primary btn-full" disabled={loading || !email.trim() || !password}>
                {loading ? "Signing in..." : "Sign in"}
              </button>
            </form>

            <p className="login-footer">
              Don&apos;t have an account? <Link to="/register">Register</Link>
            </p>
          </>
        ) : (
          <>
            <form onSubmit={handleApiKeyLogin}>
              <div className="form-group">
                <label htmlFor="apiKey">API Key</label>
                <input
                  id="apiKey"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter your API key"
                  autoFocus
                  required
                />
              </div>
              {error && <div className="form-error">{error}</div>}
              <button type="submit" className="btn-primary btn-full" disabled={loading || !apiKey.trim()}>
                {loading ? "Authenticating..." : "Sign in"}
              </button>
            </form>
            <p className="login-footer">
              Contact your administrator for an API key.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
