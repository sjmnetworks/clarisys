import { useEffect, useState } from "react";
import { useApi } from "../hooks/useApi";

interface PilotUser {
  username: string;
  email: string;
  scopes: string[];
  enabled: boolean;
  created_at: string;
  rotated_at?: string;
}

export default function AdminPage() {
  const { get } = useApi();
  const [users, setUsers] = useState<PilotUser[]>([]);
  const [coverage, setCoverage] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [covResp] = await Promise.all([
          get("/compliance/coverage"),
        ]);
        const cov = await covResp.json();
        if (!cancelled) {
          setCoverage(cov);
          // Users are loaded from a local API — may not exist yet
          try {
            const usersResp = await get("/admin/users");
            const usersData = await usersResp.json();
            if (!cancelled) setUsers(Array.isArray(usersData) ? usersData : usersData.users || []);
          } catch {
            // /admin/users not implemented yet — leave empty
          }
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [get]);

  if (loading) return <div className="page-card"><p className="loading">Loading...</p></div>;
  if (error) return <div className="page-card"><div className="form-error">{error}</div></div>;

  return (
    <div className="page-card">
      <div className="page-header">
        <h1>Administration</h1>
      </div>

      <section>
        <h2>Framework Coverage</h2>
        {coverage ? (
          <pre className="json-block">{JSON.stringify(coverage, null, 2)}</pre>
        ) : (
          <p className="muted">No coverage data available.</p>
        )}
      </section>

      <section>
        <h2>Pilot Users</h2>
        {users.length === 0 ? (
          <p className="muted">
            User management API not yet available. Users are managed via{" "}
            <code>create_pilot_user.py</code>.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Scopes</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username}>
                    <td>{u.username}</td>
                    <td>{u.email}</td>
                    <td>{u.scopes.join(", ")}</td>
                    <td>
                      <span className={`badge ${u.enabled ? "ok" : "warn"}`}>
                        {u.enabled ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td>{u.created_at?.slice(0, 10) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
