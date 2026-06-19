import { useEffect, useState, useCallback } from "react";
import { useApi } from "../hooks/useApi";

interface Decision {
  decision_id: string;
  verdict: string;
  timestamp: string;
  endpoint: string;
  overall_risk: string;
  failed_controls: string[];
  failed_standards: string[];
}

export default function HistoryPage() {
  const { get } = useApi();
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState<"all" | "ACCEPTABLE" | "DENY">("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const resp = await get(`/decisions/history?limit=${limit}`);
      const data = await resp.json();
      setDecisions(Array.isArray(data.decisions) ? data.decisions : Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [get, limit]);

  useEffect(() => { load(); }, [load]);

  const filtered = filter === "all"
    ? decisions
    : decisions.filter((d) => d.verdict === filter);

  const counts = {
    all: decisions.length,
    acceptable: decisions.filter((d) => d.verdict === "ACCEPTABLE").length,
    deny: decisions.filter((d) => d.verdict === "DENY").length,
  };

  return (
    <div className="page-card">
      <div className="page-header">
        <h1>Decision History</h1>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="select-compact"
        >
          <option value={25}>Last 25</option>
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={500}>Last 500</option>
        </select>
      </div>

      <div className="filter-tabs">
        <button className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>
          All ({counts.all})
        </button>
        <button className={filter === "ACCEPTABLE" ? "active" : ""} onClick={() => setFilter("ACCEPTABLE")}>
          Acceptable ({counts.acceptable})
        </button>
        <button className={filter === "DENY" ? "active" : ""} onClick={() => setFilter("DENY")}>
          Denied ({counts.deny})
        </button>
      </div>

      {error && <div className="form-error">{error}</div>}

      {loading ? (
        <p className="loading">Loading history...</p>
      ) : filtered.length === 0 ? (
        <p className="muted">No decisions match the current filter.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Decision ID</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Endpoint</th>
                <th>Failed Controls</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((d) => (
                <tr key={d.decision_id}>
                  <td><code>{d.decision_id?.slice(0, 20)}</code></td>
                  <td>
                    <span className={`verdict ${d.verdict === "ACCEPTABLE" ? "ok" : "deny"}`}>
                      {d.verdict}
                    </span>
                  </td>
                  <td>
                    <span className={`risk risk-${d.overall_risk?.toLowerCase()}`}>
                      {d.overall_risk}
                    </span>
                  </td>
                  <td>{d.endpoint}</td>
                  <td>
                    {d.failed_controls?.length
                      ? d.failed_controls.join(", ")
                      : "—"}
                  </td>
                  <td>{formatTime(d.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function formatTime(ts: string) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-GB", {
      day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return ts;
  }
}
