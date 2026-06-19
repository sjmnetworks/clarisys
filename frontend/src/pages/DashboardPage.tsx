import { useEffect, useState } from "react";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";

interface DashboardData {
  rulesProcessed: number;
  costSaved: string;
  hipsSaved: number;
  hoursSaved: number;
  policyVersion: string;
  policyHash: string;
  sloUptime: string;
  recentDecisions: Decision[];
}

interface Decision {
  decision_id: string;
  verdict: string;
  timestamp: string;
  endpoint: string;
  overall_risk: string;
}

export default function DashboardPage() {
  const { user } = useAuth();
  const { get } = useApi();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [roiResp, policyResp, sloResp, histResp] = await Promise.all([
          get("/metrics/roi"),
          get("/policy/metadata"),
          get("/metrics/slo"),
          get("/decisions/history?limit=10"),
        ]);
        const roi = await roiResp.json();
        const policy = await policyResp.json();
        const slo = await sloResp.json();
        const hist = await histResp.json();
        if (!cancelled) {
          setData({
            rulesProcessed: roi.rules_processed ?? 0,
            costSaved: roi.cost_saved_formatted ?? "£0",
            hipsSaved: roi.hips_equivalent ?? 0,
            hoursSaved: roi.hours_saved ?? 0,
            policyVersion: policy.policy_version ?? "unknown",
            policyHash: policy.policy_hash?.slice(0, 12) ?? "",
            sloUptime: slo.uptime_percent != null
              ? `${Number(slo.uptime_percent).toFixed(2)}%`
              : "N/A",
            recentDecisions: Array.isArray(hist.decisions)
              ? hist.decisions.slice(0, 10)
              : Array.isArray(hist)
                ? hist.slice(0, 10)
                : [],
          });
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [get]);

  if (loading) return <div className="page-card"><p className="loading">Loading dashboard...</p></div>;
  if (error) return <div className="page-card"><div className="form-error">{error}</div></div>;
  if (!data) return null;

  return (
    <div className="page-card">
      <div className="page-header">
        <h1>Dashboard</h1>
        <span className="badge">{user?.role}</span>
      </div>

      <div className="stat-grid">
        <StatCard label="Rules Processed" value={data.rulesProcessed.toLocaleString()} />
        <StatCard label="Cost Saved" value={data.costSaved} accent />
        <StatCard label="HIPS Equivalent" value={data.hipsSaved.toLocaleString()} />
        <StatCard label="Hours Saved" value={data.hoursSaved.toLocaleString()} />
      </div>

      <div className="info-row">
        <div className="info-item">
          <span className="info-label">Policy</span>
          <span className="info-value">{data.policyVersion}</span>
        </div>
        <div className="info-item">
          <span className="info-label">Hash</span>
          <code className="info-value">{data.policyHash}</code>
        </div>
        <div className="info-item">
          <span className="info-label">SLO Uptime</span>
          <span className="info-value">{data.sloUptime}</span>
        </div>
      </div>

      <h2>Recent Decisions</h2>
      {data.recentDecisions.length === 0 ? (
        <p className="muted">No decisions recorded yet.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Endpoint</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {data.recentDecisions.map((d) => (
                <tr key={d.decision_id}>
                  <td><code>{d.decision_id?.slice(0, 16)}</code></td>
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

function StatCard({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className={`stat-card${accent ? " accent" : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
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
