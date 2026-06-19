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
  source: string;
  destination: string;
  protocol: string;
  port: number;
  remediations: string[];
  reason: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalizeDecision(d: any): Decision {
  const det = d.details ?? {};
  return {
    decision_id: d.decision_id ?? "",
    verdict: d.verdict ?? d.decision_verdict ?? "",
    timestamp: d.timestamp ?? d.ts ?? "",
    endpoint: d.endpoint ?? "",
    overall_risk: d.overall_risk ?? det.overall_risk ?? "",
    failed_controls: d.failed_controls ?? det.failed_controls ?? [],
    failed_standards: d.failed_standards ?? det.failed_standards ?? [],
    source: det.source ?? det.policy_input?.source ?? "",
    destination: det.destination ?? det.policy_input?.destination ?? "",
    protocol: det.protocol ?? det.policy_input?.protocol ?? "",
    port: det.port ?? det.policy_input?.port ?? 0,
    remediations: det.remediations ?? [],
    reason: det.reason ?? "",
  };
}

export default function HistoryPage() {
  const { get } = useApi();
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState<"all" | "ACCEPTABLE" | "DENY">("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<string, boolean>>(() => {
    try { return JSON.parse(localStorage.getItem("clarisys_remediations") ?? "{}"); } catch { return {}; }
  });

  const toggleCheck = (key: string) => {
    setChecked((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      localStorage.setItem("clarisys_remediations", JSON.stringify(next));
      return next;
    });
  };

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const resp = await get(`/decisions/history?limit=${limit}`);
      const data = await resp.json();
      const raw = Array.isArray(data.items) ? data.items : Array.isArray(data.decisions) ? data.decisions : Array.isArray(data) ? data : [];
      setDecisions(raw.map(normalizeDecision));
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
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn-secondary btn-sm" onClick={() => downloadAllReport(filtered)}>
            Export Filtered
          </button>
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
                <th></th>
                <th>Decision ID</th>
                <th>Verdict</th>
                <th>Risk</th>
                <th>Source → Dest</th>
                <th>Failed Controls</th>
                <th>Time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((d) => (
                <>
                  <tr key={d.decision_id} className={expanded === d.decision_id ? "row-expanded" : ""}>
                    <td>
                      <button
                        className="btn-icon"
                        onClick={() => setExpanded(expanded === d.decision_id ? null : d.decision_id)}
                        title="Expand"
                      >
                        {expanded === d.decision_id ? "▼" : "▶"}
                      </button>
                    </td>
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
                    <td className="cell-route">
                      {d.source && d.destination
                        ? <><code>{d.source}</code> → <code>{d.destination}</code></>
                        : d.endpoint}
                    </td>
                    <td>
                      {d.failed_controls?.length
                        ? d.failed_controls.map((c) => (
                            <span key={c} className="badge-sm">{c}</span>
                          ))
                        : "—"}
                    </td>
                    <td>{formatTime(d.timestamp)}</td>
                    <td>
                      <button className="btn-icon" onClick={() => downloadReport(d)} title="Download report">
                        ↓
                      </button>
                    </td>
                  </tr>
                  {expanded === d.decision_id && (
                    <tr key={`${d.decision_id}-detail`} className="detail-row">
                      <td colSpan={8}>
                        <div className="detail-panel">
                          <div className="detail-grid">
                            <div>
                              <h4>Rule Details</h4>
                              <dl className="detail-dl">
                                <dt>Protocol / Port</dt>
                                <dd>{d.protocol?.toUpperCase()} / {d.port}</dd>
                                <dt>Verdict</dt>
                                <dd>{d.verdict}</dd>
                                <dt>Risk</dt>
                                <dd>{d.overall_risk}</dd>
                                <dt>Failed Standards</dt>
                                <dd>{d.failed_standards?.join(", ") || "None"}</dd>
                              </dl>
                              {d.reason && <p className="detail-reason">{d.reason}</p>}
                            </div>
                            <div>
                              <h4>Remediation Checklist</h4>
                              {d.remediations.length === 0 ? (
                                <p className="muted">No remediations required.</p>
                              ) : (
                                <ul className="remediation-list">
                                  {d.remediations.map((r, i) => {
                                    const key = `${d.decision_id}:${i}`;
                                    return (
                                      <li key={key} className={checked[key] ? "done" : ""}>
                                        <label>
                                          <input
                                            type="checkbox"
                                            checked={!!checked[key]}
                                            onChange={() => toggleCheck(key)}
                                          />
                                          <span>{r}</span>
                                        </label>
                                      </li>
                                    );
                                  })}
                                </ul>
                              )}
                              {d.remediations.length > 0 && (
                                <p className="remediation-progress">
                                  {d.remediations.filter((_, i) => checked[`${d.decision_id}:${i}`]).length} / {d.remediations.length} completed
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
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

function downloadReport(d: Decision) {
  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Decision Report – ${escapeHtml(d.decision_id)}</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:800px;margin:40px auto;padding:0 20px;color:#1a1a1a}
  h1{font-size:1.4rem;border-bottom:2px solid #0F6E56;padding-bottom:8px}
  h2{font-size:1.1rem;margin-top:24px;color:#0F6E56}
  .badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.85rem;font-weight:600}
  .deny{background:#fee2e2;color:#991b1b}.ok{background:#d1fae5;color:#065f46}
  .critical{background:#fecaca;color:#7f1d1d}.high{background:#fed7aa;color:#9a3412}
  .medium{background:#fef3c7;color:#92400e}.low{background:#dbeafe;color:#1e40af}
  table{width:100%;border-collapse:collapse;margin:12px 0}
  th,td{text-align:left;padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:.9rem}
  th{background:#f9fafb;font-weight:600}
  ul{margin:8px 0;padding-left:20px}li{margin:4px 0;font-size:.9rem}
  .meta{color:#6b7280;font-size:.85rem}
  .checklist li{list-style:none;padding:4px 0}
  .checklist input{margin-right:8px}
  @media print{body{margin:20px}}
</style></head><body>
<h1>Clarisys Decision Report</h1>
<p class="meta">Generated ${new Date().toLocaleString("en-GB")} | Decision ID: <code>${escapeHtml(d.decision_id)}</code></p>

<h2>Summary</h2>
<table>
  <tr><th>Verdict</th><td><span class="badge ${d.verdict === "ACCEPTABLE" ? "ok" : "deny"}">${escapeHtml(d.verdict)}</span></td></tr>
  <tr><th>Risk Level</th><td><span class="badge ${d.overall_risk?.toLowerCase()}">${escapeHtml(d.overall_risk)}</span></td></tr>
  <tr><th>Source</th><td>${escapeHtml(d.source)}</td></tr>
  <tr><th>Destination</th><td>${escapeHtml(d.destination)}</td></tr>
  <tr><th>Protocol / Port</th><td>${escapeHtml(d.protocol?.toUpperCase())} / ${d.port}</td></tr>
  <tr><th>Evaluated</th><td>${escapeHtml(d.timestamp ? new Date(d.timestamp).toLocaleString("en-GB") : "—")}</td></tr>
</table>

<h2>Compliance Findings</h2>
<table>
  <tr><th>Failed Controls</th><td>${d.failed_controls?.length ? d.failed_controls.map(c => `<code>${escapeHtml(c)}</code>`).join(", ") : "None"}</td></tr>
  <tr><th>Failed Standards</th><td>${d.failed_standards?.length ? d.failed_standards.join(", ") : "None"}</td></tr>
</table>
${d.reason ? `<p><strong>Reason:</strong> ${escapeHtml(d.reason)}</p>` : ""}

<h2>Remediation Checklist</h2>
${d.remediations.length === 0
    ? "<p>No remediations required — rule is compliant.</p>"
    : `<ul class="checklist">${d.remediations.map((r) => `<li><input type="checkbox"> ${escapeHtml(r)}</li>`).join("")}</ul>`
}
</body></html>`;
  triggerDownload(html, `decision-report-${d.decision_id.slice(0, 16)}.html`, "text/html");
}

function downloadAllReport(decisions: Decision[]) {
  const denied = decisions.filter((d) => d.verdict === "DENY");
  const rows = decisions.map((d) =>
    `<tr>
      <td><code>${escapeHtml(d.decision_id.slice(0, 16))}</code></td>
      <td><span class="badge ${d.verdict === "ACCEPTABLE" ? "ok" : "deny"}">${escapeHtml(d.verdict)}</span></td>
      <td><span class="badge ${d.overall_risk?.toLowerCase()}">${escapeHtml(d.overall_risk)}</span></td>
      <td>${escapeHtml(d.source)} → ${escapeHtml(d.destination)}</td>
      <td>${d.failed_controls?.join(", ") || "—"}</td>
      <td>${formatTime(d.timestamp)}</td>
    </tr>`
  ).join("\n");

  const remediationSection = denied.length === 0
    ? "<p>All rules compliant — no remediation required.</p>"
    : denied.map((d) =>
        `<div style="margin-bottom:16px">
          <strong>${escapeHtml(d.source)} → ${escapeHtml(d.destination)}</strong>
          <span class="badge ${d.overall_risk?.toLowerCase()}" style="margin-left:8px">${escapeHtml(d.overall_risk)}</span>
          <ul class="checklist">${d.remediations.map((r) => `<li><input type="checkbox"> ${escapeHtml(r)}</li>`).join("")}</ul>
        </div>`
      ).join("\n");

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Decision History Report</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a1a}
  h1{font-size:1.4rem;border-bottom:2px solid #0F6E56;padding-bottom:8px}
  h2{font-size:1.1rem;margin-top:24px;color:#0F6E56}
  .badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.85rem;font-weight:600}
  .deny{background:#fee2e2;color:#991b1b}.ok{background:#d1fae5;color:#065f46}
  .critical{background:#fecaca;color:#7f1d1d}.high{background:#fed7aa;color:#9a3412}
  .medium{background:#fef3c7;color:#92400e}.low{background:#dbeafe;color:#1e40af}
  table{width:100%;border-collapse:collapse;margin:12px 0}
  th,td{text-align:left;padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:.9rem}
  th{background:#f9fafb;font-weight:600}
  .summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0}
  .summary-card{background:#f9fafb;border-radius:8px;padding:12px 16px;text-align:center}
  .summary-card .num{font-size:1.6rem;font-weight:700;color:#0F6E56}
  .summary-card .lbl{font-size:.8rem;color:#6b7280;margin-top:2px}
  .meta{color:#6b7280;font-size:.85rem}
  .checklist{list-style:none;padding-left:0}
  .checklist li{padding:4px 0;font-size:.9rem}
  .checklist input{margin-right:8px}
  @media print{body{margin:20px}}
</style></head><body>
<h1>Clarisys Decision History Report</h1>
<p class="meta">Generated ${new Date().toLocaleString("en-GB")} | ${decisions.length} decisions</p>

<div class="summary-grid">
  <div class="summary-card"><div class="num">${decisions.length}</div><div class="lbl">Total Evaluated</div></div>
  <div class="summary-card"><div class="num">${decisions.length - denied.length}</div><div class="lbl">Compliant</div></div>
  <div class="summary-card"><div class="num" style="color:#991b1b">${denied.length}</div><div class="lbl">Non-Compliant</div></div>
</div>

<h2>All Decisions</h2>
<table>
  <thead><tr><th>ID</th><th>Verdict</th><th>Risk</th><th>Route</th><th>Failed Controls</th><th>Time</th></tr></thead>
  <tbody>${rows}</tbody>
</table>

<h2>Remediation Task List</h2>
${remediationSection}
</body></html>`;
  triggerDownload(html, `decision-history-report-${new Date().toISOString().slice(0, 10)}.html`, "text/html");
}

function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
