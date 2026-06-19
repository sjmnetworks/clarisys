import { useState, useRef, type FormEvent } from "react";
import { useApi } from "../hooks/useApi";

const STANDARDS = ["ISO 27001", "CIS v8.1", "PCI-DSS"];

interface AuditSummary {
  total: number;
  acceptable: number;
  denied: number;
  invalid: number;
  overallStatus: string;
}

interface ViolationRow {
  rule: number;
  control: string;
  severity: string;
  violation: string;
  remediation: string;
}

export default function AuditPage() {
  const { postFormData } = useApi();
  const fileRef = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set(STANDARDS));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [htmlReport, setHtmlReport] = useState("");
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [violations, setViolations] = useState<ViolationRow[]>([]);

  const toggleStandard = (s: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setHtmlReport("");
    setSummary(null);
    setViolations([]);

    const file = fileRef.current?.files?.[0];
    if (!file) { setError("Select a file to audit."); return; }
    if (selected.size === 0) { setError("Select at least one standard."); return; }

    setLoading(true);
    try {
      const ext = file.name.split(".").pop()?.toLowerCase();
      let endpoint: string;
      if (ext === "xlsx") endpoint = "/audit/xlsx";
      else if (ext === "csv") endpoint = "/audit/csv/html";
      else if (ext === "json" || ext === "xml") endpoint = "/audit/json/html";
      else { setError("Unsupported file type. Use .csv, .xlsx, .json, or .xml"); setLoading(false); return; }

      const params = new URLSearchParams();
      for (const s of selected) params.append("standards", s);

      const fd = new FormData();
      fd.append("file", file);

      const resp = await postFormData(`${endpoint}?${params}`, fd);
      const contentType = resp.headers.get("content-type") || "";

      if (contentType.includes("text/html")) {
        const html = await resp.text();
        setHtmlReport(html);
        parseHtmlSummary(html);
      } else {
        // Markdown or JSON fallback
        const text = await resp.text();
        parseMdSummary(text);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Audit failed");
    } finally {
      setLoading(false);
    }
  };

  const parseHtmlSummary = (html: string) => {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const items = doc.querySelectorAll("li");
    const vals: Record<string, string> = {};
    items.forEach((li) => {
      const text = li.textContent || "";
      const match = text.match(/^(.+?):\s*(.+)$/);
      if (match) vals[match[1].trim().toLowerCase()] = match[2].trim();
    });
    setSummary({
      total: parseInt(vals["total rules evaluated"] || "0"),
      acceptable: parseInt(vals["acceptable"] || "0"),
      denied: parseInt(vals["requires remediation"] || vals["denied"] || "0"),
      invalid: parseInt(vals["invalid rows"] || "0"),
      overallStatus: vals["overall status"] || "UNKNOWN",
    });
  };

  const parseMdSummary = (md: string) => {
    const num = (label: string) => {
      const m = md.match(new RegExp(`\\*\\*${label}:\\*\\*\\s*(\\d+)`));
      return m ? parseInt(m[1]) : 0;
    };
    setSummary({
      total: num("Total rules evaluated"),
      acceptable: num("Acceptable"),
      denied: num("Requires remediation") || num("Denied"),
      invalid: num("Invalid rows"),
      overallStatus: md.includes("NON-COMPLIANT") ? "NON-COMPLIANT" : "COMPLIANT",
    });
  };

  void violations; // suppress unused warning — will be populated by detail view later

  const handleClear = () => {
    if (fileRef.current) fileRef.current.value = "";
    setHtmlReport("");
    setSummary(null);
    setViolations([]);
    setError("");
  };

  return (
    <div className="page-card">
      <div className="page-header">
        <h1>Compliance Audit</h1>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="file">Upload ruleset</label>
          <input
            ref={fileRef}
            id="file"
            type="file"
            accept=".csv,.xlsx,.json,.xml"
          />
          <span className="form-hint">CSV, XLSX, JSON (Juniper SRX), or XML</span>
        </div>

        <div className="form-group">
          <label>Compliance standards</label>
          <div className="checkbox-row">
            {STANDARDS.map((s) => (
              <label key={s} className="checkbox-label">
                <input
                  type="checkbox"
                  checked={selected.has(s)}
                  onChange={() => toggleStandard(s)}
                />
                {s}
              </label>
            ))}
          </div>
        </div>

        {error && <div className="form-error">{error}</div>}

        <div className="btn-row">
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? "Auditing..." : "Run Audit"}
          </button>
          <button type="button" className="btn-secondary" onClick={handleClear}>
            Clear
          </button>
        </div>
      </form>

      {summary && (
        <div className="audit-summary">
          <h2>Results</h2>
          <div className="stat-grid cols-4">
            <SummaryCard label="Total" value={summary.total} />
            <SummaryCard label="Acceptable" value={summary.acceptable} ok />
            <SummaryCard label="Remediation" value={summary.denied} bad={summary.denied > 0} />
            <SummaryCard label="Invalid" value={summary.invalid} />
          </div>
          <div className={`overall-status ${summary.overallStatus === "COMPLIANT" ? "compliant" : "non-compliant"}`}>
            {summary.overallStatus}
          </div>
        </div>
      )}

      {htmlReport && (
        <div className="report-frame">
          <h2>Full Report</h2>
          <div
            className="report-content"
            dangerouslySetInnerHTML={{ __html: htmlReport }}
          />
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, ok, bad }: { label: string; value: number; ok?: boolean; bad?: boolean }) {
  return (
    <div className={`stat-card${ok ? " ok" : ""}${bad ? " bad" : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
