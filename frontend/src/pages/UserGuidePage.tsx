export default function UserGuidePage() {
  return (
    <div className="guide-page">
      <h1>User Guide</h1>
      <p className="guide-subtitle">
        Clarisys evaluates firewall rules against ISO&nbsp;27001, CIS&nbsp;v8.1 and PCI-DSS.
        Upload your policy export and receive a detailed compliance report in seconds.
      </p>

      {/* ── Supported Vendors ──────────────────────────── */}
      <section className="guide-section">
        <h2>Supported Vendors</h2>
        <div className="guide-cards">
          <div className="guide-card">
            <h3>Generic / Raw Schema</h3>
            <span className="guide-badge">CSV</span>
            <span className="guide-badge">XLSX</span>
            <p>Any firewall export with standard columns: source, destination, protocol, port.</p>
          </div>
          <div className="guide-card">
            <h3>Palo Alto Networks</h3>
            <span className="guide-badge">CSV</span>
            <p>
              Panorama &amp; PAN-OS security rulebase exports. Auto-detected from zone and
              address columns (e.g. <code>Source Zone</code>, <code>Destination Address</code>,
              <code>Application</code>, <code>Service</code>).
            </p>
          </div>
          <div className="guide-card">
            <h3>Juniper SRX</h3>
            <span className="guide-badge">JSON</span>
            <span className="guide-badge">XML</span>
            <p>
              <code>show security policies</code> output in JSON or XML format.
              Zone pairs, match criteria and permit/deny actions are parsed automatically.
            </p>
          </div>
          <div className="guide-card">
            <h3>Fortinet FortiGate</h3>
            <span className="guide-badge">XLSX</span>
            <p>
              FortiGate policy export worksheets. Detected by <code>Seq #</code> header layout
              with source/destination interfaces, addresses and service mappings.
            </p>
          </div>
        </div>
      </section>

      {/* ── Compliance Standards ───────────────────────── */}
      <section className="guide-section">
        <h2>Compliance Standards</h2>
        <p>Every rule is evaluated against the selected frameworks. All three are enabled by default.</p>
        <table className="guide-table">
          <thead>
            <tr><th>Standard</th><th>Focus</th><th>Example Controls</th></tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>ISO 27001</strong></td>
              <td>Information Security Management</td>
              <td>A.8.24 (encryption in transit), A.9.2 (access control)</td>
            </tr>
            <tr>
              <td><strong>CIS v8.1</strong></td>
              <td>Center for Internet Security Benchmarks (IG3)</td>
              <td>CIS 8.2 (identity), CIS 13.6 (log monitoring)</td>
            </tr>
            <tr>
              <td><strong>PCI-DSS</strong></td>
              <td>Payment Card Industry Data Security</td>
              <td>Encryption for cardholder data, segmentation controls</td>
            </tr>
          </tbody>
        </table>
      </section>

      {/* ── CSV Fields: Raw Schema ─────────────────────── */}
      <section className="guide-section">
        <h2>CSV Fields — Raw Schema</h2>
        <p>Use this format when exporting rules from any firewall as a flat CSV.</p>
        <table className="guide-table">
          <thead>
            <tr><th>Column</th><th>Required</th><th>Description</th><th>Example</th></tr>
          </thead>
          <tbody>
            <tr><td><code>source</code></td><td>Yes</td><td>Source IP / CIDR / FQDN</td><td><code>10.0.0.0/8</code></td></tr>
            <tr><td><code>destination</code></td><td>Yes</td><td>Destination IP / CIDR / FQDN</td><td><code>10.221.126.33</code></td></tr>
            <tr><td><code>protocol</code></td><td>Yes</td><td>tcp, udp, icmp, or any</td><td><code>tcp</code></td></tr>
            <tr><td><code>port</code></td><td>Yes</td><td>Destination port (0–65535, use 0 for ICMP)</td><td><code>443</code></td></tr>
            <tr><td><code>action</code></td><td>No</td><td>accept or deny (default: accept)</td><td><code>accept</code></td></tr>
            <tr><td><code>log</code></td><td>No</td><td>Logging mode: all, utm, no_log, log_all_sessions</td><td><code>log_all_sessions</code></td></tr>
            <tr><td><code>rule_name</code></td><td>No</td><td>Human-readable rule identifier</td><td><code>ALLOW-DNS</code></td></tr>
            <tr><td><code>source_interface</code></td><td>No</td><td>Source interface / zone label</td><td><code>VLAN100</code></td></tr>
            <tr><td><code>destination_interface</code></td><td>No</td><td>Destination interface / zone label</td><td><code>DMZ</code></td></tr>
            <tr><td><code>data_classification</code></td><td>No</td><td>Public, Internal, Confidential, Highly Confidential</td><td><code>Confidential</code></td></tr>
            <tr><td><code>encryption_required</code></td><td>No</td><td>Force encryption check (true/false)</td><td><code>true</code></td></tr>
            <tr><td><code>tls_version_minimum</code></td><td>No</td><td>Minimum TLS version</td><td><code>1.2</code></td></tr>
          </tbody>
        </table>
        <div className="guide-example">
          <strong>Example CSV</strong>
          <pre>{`source,destination,protocol,port,log,action,rule_name
10.0.0.0/8,10.0.0.0/8,tcp,0,log_all_sessions,accept,INTRA-LAN
10.221.0.0/16,10.221.126.33,tcp,443,log_all_sessions,accept,HTTPS-OUT
192.168.1.0/24,0.0.0.0/0,udp,53,all,accept,DNS-ALLOW`}</pre>
        </div>
      </section>

      {/* ── CSV Fields: Intake Schema ──────────────────── */}
      <section className="guide-section">
        <h2>CSV Fields — Intake (Logical Access Requests)</h2>
        <p>
          Use intake format for pre-implementation change requests. Each row represents a
          logical access requirement with business context.
        </p>
        <table className="guide-table">
          <thead>
            <tr><th>Column</th><th>Required</th><th>Description</th><th>Example</th></tr>
          </thead>
          <tbody>
            <tr><td><code>app_id</code></td><td>Yes</td><td>CMDB application ID (ap-XXXX)</td><td><code>ap-A1234</code></td></tr>
            <tr><td><code>portfolio</code></td><td>Yes</td><td>Business portfolio name</td><td><code>Finance &amp; Payroll</code></td></tr>
            <tr><td><code>environment</code></td><td>Yes</td><td>production, staging, development</td><td><code>production</code></td></tr>
            <tr><td><code>requested_by</code></td><td>Yes</td><td>Requestor email</td><td><code>alice@example.com</code></td></tr>
            <tr><td><code>expires_at</code></td><td>Yes</td><td>Expiry date (YYYY-MM-DD, max 12 months)</td><td><code>2027-03-15</code></td></tr>
            <tr><td><code>project_reference</code></td><td>Yes</td><td>Change/project reference</td><td><code>CHG0012345</code></td></tr>
            <tr><td><code>source_name</code></td><td>Yes</td><td>Logical source name</td><td><code>payroll-app</code></td></tr>
            <tr><td><code>destination_name</code></td><td>Yes</td><td>Logical destination name</td><td><code>hmrc-api</code></td></tr>
            <tr><td><code>protocol</code></td><td>Yes</td><td>TCP, UDP, ICMP, or ANY</td><td><code>TCP</code></td></tr>
            <tr><td><code>business_justification</code></td><td>Yes</td><td>Reason for access (min 20 chars)</td><td><code>Submit payroll data to HMRC API</code></td></tr>
            <tr><td><code>destination_port</code></td><td>Conditional</td><td>Required if protocol is TCP or UDP</td><td><code>443</code></td></tr>
            <tr><td><code>action</code></td><td>No</td><td>ALLOW or DENY (default: ALLOW)</td><td><code>ALLOW</code></td></tr>
          </tbody>
        </table>
      </section>

      {/* ── Palo Alto CSV ──────────────────────────────── */}
      <section className="guide-section">
        <h2>Palo Alto Networks CSV</h2>
        <p>
          Export your security rulebase from Panorama or PAN-OS. Clarisys auto-detects Palo Alto
          exports from column names — no renaming needed.
        </p>
        <table className="guide-table">
          <thead>
            <tr><th>Accepted Columns</th><th>Aliases</th></tr>
          </thead>
          <tbody>
            <tr><td>Source Zone</td><td><code>From Zone</code>, <code>Src Zone</code></td></tr>
            <tr><td>Source Address</td><td><code>Src Address</code>, <code>Source</code></td></tr>
            <tr><td>Destination Zone</td><td><code>To Zone</code>, <code>Dst Zone</code></td></tr>
            <tr><td>Destination Address</td><td><code>Dst Address</code>, <code>Destination</code></td></tr>
            <tr><td>Service</td><td><code>Application Service</code>, <code>Service Port</code></td></tr>
            <tr><td>Application</td><td><code>App</code></td></tr>
            <tr><td>Action</td><td><code>Rule Action</code>, <code>Policy Action</code></td></tr>
            <tr><td>Name</td><td><code>Rule Name</code></td></tr>
          </tbody>
        </table>
        <p className="guide-hint">
          Ports are extracted from the Service field (e.g. <code>tcp/443</code>) or inferred from
          known applications (<code>https</code> → 443, <code>dns</code> → 53).
        </p>
      </section>

      {/* ── Juniper SRX ────────────────────────────────── */}
      <section className="guide-section">
        <h2>Juniper SRX — JSON &amp; XML</h2>
        <p>
          Upload the output of <code>show security policies | display json</code> or
          <code>show security policies | display xml</code>.
        </p>
        <div className="guide-example">
          <strong>JSON structure</strong>
          <pre>{`{
  "policies": [{
    "policy": [{
      "from-zone-name": { "data": "trust" },
      "to-zone-name": { "data": "untrust" },
      "policy": [{
        "name": { "data": "allow-web" },
        "match": [{
          "source-address": [{ "data": "10.0.1.0/24" }],
          "destination-address": [{ "data": "0.0.0.0/0" }],
          "application": [{ "data": "https" }]
        }],
        "then": [{ "permit": [{}] }]
      }]
    }]
  }]
}`}</pre>
        </div>
        <div className="guide-example">
          <strong>XML structure</strong>
          <pre>{`<policies>
  <policy>
    <from-zone-name>trust</from-zone-name>
    <to-zone-name>untrust</to-zone-name>
    <policy>
      <name>allow-web</name>
      <match>
        <source-address>10.0.1.0/24</source-address>
        <destination-address>0.0.0.0/0</destination-address>
        <application>https</application>
      </match>
      <then><permit/></then>
    </policy>
  </policy>
</policies>`}</pre>
        </div>
      </section>

      {/* ── Fortinet ───────────────────────────────────── */}
      <section className="guide-section">
        <h2>Fortinet FortiGate — XLSX</h2>
        <p>
          Export your FortiGate policy table to XLSX. Clarisys detects the Fortinet layout from the
          <code> Seq #</code> header and reads source/destination interfaces, addresses, services and
          logging configuration.
        </p>
        <p className="guide-hint">Only the first worksheet is processed.</p>
      </section>

      {/* ── How To Audit ───────────────────────────────── */}
      <section className="guide-section">
        <h2>How to Run an Audit</h2>
        <ol className="guide-steps">
          <li>Navigate to the <strong>Audit</strong> page.</li>
          <li>Select your file (<code>.csv</code>, <code>.xlsx</code>, <code>.json</code>, or <code>.xml</code>).</li>
          <li>Optionally select which compliance standards to evaluate.</li>
          <li>Click <strong>Run Audit</strong> — the report renders inline.</li>
          <li>Click <strong>Download Report</strong> to save the HTML compliance report.</li>
        </ol>
        <p>
          Every audit is recorded in the <strong>History</strong> page with per-rule verdicts,
          failed controls, and remediation guidance.
        </p>
      </section>

      {/* ── File Format Quick Reference ────────────────── */}
      <section className="guide-section">
        <h2>Quick Reference</h2>
        <table className="guide-table">
          <thead>
            <tr><th>Vendor / Format</th><th>File Types</th><th>Detection</th></tr>
          </thead>
          <tbody>
            <tr><td>Generic raw rules</td><td>.csv, .xlsx</td><td>Columns: source, destination, port</td></tr>
            <tr><td>Logical intake requests</td><td>.csv</td><td>Columns: app_id, portfolio, source_name</td></tr>
            <tr><td>Palo Alto Networks</td><td>.csv</td><td>Zone + address columns detected</td></tr>
            <tr><td>Juniper SRX</td><td>.json, .xml</td><td>policies / policy structure</td></tr>
            <tr><td>Fortinet FortiGate</td><td>.xlsx</td><td>Seq # header in row 2</td></tr>
          </tbody>
        </table>
      </section>
    </div>
  );
}
