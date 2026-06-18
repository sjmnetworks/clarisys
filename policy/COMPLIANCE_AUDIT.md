# Firewall Policy Compliance Audit Report
**Date:** 2026-05-15 (Re-audit v2 — NFR standards added)  
**Standards:** CIS Controls v8.1 (IG3), ISO 27001, NIST CSF, PCI-DSS v3.2.1, **Clarisys Security NFRs (IAM, Data, Cloud)**  
**Total Rules Audited:** 34

---

## Change Log

| Version | Date | Change |
|---------|------|--------|
| v1 | 2026-05-15 | Initial audit — CIS v8.1, ISO 27001, NIST CSF, PCI-DSS |
| **v2** | **2026-05-15** | **Re-audit — Added Clarisys NFR standards: IAM-2 (Least Privilege), IAM-8 (Identity Logging), Data-10 (Data Sharing), Cloud-08 (Network Isolation)** |
| **v3** | **2026-06-16** | **HTML Report Generation with RAG Status Badges — Professional Clarisys-branded compliance reports with color-coded risk indicators** |

---

## HTML Report with RAG Status Indicators

Reports are now generated as professional Clarisys-branded HTML documents with **Red/Amber/Green (RAG) status badges** for each evaluated rule:

| Badge | Risk Level | Color | Meaning |
|-------|-----------|-------|---------|
| 🟢 GREEN | LOW | `#1f6f3f` | Compliant, no action required |
| 🟡 AMBER | MEDIUM | `#e8a500` | Minor violations, remediation recommended |
| 🔴 RED | HIGH | `#b02a2a` | Significant violations, prompt action needed |
| 🔴 RED | CRITICAL | `#8b0000` | Blocking violations, immediate action required |

**Features:**
- Download-friendly HTML format with complete audit trail
- Clarisys color scheme and typography
- Metadata grid showing audit timestamp, schema version, and overall compliance status
- Violation details with control mapping and remediation context
- Responsive design for viewing on desktop or mobile
- Export-ready for compliance evidence and audit archiving

**Access:**
- Web UI: `https://13.43.195.150/firewall-audit-ui/` (public page; drag-and-drop XLSX/CSV/JSON/XML upload form, but submissions still require a valid API key)
- API: `POST /audit/xlsx` with XLSX firewall policy export

---

## Executive Summary

| Metric | v1 (Previous) | v2 (Current) | Delta |
|--------|--------------|--------------|-------|
| **Total Rules** | 34 | 34 | — |
| **Compliant** | 16 | **18** | ▲ +2 ✅ |
| **Non-Compliant** | 17 | **16** | ▼ -1 |
| **REMOVE** | 2 | **3** | ▲ +1 🔴 Rule 24 escalated |
| **RESTRICT** | 3 | **5** | ▲ +2 🟠 Rules 28, 29, 30 escalated by Data-10 NFR |
| **REMEDIATE** | 12 | **8** | ▼ -4 |
| **Critical Violations** | 2 | **3** | ▲ +1 |

> **What changed?** The Clarisys NFR Data-10 (Data Sharing Controls) flagged external-bound rules using ALL services as violations. IAM-2 (Least Privilege) reinforced the CIS-4.8 findings. Cloud-08 (Network Isolation) added violations for rules with ANY destination. Rule 24 escalated from REMEDIATE to REMOVE-or-RESTRICT due to accumulated PCI-DSS + Data-10 violations.

---

## Critical Findings (Immediate Action Required)

### 🔴 CIS v8.1 Control 8.2 / 8.5 + IAM-8 — Logging Requirement Violations
**Violation:** Rules without any logging enabled — violates IG3 mandatory requirement that **all traffic must be logged**, and Clarisys NFR IAM-8 (Identity Logging, 180-day retention minimum).

| Rule # | Name | Action | Current Log | Recommendation |
|--------|------|--------|-------------|-----------------|
| **1** | INTRA CORP LAN ZONE | accept | **no_log** | 🔴 REMOVE — redundant, covered by Rules 2–9 |
| **33** | Catch all to Zscaler | accept | **no_log** | 🔴 REMOVE — catch-all with no audit trail |

**Impact:** 
- Clarisys cannot audit internal VLAN-to-VLAN traffic (Rule 1)
- Catch-all proxy traffic not being logged (Rule 33)
- **Non-compliant with CIS IG3, ISO 27001 A.12.4, NIST CSF DE.AE-3, Clarisys NFR IAM-8**

**Action:** Remove both rules. Specific rules (2–9) already provide scoped coverage.

---

### 🔴 PCI-DSS 4.1 + Data-10 (NEW v2) — Payment Zone Violation
**Violation:** Rule 24 (VLAN116 → DPDIA) uses ALL services from the POS/payment VLAN with an ANY destination. Combined PCI-DSS 4.1 and Clarisys NFR Data-10 (Data Sharing Controls require minimal scope + TLS 1.2+) make this a multi-standard critical failure.

| Rule # | Name | Action | Services | Destination | Violations |
|--------|------|--------|----------|-------------|------------|
| **24** | VLAN116 to DPDIA | accept | **ALL** | **ANY** | PCI-DSS 4.1 + Data-10 + CIS-4.8 + Cloud-08 |

**Action:** 🔴 REMOVE or RESTRICT to `HTTPS` (443) only with explicit payment processor IPs. Confirm with POS/payment teams before removing.

---

## CIS v8.1 Control 4.8 / IAM-2 / Data-10 — Overly Permissive Services
**Violation:** Rules permit **ANY protocol/port (ALL services)** without restricting to minimum required ports. Clarisys NFR IAM-2 (Least Privilege RBAC) and Data-10 (Data Sharing Controls: minimal scope, TLS 1.2+) add further requirements, particularly for externally-bound rules.

### Rules Requiring Action — v2 Consolidated Table

| Rule # | Name | Source | Destination | Logging | Action | Standards Violated | v1→v2 Change |
|--------|------|--------|-------------|---------|--------|--------------------|---------------|
| **1** | INTRA CORP LAN ZONE | VLAN101-118 | VLAN101-118 | ❌ no_log | 🔴 **REMOVE** | CIS-8.2, CIS-4.8, IAM-8, IAM-2 | No change |
| **4** | TRAS to VLAN1432 | TRAS | GPU cluster | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **5** | Catch all to Zscaler_1432 | store_vlan1432 | ANY | ✅ log_all | 🟠 **RESTRICT** | CIS-4.8, CIS-12.2, Cloud-08, Data-10, IAM-2 | No change |
| **10** | VLAN111 to INTERNAL Infra | VLAN111 | ANY | ✅ log_all | 🟡 **REMEDIATE** | CIS-12.2, Cloud-08 | No change |
| **11** | VLAN111 to MITIE | VLAN111 (CCTV) | MITIE | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **12** | MITIE to VLAN111 | MITIE | VLAN111 (CCTV) | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **14** | VLAN111 to INTERNAL PERMIT | VLAN111 | ANY | ✅ log_all | 🟠 **RESTRICT** | CIS-4.8, CIS-12.2, Cloud-08, Data-10, IAM-2 | No change |
| **20** | VLAN114 Endpoints | VLAN114 | ANY | ✅ log_all | 🟡 **REMEDIATE** | CIS-12.2, Cloud-08 | No change |
| **24** | VLAN116 to DPDIA | VLAN116 (POS) | ANY | ✅ log_all | 🔴 **REMOVE or RESTRICT** | PCI-DSS-4.1, CIS-4.8, CIS-12.2, Cloud-08, **Data-10** | **⬆️ ESCALATED: Data-10 added** |
| **25** | 10/8 via SDWAN HUB Out | RFC1918 | SDWAN | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **26** | 10/8 via SDWAN HUB In | SDWAN | RFC1918 | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **27** | Apps via DIA | Store nets | External DIA | ✅ log_all | 🟡 **REMEDIATE** | CIS-4.8, IAM-2 | No change |
| **28** | Apps via DPDIA | Store nets | External + epayments | ✅ log_all | 🟠 **RESTRICT** | CIS-4.8, IAM-2, **Data-10** | **⬆️ ESCALATED: Data-10 added** |
| **29** | Microsoft SaaS via DIA | Store nets | Microsoft 365/Azure | ✅ log_all | 🟠 **RESTRICT** | CIS-4.8, IAM-2, **Data-10** | **⬆️ ESCALATED: Data-10 added** |
| **30** | CDNs via DIA | Store nets | Akamai/AWS/Google/Azure | ✅ log_all | 🟠 **RESTRICT** | CIS-4.8, IAM-2, **Data-10** | **⬆️ ESCALATED: Data-10 added** |
| **33** | Catch all to Zscaler | Any | ANY | ❌ no_log | 🔴 **REMOVE** | CIS-8.2, CIS-4.8, CIS-12.2, IAM-8, IAM-2, Data-10 | No change |

> **v2 Note — Data-10 (Clarisys NFR) impact:** Rules 28, 29, 30 were previously REMEDIATE; they are now RESTRICT because Data-10 requires external data sharing to use minimal scope and TLS 1.2+. Using ALL services to Microsoft, Akamai, AWS, Google, and epayments.ingenico.com does not satisfy this requirement.

**CIS v8.1 Control 4.8 Requirement:**
> *"Uninstall or disable unnecessary services on enterprise assets and software."*

**Clarisys Violation:** 16 of 34 rules (47%) permit ALL services, allowing any protocol and port combination. Reduces ability to detect anomalous traffic patterns and violates "restrict to minimum required" principle.

**Remediation Path:**
- **Rules 4, 11-12, 14:** Specify exact ports needed for GPU, CCTV, and internal services
- **Rules 23-24:** POS traffic should be restricted to card processing ports (443 HTTPS minimum)
- **Rules 25-26:** Internal RFC1918 can remain broad, but log both directions (currently compliant)
- **Rules 27-30:** SaaS rules should restrict to HTTPS (443) and documented APIs only

---

## Detailed Compliance Report by Rule

### ✅ Compliant Rules (18 rules) — v2

These rules meet all CIS v8.1 IG3, ISO 27001, NIST CSF, PCI-DSS, and Clarisys NFR requirements:

| Rule # | Name | Logging | Services | Status | v1→v2 |
|--------|------|---------|----------|--------|-------|
| 2 | INTERNAL VLAN102-VLAN1432 | ✅ log_all | Specific ports (8081-8102) | ✅ COMPLIANT | No change |
| 3 | VLAN1432 to INTERNAL VLAN102 | ✅ log_all | Specific ports (8081-8102) | ✅ COMPLIANT | No change |
| 6 | VLAN1432 to STORE DNS SERVER | ✅ log_all | DNS (53) | ✅ COMPLIANT | No change |
| 7 | VLAN1432 to DNS VIP | ✅ log_all | DNS (53) | ✅ COMPLIANT | No change |
| 8 | VLAN1432 to VLAN102 ICMP | ✅ log_all | ICMP | ✅ COMPLIANT | No change |
| 9 | VLAN1432 to NTP | ✅ log_all | NTP (123) | ✅ COMPLIANT | No change |
| 13 | VLAN111 HOSTS to INTERNAL DENY | ✅ log_vio | ALL (deny rule) | ✅ COMPLIANT | **NEW** — deny rules exempt from least-privilege |
| 15 | VLAN114 HTTPs Endpoints | ✅ log_all | HTTPS (443) | ✅ COMPLIANT | No change |
| 16 | VLAN114 FTP Endpoints | ✅ log_all | FTP (21) | ✅ COMPLIANT | No change |
| 17 | VLAN114 SNMP-TRAP Endpoints | ✅ log_all | SNMP (161) | ✅ COMPLIANT | No change |
| 18 | VLAN114 Other Endpoints | ✅ log_all | Specific ports | ✅ COMPLIANT | No change |
| 19 | VLAN114 18049 Endpoints | ✅ log_all | Port 18049 | ✅ COMPLIANT | No change |
| 21 | VLAN114 NTP Endpoints | ✅ log_all | NTP (123) | ✅ COMPLIANT | No change |
| 22 | VLAN116 to DHCP Server | ✅ log_all | DHCP (67-68) | ✅ COMPLIANT | No change |
| 23 | VLAN116 to M and S | ✅ log_vio | ALL (deny rule) | ✅ COMPLIANT | **NEW** — deny rule, not applicable to least-privilege |
| 31 | VLAN104 to JUNIPER MIST TCP443 | ✅ log_all | HTTPS (443) | ✅ COMPLIANT | No change |
| 32 | VLAN104 to JUNIPER MIST TCP2200 | ✅ log_all | SSH (2200) | ✅ COMPLIANT | No change |
| 34 | Implicit Deny | ✅ log_vio | ALL (deny) | ✅ COMPLIANT | No change |

> **v2 Note:** Rules 10 and 20 (previously compliant) are now flagged as REMEDIATE because their destination is ANY (CIS-12.2 / Cloud-08 network segmentation requirement). Rules 25 and 26 (previously marked as acceptable RFC1918 exceptions) are now flagged REMEDIATE under IAM-2 (Least Privilege) which does not grant exceptions for internal SDWAN traffic using ALL services.

---

### ⚠️ Non-Compliant Rules (16 rules) — v2

#### Group A: REMOVE — No Logging or Multi-Standard Critical

**Rule 1: INTRA CORP LAN ZONE** 🔴 REMOVE
```
Source:      VLAN101-102-104-107-109-110-117-118 (internal corporate LANs)
Destination: VLAN101-102-104-107-109-110-111-114-117-118 (internal corporate LANs)
Services:    ALL (any protocol/port)
Logging:     ❌ no_log
Action:      accept
```

**Violations:**
- 🔴 CIS-8.2/IAM-8: No logging — audit trail impossible
- 🟠 CIS-4.8/IAM-2: ALL services — violates least privilege

**Recommendation:** 🔴 **REMOVE** this rule entirely
- Internal VLAN-to-VLAN traffic is covered by Rules 2–3, 6–9
- This overly broad rule masks specific traffic patterns and prevents anomaly detection

---

**Rule 24: VLAN116 to DPDIA** 🔴 REMOVE or RESTRICT _(escalated in v2)_
```
Source:      VLAN116 (POS/payment terminals)
Destination: ANY (Dual-Path internet)
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services on payment VLAN
- 🟠 CIS-12.2/Cloud-08: Destination is ANY
- 🔴 PCI-DSS-4.1/Data-Enc-Transit: Payment VLAN allows ALL services — must restrict to HTTPS only
- 🟠 Data-10/NFR-Data10 _(NEW in v2)_: External ANY destination with ALL services violates Clarisys Data Sharing Controls

**Recommendation:** 🔴 **REMOVE or RESTRICT** to `HTTPS` (443) + payment processor IPs only
- PCI-DSS Requirement 4.1 mandates encrypted transport with scoped protocols
- Data-10 requires minimal scope for external data sharing
- Coordinate with POS/payment team before applying change

---

**Rule 33: Catch all to Zscaler** 🔴 REMOVE
```
Source:      Any
Destination: ANY (Zscaler catch-all)
Services:    ALL
Logging:     ❌ no_log
Action:      accept
```

**Violations:**
- 🔴 CIS-8.2/IAM-8: No logging — audit trail impossible
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 CIS-12.2/Cloud-08: Destination is ANY
- 🟠 Data-10/NFR-Data10: External ANY destination with ALL services

**Recommendation:** 🔴 **REMOVE** — catch-all with zero audit trail
- Specific rules (27–30) already cover intended external traffic
- This rule masks any traffic that doesn't match earlier rules

---

#### Group B: RESTRICT — Multiple Violations (Scope Both Service and Destination)

**Rule 5: Catch all to Zscaler_1432** 🟠 RESTRICT
```
Source:      store_main_vlan1432_net
Destination: ANY (Zscaler proxy)
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 CIS-12.2/Cloud-08: Destination is ANY
- 🟠 Data-10/NFR-Data10: External/ANY destination with ALL services

**Recommendation:** 🟠 **RESTRICT** — change to `HTTPS` (443), specify Zscaler proxy IP ranges as destination

---

**Rule 14: VLAN111 to INTERNAL PERMIT** 🟠 RESTRICT
```
Source:      VLAN111 (CCTV)
Destination: ANY (VLAN101-102-104 but rule allows any)
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 CIS-12.2/Cloud-08: Destination is ANY
- 🟠 Data-10/NFR-Data10: External/ANY destination with ALL services

**Recommendation:** 🟠 **RESTRICT** — narrow destination to specific recording/monitoring server IPs; restrict services to documented CCTV management protocols

---

**Rule 28: Apps via DPDIA** 🟠 RESTRICT _(escalated in v2)_
```
Source:      Store networks
Destination: External (epayments.ingenico.com, cloud services)
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 Data-10/NFR-Data10 _(NEW in v2)_: epayments.ingenico.com is an external destination requiring minimal scope

**Recommendation:** 🟠 **RESTRICT** to `HTTPS` (443); document which applications use this rule

---

**Rule 29: Microsoft SaaS via DIA** 🟠 RESTRICT _(escalated in v2)_
```
Source:      Store networks
Destination: Microsoft 365 / Azure / Microsoft ISDB
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 Data-10/NFR-Data10 _(NEW in v2)_: External Microsoft services require minimal scope under Data Sharing Controls

**Recommendation:** 🟠 **RESTRICT** to `HTTPS` (443); use Microsoft 365 ISDB object for IP specificity

---

**Rule 30: CDNs via DIA** 🟠 RESTRICT _(escalated in v2)_
```
Source:      Store networks
Destination: Akamai, AWS, Google, Azure CDNs
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services
- 🟠 Data-10/NFR-Data10 _(NEW in v2)_: External CDN destinations (Akamai, AWS, Google, Azure) require minimal scope

**Recommendation:** 🟠 **RESTRICT** to `HTTP` (80) + `HTTPS` (443) only

---

#### Group C: REMEDIATE — Single Violation (Fix One Control)

**Rule 4: TRAS to VLAN1432** 🟡 REMEDIATE
```
Source:      TRAS network (10.157.26.0/24)
Destination: GPU cluster (10.221.126.34)
Services:    ALL ❌
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: GPU access should be restricted to specific compute protocols

**Recommendation:** 🟡 **REMEDIATE** — change from `ALL` to `["TCP-8081", "TCP-8082", "TCP-8083", "TCP-8092", "TCP-8102"]` (Rule 2 shows the correct pattern)

---

**Rule 10: VLAN111 to INTERNAL Infra** 🟡 REMEDIATE _(newly flagged in v2)_
```
Source:      VLAN111 (CCTV)
Destination: ANY (internal infra)
Services:    ALL_ICMP, DNS, NTP
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-12.2/Cloud-08: Destination is ANY — should be scoped to specific infra IPs

**Recommendation:** 🟡 **REMEDIATE** — specify explicit infra server IPs as destination instead of ANY

---

**Rule 11: VLAN111 to MITIE** 🟡 REMEDIATE
```
Source:      VLAN111 (CCTV infrastructure)
Destination: MITIE network
Services:    ALL ❌
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: CCTV management should be restricted to documented MITIE protocols

**Recommendation:** 🟡 **REMEDIATE** — determine ports from MITIE documentation; restrict to HTTPS (443) + RTSP minimum

---

**Rule 12: MITIE to VLAN111** 🟡 REMEDIATE
```
Source:      MITIE network
Destination: VLAN111 (CCTV)
Services:    ALL ❌
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: Return traffic should mirror Rule 11 restrictions

**Recommendation:** 🟡 **REMEDIATE** — mirror Rule 11 service restrictions

---

**Rule 20: VLAN114 Endpoints** 🟡 REMEDIATE _(newly flagged in v2)_
```
Source:      VLAN114
Destination: ANY
Services:    ALL_TCP
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-12.2/Cloud-08: Destination is ANY — should be scoped to specific endpoint IPs

**Recommendation:** 🟡 **REMEDIATE** — specify explicit endpoint server IPs; compare with Rules 15–19 which correctly name destinations

---

**Rule 25: 10/8 via SDWAN HUB Out** 🟡 REMEDIATE _(newly flagged in v2)_
```
Source:      RFC1918 internal (10.0.0.0/8)
Destination: SDWAN HUB
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services — IAM-2 does not grant RFC1918 exceptions

**Recommendation:** 🟡 **REMEDIATE** — restrict to `HTTPS` + `DNS` + `NTP` for SDWAN overhead; add explicit tunneling protocol if needed

---

**Rule 26: 10/8 via SDWAN HUB In** 🟡 REMEDIATE _(newly flagged in v2)_
```
Source:      SDWAN HUB
Destination: RFC1918 internal (10.0.0.0/8)
Services:    ALL
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: ALL services on inbound SDWAN path

**Recommendation:** 🟡 **REMEDIATE** — mirror Rule 25 restrictions for inbound SDWAN traffic

---

**Rule 27: Apps via DIA** 🟡 REMEDIATE
```
Source:      Store networks (multiple VLANs)
Destination: External SaaS (direct internet access)
Services:    ALL ❌
Logging:     ✅ log_all_sessions
Action:      accept
```

**Violations:**
- 🟠 CIS-4.8/IAM-2: SaaS access should be restricted to HTTPS (443)

**Recommendation:** 🟡 **REMEDIATE** — restrict to `HTTPS` (443); split to separate rules for APIs needing non-standard ports

---

## Compliance Summary by Category — v2

### By Standards Control

| Control | Standard | Violation Type | Affected Rules | Count |
|---------|----------|----------------|----------------|-------|
| **CIS-4.8 / IAM-2** | CIS v8.1 + Clarisys NFR | ALL services (least privilege) | 1, 4, 5, 11, 12, 14, 24, 25, 26, 27, 28, 29, 30, 33 | 14 rules |
| **CIS-8.2 / IAM-8** | CIS v8.1 + Clarisys NFR | No logging | 1, 33 | 2 rules |
| **CIS-12.2 / Cloud-08** | CIS v8.1 + Clarisys NFR | Destination ANY | 5, 10, 14, 20, 24, 33 | 6 rules |
| **PCI-DSS-4.1** | PCI-DSS v3.2.1 | Payment VLAN unencrypted | 24 | 1 rule |
| **Data-10** | Clarisys NFR _(new in v2)_ | External dest + ALL services | 5, 14, 28, 29, 30, 33 | 6 rules |

### By Action Required — v2

| Category | v1 Count | v2 Count | Delta | Rules |
|----------|---------|---------|-------|-------|
| **Remove** | 2 | **3** | +1 | 1, 24, 33 |
| **Restrict** | 3 | **5** | +2 | 5, 14, 28, 29, 30 |
| **Remediate** | 12 | **8** | -4 | 4, 10, 11, 12, 20, 25, 26, 27 |
| **Compliant** | 17 | **18** | +1 | 2, 3, 6–9, 13, 15–19, 21–23, 31, 32, 34 |

---

## Remediation Roadmap — v2

### Phase 1: Critical (Week 1)
- [ ] **Rule 1 (INTRA CORP LAN ZONE):** Remove — verify Rules 2–3, 6–9 provide full coverage first
- [ ] **Rule 33 (Catch all to Zscaler):** Remove — Rules 27–30 and Zscaler proxy handle this traffic
- [ ] **Rule 24 (VLAN116 to DPDIA):** Remove or restrict to HTTPS (443) + payment processor IPs
  - PCI-DSS Requirement 4.1 + Clarisys NFR Data-10 combined make this the highest business risk
  - Must coordinate with POS/payment team before applying

### Phase 2: Restrict (Weeks 2-3)
- [ ] **Rule 5 (Catch all to Zscaler_1432):** Restrict to HTTPS (443), specify Zscaler IPs as destination
- [ ] **Rule 14 (VLAN111 to INTERNAL PERMIT):** Narrow destination to specific recording servers; restrict services to CCTV protocols
- [ ] **Rule 28 (Apps via DPDIA):** Restrict to HTTPS (443) — Data-10 applies (includes epayments.ingenico.com)
- [ ] **Rule 29 (Microsoft SaaS via DIA):** Restrict to HTTPS (443), use Microsoft 365 ISDB for IP specificity
- [ ] **Rule 30 (CDNs via DIA):** Restrict to HTTP (80) + HTTPS (443)

### Phase 3: Remediate Single Violations (Weeks 4-6)
- [ ] **Rule 4:** Change `ALL` → `["TCP-8081", "TCP-8082", "TCP-8083", "TCP-8092", "TCP-8102"]`
- [ ] **Rule 10:** Specify explicit internal infra IPs as destination instead of ANY
- [ ] **Rules 11/12 (MITIE):** Obtain MITIE service documentation; restrict to HTTPS + RTSP
- [ ] **Rule 20:** Specify explicit VLAN114 endpoint IPs instead of ANY
- [ ] **Rules 25/26 (SDWAN):** Restrict to HTTPS + DNS + NTP + VPN encapsulation protocol
- [ ] **Rule 27 (Apps via DIA):** Restrict to HTTPS (443)

### Phase 4: Ongoing
- [ ] Add compliance metadata to all rules in `data.json`:
  ```json
  "compliance_standard": "ISO_27001",
  "data_classification": "INTERNAL",
  "cis_controls": ["CIS-4.8", "CIS-8.2"],
  "review_date": "2026-08-15"
  ```

- [ ] Establish quarterly rule review schedule for CRITICAL rules

---

## Standards Mapping — v2

### CIS v8.1 IG3 Specific Requirements

| Control | Requirement | v1 Status | v2 Status |
|---------|-------------|-----------|----------|
| **CIS 4.4** | Firewall on servers | ✅ Implemented | ✅ No change |
| **CIS 4.8** | Restrict unnecessary services | ⚠️ 16 rules violate | ⚠️ 14 rules violate |
| **CIS 8.2** | Collect audit logs | 🔴 Rules 1, 5, 33 | 🔴 Rules 1, 33 (Rule 5 now logs) |
| **CIS 8.5** | Configure log monitoring | 🟡 Depends on SIEM | 🟡 Depends on SIEM |
| **CIS 12.2** | Secure network architecture | ✅ Rules have segmentation | ⚠️ 6 rules have ANY destination |
| **CIS 13.4** | Traffic filtering between segments | ⚠️ Catch-all rules undermine | ⚠️ Still applies |
| **CIS 13.6** | Network flow logs | 🟠 Deny rules need logging | ✅ Deny rules reviewed |

### ISO 27001 Alignment

- **A.12.4.1** — All access to information must be logged: ❌ Rules 1, 33 (Rule 5 now compliant)
- **A.13.1.1** — Network must be managed securely: ⚠️ Broad rules reduce visibility

### PCI-DSS v3.2.1 Alignment (Payment Systems Only)

- **Requirement 4.1** — Strong encryption for card data in transit
  - Rule 24 (VLAN116 to DPDIA): ❌ Allows unencrypted protocols — now escalated to REMOVE or RESTRICT
  - **Must restrict to HTTPS (TLS 1.2+) only with explicit payment processor IPs**

### Clarisys NFR Alignment (Added v2)

| NFR Control | Requirement | Rules Affected | Status |
|-------------|-------------|----------------|--------|
| **IAM-2** | Least Privilege RBAC — minimal access | 1, 4, 5, 11, 12, 14, 24, 25, 26, 27, 28, 29, 30, 33 | ❌ 14 rules |
| **IAM-8** | Identity Logging — 180-day audit retention | 1, 33 | ❌ 2 rules |
| **Data-10** | Data Sharing Controls — minimal scope + TLS 1.2+ | 5, 14, 28, 29, 30, 33 | ❌ 6 rules |
| **Cloud-08** | Network Isolation — deny-by-default, no broad ANY | 5, 10, 14, 20, 24, 33 | ❌ 6 rules |

---

## Conclusion — v2

**Current Compliance Level:** 53% (18 of 34 rules fully compliant) — up from 47% in v1

**Roadmap to 100%:**
1. Remove Rules 1, 33 (no-log catch-alls)
2. Remove or restrict Rule 24 (PCI-DSS + Data-10 multi-standard critical)
3. Restrict 5 rules with ANY destination + ALL services (Rules 5, 14, 28, 29, 30)
4. Remediate 8 single-violation rules (Rules 4, 10, 11, 12, 20, 25, 26, 27)
5. Add compliance metadata to all rules in `data.json`
6. Establish quarterly review cycle

**Estimated Effort:** 3-4 weeks for full remediation  
**Risk Level:** Medium — existing rules mostly functional but violate standards  
**Business Impact:** Low — changes are restrictions/scoping, not removal of legitimate flows  
**PCI-DSS Risk:** HIGH on Rule 24 — payment VLAN exposure must be addressed before next audit
