# Quick Reference: Rules Requiring Action — v2 (2026-05-15)

> **v2 update:** Added M&S NFR standards (IAM-2, IAM-8, Data-10, Cloud-08). Rule 24 escalated to REMOVE. Rules 28, 29, 30 escalated to RESTRICT. Rules 10 and 20 newly flagged. See COMPLIANCE_AUDIT.md for full detail.

## Summary
- **Total Rules:** 34
- **Compliant:** 18 (53%) ✅ _(was 16/47% in v1)_
- **Non-Compliant:** 16 (47%) ⚠️
- **Should Remove:** 3 rules _(was 2 in v1)_
- **Should Restrict:** 5 rules _(was 3 in v1)_
- **Should Remediate:** 8 rules _(was 12 in v1)_

---

## Rules to REMOVE (3 — Immediate Priority)

| Rule # | Name | Reason | Standards | v1→v2 |
|--------|------|--------|-----------|-------|
| **1** | INTRA CORP LAN ZONE | No logging + ALL services + overly broad | CIS-8.2, IAM-8, CIS-4.8 | No change |
| **24** | VLAN116 to DPDIA | PCI-DSS + Data-10 + ANY dest + ALL services | PCI-DSS-4.1, Data-10, CIS-12.2, CIS-4.8 | **ESCALATED from REMEDIATE** |
| **33** | Catch all to Zscaler | No logging + ALL services + ANY destination | CIS-8.2, IAM-8, CIS-4.8, Data-10 | No change |

> **Rule 24:** Remove or restrict to `HTTPS` (443) with explicit payment processor IPs only. Coordinate with POS/payment team. This is the highest business risk — PCI-DSS + M&S NFR Data-10 dual failure.

---

## Rules to RESTRICT (5 — Multiple Violations)

| Rule # | Name | Current | Should Be | Standards | v1→v2 |
|--------|------|---------|-----------|-----------|-------|
| **5** | Catch all to Zscaler_1432 | ALL, ANY dst | HTTPS (443), Zscaler IPs | CIS-4.8, CIS-12.2, Data-10 | No change |
| **14** | VLAN111 to INTERNAL PERMIT | ALL, ANY dst | CCTV protocols, specific IPs | CIS-4.8, CIS-12.2, Data-10 | No change |
| **28** | Apps via DPDIA | ALL | HTTPS (443) | CIS-4.8, **Data-10** | **ESCALATED from REMEDIATE** |
| **29** | Microsoft SaaS via DIA | ALL | HTTPS (443) | CIS-4.8, **Data-10** | **ESCALATED from REMEDIATE** |
| **30** | CDNs via DIA | ALL | HTTP (80) + HTTPS (443) | CIS-4.8, **Data-10** | **ESCALATED from REMEDIATE** |

---

## Rules to REMEDIATE (8 — Single Violation)

| Rule # | Name | Fix | Standard | v1→v2 |
|--------|------|-----|----------|-------|
| **4** | TRAS to VLAN1432 | Change ALL → TCP-8081/8082/8083/8092/8102 | CIS-4.8, IAM-2 | No change |
| **10** | VLAN111 to INTERNAL Infra | Specify infra IPs instead of ANY dst | CIS-12.2, Cloud-08 | **NEWLY FLAGGED** |
| **11** | VLAN111 to MITIE | Change ALL → CCTV/RTSP + HTTPS | CIS-4.8, IAM-2 | No change |
| **12** | MITIE to VLAN111 | Mirror Rule 11 restrictions | CIS-4.8, IAM-2 | No change |
| **20** | VLAN114 Endpoints | Specify endpoint IPs instead of ANY dst | CIS-12.2, Cloud-08 | **NEWLY FLAGGED** |
| **25** | 10/8 via SDWAN HUB Out | Change ALL → HTTPS + DNS + NTP | CIS-4.8, IAM-2 | **NEWLY FLAGGED** |
| **26** | 10/8 via SDWAN HUB In | Mirror Rule 25 restrictions | CIS-4.8, IAM-2 | **NEWLY FLAGGED** |
| **27** | Apps via DIA | Change ALL → HTTPS (443) | CIS-4.8, IAM-2 | No change |

---

## Fully Compliant Rules (18) — No Changes Required

```
2, 3, 6, 7, 8, 9, 13, 15, 16, 17, 18, 19, 21, 22, 23, 31, 32, 34
```

> v2 additions: Rules 13 and 23 confirmed compliant (deny rules, exempt from least-privilege checks); Rules 34 (Implicit Deny) confirmed compliant.  
> v2 removals: Rules 10, 20, 25, 26 moved from compliant to REMEDIATE due to CIS-12.2/Cloud-08 and IAM-2 failures.

---

## Standards Mapping — v2

| Rule # | Name | CIS-4.8/IAM-2 | CIS-8.2/IAM-8 | CIS-12.2/Cloud-08 | PCI-DSS-4.1 | Data-10 | Action |
|--------|------|--------------|--------------|-------------------|-------------|---------|--------|
| 1 | INTRA CORP LAN ZONE | ❌ | ❌ | ✅ | ✅ | ✅ | 🔴 REMOVE |
| 4 | TRAS to VLAN1432 | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 5 | Catch all to Zscaler_1432 | ❌ | ✅ | ❌ | ✅ | ❌ | 🟠 RESTRICT |
| 10 | VLAN111 to INTERNAL Infra | ✅ | ✅ | ❌ | ✅ | ✅ | 🟡 REMEDIATE |
| 11 | VLAN111 to MITIE | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 12 | MITIE to VLAN111 | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 14 | VLAN111 to INTERNAL PERMIT | ❌ | ✅ | ❌ | ✅ | ❌ | 🟠 RESTRICT |
| 20 | VLAN114 Endpoints | ✅ | ✅ | ❌ | ✅ | ✅ | 🟡 REMEDIATE |
| 24 | VLAN116 to DPDIA | ❌ | ✅ | ❌ | ❌ | ❌ | 🔴 REMOVE/RESTRICT |
| 25 | 10/8 via SDWAN HUB Out | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 26 | 10/8 via SDWAN HUB In | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 27 | Apps via DIA | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 REMEDIATE |
| 28 | Apps via DPDIA | ❌ | ✅ | ✅ | ✅ | ❌ | 🟠 RESTRICT |
| 29 | Microsoft SaaS via DIA | ❌ | ✅ | ✅ | ✅ | ❌ | 🟠 RESTRICT |
| 30 | CDNs via DIA | ❌ | ✅ | ✅ | ✅ | ❌ | 🟠 RESTRICT |
| 33 | Catch all to Zscaler | ❌ | ❌ | ❌ | ✅ | ❌ | 🔴 REMOVE |

---

## Actionable Checklist — v2

### Immediate (This Week)
- [ ] Remove Rule 1 (INTRA CORP LAN ZONE) — confirm Rules 2–3, 6–9 cover all traffic
- [ ] Remove Rule 33 (Catch all to Zscaler) — confirm Rules 27–30 cover traffic
- [ ] Coordinate with POS/payment teams on Rule 24 (VLAN116 to DPDIA) — PCI-DSS + Data-10 critical

### Short Term (Next 2 Weeks)
- [ ] Restrict Rule 5 to HTTPS (443) + Zscaler proxy IPs
- [ ] Restrict Rule 14 to CCTV management protocols + specific server IPs
- [ ] Restrict Rules 28, 29, 30 to HTTPS (443) — Data-10 compliance required
- [ ] Pull MITIE service documentation for Rules 11/12 restrictions

### Medium Term (Next 4 Weeks)
- [ ] Restrict Rule 4 (TRAS→GPU) to TCP-8081/8082/8083/8092/8102
- [ ] Specify explicit destinations for Rules 10, 20 (replace ANY with IPs)
- [ ] Restrict Rules 25/26 (SDWAN) to HTTPS + DNS + NTP
- [ ] Restrict Rule 27 (Apps via DIA) to HTTPS (443)

### Ongoing
- [ ] Set quarterly review calendar for CRITICAL rules
- [ ] Monitor OPA compliance warnings in production
- [ ] Add compliance metadata fields to all rules in `data.json` (compliance_standard, review_date, cis_controls)

---

## Impact Assessment — v2

| Action | Business Impact | Compliance Gain | Priority |
|--------|-----------------|-----------------|----------|
| Remove Rule 1 | Low — covered by Rules 2–9 | +1 logging | Week 1 |
| Remove Rule 33 | Low — covered by 27–30 | +1 logging | Week 1 |
| Restrict/Remove Rule 24 (POS) | Medium — validate with POS teams | PCI-DSS + Data-10 | Week 1 |
| Restrict Rules 28, 29, 30 | Low — HTTPS is standard | +3 Data-10 | Week 2 |
| Restrict Rule 5, 14 | Low — scoping only | +2 Cloud-08 | Week 2 |
| Remediate Rules 4, 11, 12, 27 | Low — known services | +4 CIS-4.8 | Week 4 |
| Remediate Rules 10, 20, 25, 26 | Low — specify IPs | +4 Cloud-08/IAM-2 | Week 4 |

**Overall Risk:** Low — restrictions don't block legitimate traffic  
**Overall Effort:** 3–4 weeks  
**Compliance ROI:** 53% → 100% alignment across CIS v8.1 IG3, ISO 27001, PCI-DSS 4.1, and M&S NFRs
