# Security Standards-Aligned Policy Framework

## Overview

This framework ensures firewall rules comply with:
- **NIST Cybersecurity Framework (CSF)**
- **ISO 27001** - Information Security Management
- **PCI-DSS v3.2.1** - Payment Card Industry standards

---

## Quick Start: Adding New Rules

### 1. Identify the Rule Type

Check which security standard applies:

```
Payment/Card Data?  → PCI-DSS (CRITICAL)
Employee/HR Data?   → ISO 27001 (CONFIDENTIAL)
General Business?   → ISO 27001 (INTERNAL/BUSINESS)
Internet Access?    → NIST CSF (HIGH risk)
```

### 2. Use the Appropriate Template

**Template A: Internal-to-Internal (Low Risk)**
```json
{
  "seq": 35,
  "id": 100,
  "name": "Internal DNS Resolution",
  "action": "accept",
  "source": {
    "interfaces": ["VLAN101", "VLAN102"],
    "addresses": ["10.0.0.0_8"]
  },
  "destination": {
    "interfaces": [],
    "addresses": ["store_main_vlan101_dns_server"]
  },
  "services": ["DNS"],
  "log": "log_all_sessions",
  "nat": false,
  "install_on": ["FW1-2099"],
  "comments": "DNS resolution - ISO 27001 compliant",
  "compliance_standard": "ISO_27001",
  "data_classification": "INTERNAL"
}
```

**Template B: Store-to-SaaS (Medium Risk - PCI-DSS)**
```json
{
  "seq": 36,
  "id": 101,
  "name": "Store POS to Payment Gateway",
  "action": "accept",
  "source": {
    "interfaces": ["VLAN1432"],
    "addresses": ["store_main_vlan1432_net"]
  },
  "destination": {
    "interfaces": [],
    "addresses": ["G_EUROCHANGE-VERIFONE"]
  },
  "services": ["HTTPS"],
  "log": "log_all_sessions",
  "nat": false,
  "install_on": ["FW1-2099"],
  "comments": "PCI-DSS: Payment data encrypted in transit",
  "compliance_standard": "PCI_DSS",
  "data_classification": "RESTRICTED",
  "requires_mfa": true,
  "requires_encryption": "TLS_1_2_PLUS",
  "audit_logging_required": true
}
```

**Template C: Internet Access (High Risk - NIST)**
```json
{
  "seq": 37,
  "id": 102,
  "name": "Store Internet via Proxy - NIST Compliant",
  "action": "accept",
  "source": {
    "interfaces": ["VLAN114"],
    "addresses": ["store_main_vlan114_net"]
  },
  "destination": {
    "interfaces": ["SDWAN.DIA"],
    "addresses": ["all"]
  },
  "services": ["HTTP", "HTTPS"],
  "log": "log_all_sessions",
  "nat": false,
  "install_on": ["FW1-2099"],
  "comments": "NIST: All internet via proxy for inspection",
  "compliance_standard": "NIST_CSF",
  "data_classification": "PUBLIC",
  "proxy_required": true,
  "requires_encryption": "TLS_1_2_PLUS",
  "requires_dlp_inspection": true
}
```

### 3. Validation Checklist

Before adding a rule, verify:

```
☐ Source and destination networks clearly defined (no "any" unless justified)
☐ Service ports/protocols explicitly listed
☐ Logging enabled for sensitive traffic
☐ Compliance standard identified (PCI/ISO/NIST)
☐ Data classification assigned
☐ Install target specified
☐ Comments explain business purpose + compliance justification
☐ Rule doesn't duplicate existing rules
☐ Quarterly review date noted if critical
```

---

## Security Standards Mapping

### PCI-DSS (Payment Card Industry Data Security Standard)

**Applies to:** Payment systems, POS terminals, card data storage

**Requirements:**
- ✅ Explicit allow rules (no implicit allows)
- ✅ Encryption in transit (TLS 1.2+)
- ✅ Network segmentation (POS isolated)
- ✅ Logging with 1-year retention
- ✅ Quarterly rule reviews
- ✅ Strong authentication (MFA for admins)

**Rule Examples:**
```
Name: "POS to Payment Gateway - PCI-DSS"
Compliance: PCI_DSS
Data_Classification: RESTRICTED
Requires_Encryption: TLS_1_2_PLUS
Audit_Logging: true
```

### ISO 27001 (Information Security Management)

**Applies to:** All systems

**Requirements:**
- ✅ Access control based on job function
- ✅ Encryption for sensitive data
- ✅ Incident response procedures
- ✅ Audit logging for sensitive access
- ✅ Annual compliance assessment

**Rule Examples:**
```
Name: "HR Systems Access - ISO 27001"
Compliance: ISO_27001
Data_Classification: CONFIDENTIAL
Requires_Encryption: true
Audit_Logging: true
Review_Frequency: Annual
```

### NIST Cybersecurity Framework

**Applies to:** All systems

**Functions:**
1. **Identify** - Know your assets & data
2. **Protect** - Implement safeguards
3. **Detect** - Identify security events
4. **Respond** - Take action
5. **Recover** - Restore systems

**Rule Examples:**
```
Name: "Store Internet via Proxy - NIST Protect"
Compliance: NIST_CSF
Function: Protect
Controls: ["Network Segmentation", "DLP Inspection"]
Proxy_Required: true
```

---

## Data Classification Levels

### Level 1: PUBLIC
- Publicly available information
- Marketing, general web content
- **Min Trust Zone:** EXTERNAL_INTERNET
- **Encryption Required:** No

### Level 2: INTERNAL
- Internal use only
- Wikis, announcements
- **Min Trust Zone:** STORE_NETWORKS
- **Encryption Required:** No

### Level 3: CONFIDENTIAL
- Sensitive business data
- Store financials, employee data
- **Min Trust Zone:** STORE_NETWORKS
- **Encryption Required:** Yes (TLS 1.2+)

### Level 4: RESTRICTED
- Highly sensitive, regulated
- PCI payment data, PII, trade secrets
- **Min Trust Zone:** INTERNAL_CORE
- **Encryption Required:** Yes (AES-256)
- **MFA Required:** Yes
- **Audit Logging:** Yes

---

## Trust Zones

| Zone | Level | Networks | Risk | Encryption | Logging |
|------|-------|----------|------|-----------|---------|
| INTERNAL_CORE | 1 | HQ, DCs (10.0.0.0/8) | Low | Optional | Always |
| STORE_NETWORKS | 2 | VLANs (1432, 102) | Medium | Optional | Always |
| EXTERNAL_SAAS | 3 | APIs, cloud | High | Required | Always |
| EXTERNAL_INTERNET | 4 | Public internet | Critical | Required | Always |

---

## Rule Review & Maintenance

### Quarterly (PCI-DSS Required)
- Review all CRITICAL category rules
- Check for unused rules
- Verify logging is active
- Test rule enforcement

### Semi-Annually (ISO 27001)
- Review all CONFIDENTIAL data access rules
- Audit encryption settings
- Check compliance with industry updates

### Annually (All Standards)
- Full policy audit
- Update for new threats/standards
- Training for approvers
- Document lessons learned

---

## Adding Rules: Step-by-Step Example

### Scenario: New SaaS vendor for store analytics

**Step 1: Classify**
```
Type: Business application
Data: Store metrics (INTERNAL)
Standard: ISO 27001
Risk: Medium
```

**Step 2: Use Template**
```json
{
  "seq": 38,
  "id": 103,
  "name": "Store Analytics to SaaS Vendor",
  "action": "accept",
  "source": {
    "interfaces": ["VLAN102"],
    "addresses": ["store_main_vlan102_net"]
  },
  "destination": {
    "interfaces": [],
    "addresses": ["analytics-vendor.com"]
  },
  "services": ["HTTPS"],
  "log": "log_all_sessions",
  "nat": false,
  "install_on": ["FW1-2099"],
  "comments": "ISO 27001: Store metrics analytics - vendor contract signed 2026-05-15",
  "compliance_standard": "ISO_27001",
  "data_classification": "INTERNAL",
  "requires_encryption": "TLS_1_2_PLUS"
}
```

**Step 3: Validate**
- ✅ Source/dest specific
- ✅ Service explicit (HTTPS only)
- ✅ Logging enabled
- ✅ Compliance noted
- ✅ Data class assigned
- ✅ Encryption required

**Step 4: Deploy**
- Test in staging
- Get approval (change control if CRITICAL)
- Deploy to production
- Document in change log

**Step 5: Monitor**
- Watch logs for anomalies
- Verify traffic patterns expected
- Schedule next review: 3 months

---

## Testing Your Policy

### Test Compliance Policy
```bash
# Test with compliance checking
opa eval -i test_pci_traffic.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.decision'
```

### Check Compliance Summary
```bash
opa eval -i test_pci_traffic.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.compliance_summary'
```

---

## Future Enhancements

### Ready for Implementation:
- [ ] Automated compliance scanning for new rules
- [ ] Slack/email alerts for non-compliant traffic
- [ ] Dashboard showing compliance status
- [ ] Automated report generation for auditors
- [ ] AI-powered threat detection integration
- [ ] Zero Trust policy implementation

### Planned:
- [ ] Multi-store policy inheritance
- [ ] Role-based access control (RBAC) policies
- [ ] Data residency enforcement
- [ ] Geolocation-based rules
- [ ] Machine learning anomaly detection

---

## Support & Questions

Reference Documents:
- `security_standards.json` - Standard definitions
- `firewall_compliance.rego` - Compliance evaluation engine
- `data.json` - Current policy data
- `firewall.rego` - Core matching logic
