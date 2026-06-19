# Implementation Guide: Standards-Aligned Firewall Policy

## Files Created

### Core Policy Files
1. **firewall.rego** - Base firewall logic (existing)
2. **firewall_compliance.rego** - NEW: Compliance checking engine
3. **security_standards.json** - NEW: Standard definitions & templates

### Documentation
- **STANDARDS_GUIDE.md** - Adding rules aligned with standards
- **README.md** - Basic usage (existing)
- **data.json** - Firewall rules & address groups (existing)

---

## Phase 1: Current State (✅ COMPLETE)

Your firewall policy now includes:
- **34 firewall rules** covering store operations
- **35 address groups** for network segmentation
- **8 service definitions** for protocol/port matching
- **IP range matching** for flexible network definitions
- **Comprehensive audit trail** with decision logging

### Current Testing:
```bash
cd /home/ubuntu/calrisys/policy

# Test Rule 4: TRAS to GPU servers (WORKING)
opa eval -i test_rule4.json -d data.json -d firewall.rego 'data.policy.firewall.decision'

# Result: ✅ Allows traffic as expected
```

---

## Phase 2: Standards Alignment (🎯 NEW)

Now enhanced with compliance awareness:

### New Capabilities:

**1. Compliance Detection**
```bash
opa eval -i test_pci_compliant.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.decision'
```

Output will include:
```json
{
  "allow": true,
  "compliance": ["PCI_DSS", "ISO_27001", "NIST_CSF"],
  "security_level": 4,
  "warnings": [],
  "category": "CRITICAL",
  "data_classification": "RESTRICTED"
}
```

**2. Compliance Summary**
```bash
opa eval -i test_pci_compliant.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.compliance_summary'
```

Output:
```json
{
  "status": "COMPLIANT",
  "risk_level": 4,
  "applicable_standards": ["PCI_DSS", "ISO_27001", "NIST_CSF"],
  "action_required": false,
  "warnings": []
}
```

---

## Phase 3: Adding New Rules (Future-Ready)

### Process:

**Step 1: Choose Template**
- Use STANDARDS_GUIDE.md templates
- Define data classification level
- Identify compliance standards

**Step 2: Create Rule**
```json
{
  "seq": 35,
  "id": 104,
  "name": "New Store Analytics API",
  "action": "accept",
  "source": {
    "interfaces": ["VLAN102"],
    "addresses": ["store_main_vlan102_net"]
  },
  "destination": {
    "interfaces": [],
    "addresses": ["analytics.example.com"]
  },
  "services": ["HTTPS"],
  "log": "log_all_sessions",
  "nat": false,
  "install_on": ["FW1-2099"],
  "comments": "ISO 27001: Business analytics - needs HTTPS",
  "compliance_standard": "ISO_27001",
  "data_classification": "INTERNAL"
}
```

**Step 3: Add to data.json**
```bash
# Edit /home/ubuntu/calrisys/policy/data.json
# Add rule to rules array
# Increment _metadata.total_rules
```

**Step 4: Test & Validate**
```bash
# Create test input
cat > test_analytics.json << 'EOF'
{
  "source": {"ip": "10.50.2.100", "fqdn": ""},
  "destination": {"ip": "10.20.1.50", "fqdn": "analytics.example.com"},
  "protocol": "tcp",
  "port": 443,
  "interface_in": "VLAN102",
  "interface_out": "SDWAN.CORP-WAN"
}
EOF

# Test with compliance checking
opa eval -i test_analytics.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.decision'
```

---

## Security Standards Reference

### PCI-DSS (Payment Card Industry)

**When Required:**
- Payment processing systems
- POS terminals
- Card data storage
- Payment gateways

**Requirements:**
```yaml
Encryption:
  Transit: TLS 1.2+
  Rest: AES-256
  
Access_Control:
  MFA: Required for admin
  Segmentation: POS isolated
  
Logging:
  Enabled: Always
  Retention: 1 year
  Audit: Quarterly
  
Rule_Updates:
  Frequency: Quarterly
  Testing: Before production
```

**Example Rule:**
```json
{
  "name": "POS to Payment Gateway - PCI-DSS",
  "compliance_standard": "PCI_DSS",
  "data_classification": "RESTRICTED",
  "requires_encryption": "TLS_1_2_PLUS",
  "audit_logging_required": true,
  "comments": "PCI-DSS v3.2.1 Requirement 1.1"
}
```

### ISO 27001 (Information Security Management)

**When Required:**
- All systems (baseline)
- Especially for sensitive data (HR, financials)

**Requirements:**
```yaml
Access_Control:
  Principle: Least Privilege
  Basis: Job Function
  
Encryption:
  Sensitive_Data: Required
  Transit: TLS 1.2+
  
Audit_Logging:
  Sensitive_Access: Always
  Retention: Varies by data
  
Compliance:
  Frequency: Annual
  Assessment: Full audit
```

**Example Rule:**
```json
{
  "name": "HR Systems Access - ISO 27001",
  "compliance_standard": "ISO_27001",
  "data_classification": "CONFIDENTIAL",
  "requires_encryption": true,
  "audit_logging_required": true
}
```

### NIST Cybersecurity Framework

**When Required:**
- All systems (foundational)
- Risk management framework

**Functions:**
```yaml
Identify:
  Asset_Inventory: Maintain
  Risk_Assessment: Regular
  
Protect:
  Access_Control: Implement
  Data_Security: Encrypt
  
Detect:
  Monitoring: Continuous
  Anomalies: Alert
  
Respond:
  Incident_Plan: Document
  Communication: Notify
  
Recover:
  Resilience: Plan
  Testing: Quarterly
```

**Example Rule:**
```json
{
  "name": "Store Internet via Proxy - NIST Protect",
  "compliance_standard": "NIST_CSF",
  "controls": ["Network Segmentation", "DLP"],
  "proxy_required": true
}
```

---

## Data Classification Levels

Your data falls into these categories:

### 🟢 Level 1: PUBLIC
- Marketing materials
- General web content
- Public APIs

**Access:** Any network
**Encryption:** Optional
**Logging:** Standard

### 🟡 Level 2: INTERNAL
- Internal wikis
- Announcements  
- General business data

**Access:** Internal networks only
**Encryption:** Optional
**Logging:** Standard + audit for sensitive access

### 🟠 Level 3: CONFIDENTIAL
- Store financials
- Employee data
- Business plans

**Access:** Internal networks only
**Encryption:** Required (TLS 1.2+)
**Logging:** All access logged
**Review:** Semi-annual

### 🔴 Level 4: RESTRICTED
- Payment card data (PCI)
- Personal identifiable info (PII)
- Trade secrets
- Security credentials

**Access:** INTERNAL_CORE only
**Encryption:** Required (AES-256)
**MFA:** Required
**Logging:** Detailed audit trail
**Review:** Quarterly

---

## Trust Zones

Map your networks to security zones:

| Zone | Example Networks | Risk | Controls | Encryption |
|------|-----------------|------|----------|-----------|
| **INTERNAL_CORE** | HQ, DCs (10.0.0.0/8) | Low | Basic | Optional |
| **STORE_NETWORKS** | POS VLANs (1432) | Medium | Medium | Optional |
| **EXTERNAL_SAAS** | Cloud APIs | High | Strong | TLS 1.2+ |
| **EXTERNAL_INTERNET** | Public internet | Critical | Strictest | AES-256 |

---

## Compliance Validation

### Automated Checks

The policy now validates:

✅ **Encryption Requirements**
- Payment data must use TLS 1.2+
- Sensitive data encrypted in transit

✅ **Network Segmentation**
- PCI systems isolated
- Clear trust boundaries

✅ **Logging Compliance**
- Sensitive access always logged
- Retention periods met

✅ **Access Control**
- Explicit allows (no wildcards)
- Least privilege principle

✅ **Audit Trail**
- Rule changes tracked
- Compliance history maintained

### Manual Reviews

**Quarterly (PCI-DSS)**
- All payment-related rules
- Encryption settings
- Access logs
- Test rule effectiveness

**Semi-Annually (ISO 27001)**
- Sensitive data rules
- Privilege escalation checks
- New threat assessment

**Annually (All)**
- Full policy audit
- Industry update review
- Vendor compliance checks
- Training effectiveness

---

## Dashboard/Reporting (Ready for Phase 3)

Currently available:
```bash
# Get full audit trail
opa eval -i test_pci_compliant.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.audit'

# Get compliance summary
opa eval -i test_pci_compliant.json \
         -d data.json \
         -d security_standards.json \
         -d firewall_compliance.rego \
         'data.policy.firewall_compliance.compliance_summary'
```

Future enhancements:
- [ ] Real-time compliance dashboard
- [ ] Email/Slack alerts
- [ ] Automated audit reports
- [ ] Policy change notifications
- [ ] Risk scoring
- [ ] Trend analysis

---

## Quick Reference: Add Rule Checklist

```
When Adding a New Rule:
□ Identify compliance standard (PCI/ISO/NIST)
□ Assign data classification (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED)
□ Define source/dest networks explicitly
□ Specify service/protocol/port
□ Set logging (log_all_sessions for sensitive)
□ Identify trust zones (from/to which zone?)
□ Add compliance_standard field
□ Add descriptive comments with justification
□ Get approvals (if CRITICAL category)
□ Test with compliance engine
□ Document review schedule
□ Deploy with change control
□ Monitor for 2 weeks post-deployment
```

---

## Support

### Policy Governance

**Rule Approval Authority:**
- CRITICAL rules: Security + Business lead approval
- BUSINESS rules: Department head approval
- OPERATIONAL rules: Network admin approval
- SUPPORT rules: Network admin approval

**Change Control:**
- All changes via formal request
- Test in staging first
- Document business justification
- Track approval chain

**Review Schedule:**
- CRITICAL: Monthly + quarterly compliance
- BUSINESS: Semi-annual
- OPERATIONAL: Annual
- SUPPORT: Annual

---

## Next Steps

1. **Review** STANDARDS_GUIDE.md to understand templates
2. **Identify** which standards apply to your environment
3. **Update** security_standards.json with your specific requirements
4. **Test** new rules with firewall_compliance.rego
5. **Establish** review schedule for your organization
6. **Train** team on standards-aligned rule addition
7. **Automate** compliance reporting (Phase 3)

---

## Files Structure

```
/home/ubuntu/calrisys/policy/
├── firewall.rego                 # Core logic ✅
├── firewall_compliance.rego      # Compliance validation 🆕
├── data.json                     # Rules & address groups ✅
├── security_standards.json       # Standards definitions 🆕
├── STANDARDS_GUIDE.md           # How-to guide 🆕
├── IMPLEMENTATION_GUIDE.md      # This file 🆕
├── README.md                     # Usage guide ✅
├── test_rule4.json              # Working test ✅
├── test_pci_compliant.json      # Compliance test 🆕
└── generate_data.py             # Data extraction ✅
```

---

## Questions?

For specific scenarios or compliance questions, update `security_standards.json` with your organization's:
- Applicable standards (PCI/ISO/NIST combinations)
- Data classifications
- Trust zones
- Review frequencies
- Approval authorities
