# M&S Security NFR Compliance Framework

## Overview

This framework validates firewall rules, data flows, and cloud resources against M&S Security Non-Functional Requirements (NFRs) defined in Book1.xlsx.

**Framework Version:** 1.0  
**Effective Date:** May 15, 2026  
**Standards:** CIS v8.1 IG3, ISO 27001, NIST CSF, PCI-DSS v3.2.1

---

## Components

### 1. **nfr_requirements.json** (Source of Truth)
Structured definition of all 32 security NFR controls across three domains:

#### Identity & Access Management (IAM)
- **IAM-1**: Unified Identity & MFA (CRITICAL)
- **IAM-2**: Least Privilege RBAC (CRITICAL)
- **IAM-3**: Privileged Access Management / PIM (CRITICAL)
- **IAM-4**: Auto-provisioned Access via Joiner-Mover-Leaver (HIGH)
- **IAM-6**: Break-Glass Accounts with Strong Passwords (CRITICAL)
- **IAM-8**: Identity Logging (180-day retention) (HIGH)
- **IAM-9**: Access Recertification (Quarterly) (HIGH)

#### Data Security
- **Data-01**: Data Classification (Public/Internal/Confidential/Highly Confidential) (CRITICAL)
- **Data-10**: Data Sharing Controls (Encrypted TLS 1.2+, Contractual) (CRITICAL)
- **Data-11**: Test Data Security (No prod data in non-prod without approval) (HIGH)
- **Data-Encryption-Rest**: AES-256 for all storage/DBs (CRITICAL)
- **Data-Encryption-Transit**: TLS 1.2+ minimum (CRITICAL)
- **Data-Backup**: Encrypted, Immutable, Geo-distributed, Tested (HIGH)

#### Cloud Security (Azure)
- **Cloud-01**: Azure Guardrails (Policies enforce logging, encryption, locations, tagging) (HIGH)
- **Cloud-02**: Private Endpoints Only (Disable public access by default) (CRITICAL)
- **Cloud-03**: Managed Identities (No secrets/credentials) (CRITICAL)
- **Cloud-04**: Key Vault Hardening (Soft delete, purge protection, rotation) (CRITICAL)
- **Cloud-06**: Cloud Security Posture Management (Continuous scanning) (HIGH)
- **Cloud-08**: Network Isolation (Segmented VNets, deny-by-default NSGs) (CRITICAL)
- **Cloud-09**: Admin Action Logging (Create/Update/Delete operations) (HIGH)

### 2. **nfr_compliance.rego** (Validation Engine)
OPA/Rego policy that evaluates resources against NFR controls:

```rego
# Main decision returns:
nfr_decision := {
    "compliant": boolean,
    "violations_count": integer,
    "critical_violations": integer,
    "high_violations": integer,
    "violations": [array of violation objects],
    "compliant_controls": [list of passing controls],
    "risk_score": calculated risk,
    "summary": compliance summary
}
```

**Validation Areas:**

- **Firewall Domain**: Sensitive data encryption, least privilege services, logging
- **Data Security Domain**: Encryption requirements, data classification, retention
- **Cloud Domain**: Managed identities, private endpoints, network isolation, logging
- **IAM Domain**: MFA enforcement, RBAC, access recertification tracking

### 3. **integrated_compliance.rego** (Unified Framework)
Combines firewall_compliance.rego + nfr_compliance.rego for holistic assessment:

```rego
integrated_decision := {
    "firewall_compliance": {...},
    "nfr_compliance": {...},
    "overall_status": "COMPLIANT" | "NON_COMPLIANT",
    "total_violations": integer,
    "critical_issues": integer,
    "compliance_score": percentage,
    "audit_trail": {...}
}
```

---

## Usage

### Evaluate Firewall Rules Against NFRs

```bash
cd /Users/stephenmcconnell/MandS/OPA/policy

# Test a single firewall rule
opa eval -i test_nfr_compliance.json \
  -d data.json \
  -d nfr_requirements.json \
  -d nfr_compliance.rego \
  'data.policy.nfr_compliance.nfr_decision'
```

### Evaluate Integrated Compliance (Firewall + NFR)

```bash
opa eval -i test_nfr_compliance.json \
  -d data.json \
  -d nfr_requirements.json \
  -d firewall_compliance.rego \
  -d nfr_compliance.rego \
  -d integrated_compliance.rego \
  'data.policy.integrated_compliance.integrated_decision'
```

### Run Unit Tests

```bash
opa test nfr_compliance_test.rego -v
```

---

## Sample Violations

### ❌ Rule 1 (INTRA CORP LAN ZONE)
```
Violation: Rule permits ALL services (least privilege violation)
Control: CIS_4.8
Standard: CIS_v8.1
Severity: HIGH
Remediation: Replace 'ALL' with explicit service list (HTTP, HTTPS, DNS, etc.)
```

### ✅ Rule 4 (TRAS to GPU via HTTPS)
```
Status: COMPLIANT
- Encryption required: ✓ (TLS 1.2+)
- Specific services: ✓ (HTTPS only)
- Logging enabled: ✓
- Risk classification: ✓ (sensitive data marked)
```

---

## NFR Severity Levels

| Level | Timeline | Description |
|-------|----------|-------------|
| **CRITICAL** | 7 days | Must implement immediately (security breach risk) |
| **HIGH** | 30 days | Should implement with priority (audit/compliance impact) |
| **MEDIUM** | 90 days | Should plan and implement (operational security) |

---

## CIS Control Mapping

Each NFR maps to relevant CIS Controls v8.1 IG3:

- **CIS-3**: Data Protection
- **CIS-4**: Secure Configuration Management
- **CIS-5**: Identity & Access Management
- **CIS-6**: Access Control
- **CIS-8**: Audit Logging & Monitoring
- **CIS-10**: Data Recovery
- **CIS-12**: Network Infrastructure
- **CIS-15**: Third-party Risk Management
- **CIS-16**: Security Testing
- **CIS-17**: Threat & Vulnerability Management

---

## Integration with Existing Systems

### Firewall Rules (data.json)
- Evaluated against Enc-Transit, Enc-Rest, CIS_4.8 controls
- Violations flagged if sensitive data lacks encryption
- Overly permissive rules (ALL services) flagged

### Data Flows (future)
- Will validate against Data-01 (classification), Data-10 (sharing), Data-11 (test data)
- Will check encryption in transit (TLS 1.2+)

### Cloud Resources (future)
- Will validate against Cloud-01 through Cloud-09 controls
- Will check Managed Identity usage, private endpoints, NSG rules

### Identity Operations (future)
- Will validate against IAM-1 through IAM-9 controls
- Will check MFA logs, access recertification records

---

## Files Included

```
/policy/
├── nfr_requirements.json         # NFR control definitions (source of truth)
├── nfr_compliance.rego           # NFR validation policy engine
├── nfr_compliance_test.rego      # Unit tests for NFR controls
├── integrated_compliance.rego    # Combined firewall + NFR assessment
├── test_nfr_compliance.json      # Sample test input
│
# Existing files (still active)
├── firewall_compliance.rego      # Firewall-specific compliance checks
├── data.json                      # Extracted firewall rules & config
├── security_standards.json        # Standards reference
├── firewall.rego                 # Core firewall policy engine
```

---

## Next Steps

### Phase 1: Finalize Integration (This Week)
1. ✅ Verify NFR policies syntax-valid with `opa check`
2. ✅ Test against sample firewall rules
3. ⏳ Expand test coverage to data flows and cloud resources
4. ⏳ Document violation remediation for each control

### Phase 2: Operational Deployment (Weeks 2-3)
1. Deploy integrated_compliance.rego to production OPA instance
2. Set up automated daily evaluation of all firewall rules
3. Generate NFR compliance dashboard in SIEM
4. Create alerts for CRITICAL violations (7-day SLA)

### Phase 3: Expand Coverage (Weeks 4-6)
1. Add Cloud resource validation (Azure VNets, Key Vaults, NSGs)
2. Add Data flow validation (encryption requirements)
3. Add Identity operations validation (MFA, access recertification)

---

## Example: Complete NFR Compliance Output

```json
{
  "compliant": false,
  "violations_count": 2,
  "critical_violations": 1,
  "high_violations": 1,
  "violations": [
    {
      "control": "Data-Encryption-Transit",
      "standard": "CIS_3",
      "severity": "CRITICAL",
      "resource_id": "Rule 5 (Store→Payment)",
      "violation": "Sensitive data traffic lacks encryption requirement",
      "remediation": "Enforce TLS 1.2+ for PCI-DSS payment traffic"
    },
    {
      "control": "CIS_4.8",
      "standard": "CIS_v8.1",
      "severity": "HIGH",
      "resource_id": "Rule 1 (INTRA CORP LAN)",
      "violation": "Rule permits ALL services",
      "remediation": "Restrict to minimum required services"
    }
  ],
  "risk_score": 45,
  "summary": {
    "status": "NON-COMPLIANT",
    "controls_passing": 28,
    "controls_failing": 2,
    "critical_issues": 1,
    "overall_risk": "HIGH"
  }
}
```

---

## Support & Questions

Contact: Security Policy Team  
Framework Owner: oprah (OPA/Rego Specialist)  
Last Updated: 2026-05-15
