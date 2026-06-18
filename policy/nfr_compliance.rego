package policy.nfr_compliance

# ──────────────────────────────────────────────────────────────────────────────
# Clarisys SECURITY NFR COMPLIANCE POLICY
# Validates firewall rules, data flows, and cloud resources against:
#   - Identity & Access Management (IAM-1 through IAM-9)
#   - Data Security (Encryption, Classification, Sharing)
#   - Cloud Security / Azure Guardrails (Cloud-01 through Cloud-09)
#
# Standards: CIS v8.1 IG3, ISO 27001, NIST CSF, PCI-DSS v3.2.1
# ──────────────────────────────────────────────────────────────────────────────

import future.keywords.contains
import future.keywords.if

# Default: no violations
default violations := []

# ──────────────────────────────────────────────────────────────────────────────
# MAIN DECISION: Assess NFR compliance
# ──────────────────────────────────────────────────────────────────────────────

nfr_decision := {
    "compliant": count(violations) == 0,
    "violations_count": count(violations),
    "critical_violations": count(critical_violations),
    "high_violations": count(high_violations),
    "violations": violations,
    "compliant_controls": compliant_controls,
    "risk_score": calculate_risk_score(violations),
    "summary": compliance_summary
}

# Aggregate violations across all domains
violations := {v | v := firewall_violations[_]} | {v | v := data_security_violations[_]} | {v | v := cloud_violations[_]} | {v | v := iam_violations[_]}

# ──────────────────────────────────────────────────────────────────────────────
# FIREWALL DOMAIN: Data Encryption & Network Segmentation
# ──────────────────────────────────────────────────────────────────────────────

firewall_violations[v] if {
    some rule in input.firewall_rules
    
    # Check if rule handles sensitive data (payment/PII/confidential)
    is_sensitive_traffic(rule)
    
    # Sensitive traffic MUST use encryption
    not has_encryption_requirement(rule)
    
    v := {
        "control": "Enc-Transit",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "firewall_rule",
        "resource_id": rule.name,
        "violation": "Sensitive data traffic lacks encryption requirement",
        "details": sprintf("Rule '%s' (action: %s) handles sensitive data but TLS not enforced", 
                          [rule.name, rule.action]),
        "remediation": "Add encryption_required: true and tls_version_minimum: 1.2"
    }
}

firewall_violations[v] if {
    some rule in input.firewall_rules
    
    # Check for overly permissive rules (all services)
    contains(rule.services, "ALL")
    rule.action == "accept"
    
    v := {
        "control": "CIS_4.8",
        "standard": "CIS_v8.1",
        "severity": "HIGH",
        "resource_type": "firewall_rule",
        "resource_id": rule.name,
        "violation": "Rule permits ALL services (least privilege violation)",
        "details": sprintf("Rule '%s' allows unlimited services - restrict to minimum required", 
                          [rule.name]),
        "remediation": "Replace 'ALL' with explicit service list (HTTP, HTTPS, DNS, etc.)"
    }
}

firewall_violations[v] if {
    some rule in input.firewall_rules
    rule.action == "accept"
    
    # Check for source/destination network segmentation
    count(rule.source.addresses) == 0
    count(rule.source.interfaces) == 0
    
    v := {
        "control": "Cloud-08 / CIS_12.2",
        "standard": "CIS_v8.1",
        "severity": "HIGH",
        "resource_type": "firewall_rule",
        "resource_id": rule.name,
        "violation": "Rule lacks source segmentation (zero-trust network violation)",
        "details": sprintf("Rule '%s' has no source address or interface restriction", 
                          [rule.name]),
        "remediation": "Specify source interface and/or address group for network segmentation"
    }
}

firewall_violations[v] if {
    some rule in input.firewall_rules
    
    # Check logging requirement (IAM-8, Cloud-09)
    rule.log == "no_log"
    rule.action == "accept"
    
    v := {
        "control": "IAM-8 / Cloud-09 / CIS_8.2",
        "standard": "CIS_v8.1",
        "severity": "HIGH",
        "resource_type": "firewall_rule",
        "resource_id": rule.name,
        "violation": "Allow rule not logged (audit trail gap)",
        "details": sprintf("Rule '%s' (action: accept) has logging disabled - audit trail required", 
                          [rule.name]),
        "remediation": "Enable logging: log = 'all' or 'utm'"
    }
}

firewall_violations[v] if {
    some rule in input.firewall_rules
    rule.action == "deny"
    rule.log == "no_log"
    
    v := {
        "control": "CIS_13.6",
        "standard": "CIS_v8.1",
        "severity": "MEDIUM",
        "resource_type": "firewall_rule",
        "resource_id": rule.name,
        "violation": "Deny rule not logged (dropped traffic invisible to SOC)",
        "details": sprintf("Rule '%s' (deny) requires logging for security monitoring", 
                          [rule.name]),
        "remediation": "Enable logging on deny rules for forensics and threat detection"
    }
}

# Helper: Check if traffic is sensitive
is_sensitive_traffic(rule) if {
    some addr in rule.destination.addresses
    contains_sensitive_keyword(addr)
}

is_sensitive_traffic(rule) if {
    contains(upper(rule.name), "PAYMENT")
}

is_sensitive_traffic(rule) if {
    contains(upper(rule.name), "POS")
}

is_sensitive_traffic(rule) if {
    contains(upper(rule.name), "CARD")
}

# Keywords indicating sensitive data
contains_sensitive_keyword(addr) if {
    keywords := ["PAYMENT", "POS", "CARD", "PII", "CONFIDENTIAL", "SECURE", "CARD_PROCESSING"]
    some keyword in keywords
    contains(upper(addr), keyword)
}

# Helper: Check if rule requires encryption
has_encryption_requirement(rule) if {
    rule.encryption_required == true
}

has_encryption_requirement(rule) if {
    rule.tls_version_minimum != null
    tls_version_acceptable(rule.tls_version_minimum)
}

# ──────────────────────────────────────────────────────────────────────────────
# DATA SECURITY DOMAIN: Encryption, Classification, Sharing
# ──────────────────────────────────────────────────────────────────────────────

data_security_violations[v] if {
    some flow in input.data_flows
    
    # All data must be classified (Data-01)
    flow.data_classification == null
    flow.data_classification == ""
    
    v := {
        "control": "Data-01",
        "standard": "CIS_3",
        "severity": "HIGH",
        "resource_type": "data_flow",
        "resource_id": sprintf("%s -> %s", [flow.source_system, flow.destination_system]),
        "violation": "Data flow lacks classification",
        "details": "All data must be classified as Public/Internal/Confidential/Highly Confidential",
        "remediation": "Assign appropriate classification and data owner"
    }
}

data_security_violations[v] if {
    some flow in input.data_flows
    
    # Sensitive data must be encrypted in transit (Enc-Transit)
    is_sensitive_classification(flow.data_classification)
    flow.encryption_in_transit != "TLS_1.2"
    flow.encryption_in_transit != "TLS_1.3"
    flow.encryption_in_transit != "encrypted"
    
    v := {
        "control": "Enc-Transit",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "data_flow",
        "resource_id": sprintf("%s -> %s", [flow.source_system, flow.destination_system]),
        "violation": "Sensitive data lacks TLS 1.2+ encryption in transit",
        "details": sprintf("Data classified as %s must use TLS 1.2+, found: %s", 
                          [flow.data_classification, flow.encryption_in_transit]),
        "remediation": "Enable TLS 1.2+ on all data flows carrying sensitive information"
    }
}

data_security_violations[v] if {
    some flow in input.data_flows
    
    # All data must be encrypted at rest (Enc-Rest)
    flow.encryption_at_rest != "AES-256"
    flow.encryption_at_rest != "encrypted"
    
    v := {
        "control": "Enc-Rest",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "data_flow",
        "resource_id": sprintf("%s -> %s (storage)", [flow.source_system, flow.destination_system]),
        "violation": "Data storage lacks AES-256 encryption",
        "details": sprintf("Current encryption: %s (required: AES-256)", 
                          [flow.encryption_at_rest]),
        "remediation": "Enable AES-256 encryption for all storage systems"
    }
}

data_security_violations[v] if {
    some flow in input.data_flows
    
    # External sharing requires contractual governance (Data-10)
    flow.approved_external_sharing == true
    flow.contract_reference == null
    flow.contract_reference == ""
    
    v := {
        "control": "Data-10",
        "standard": "CIS_3 / CIS_15",
        "severity": "HIGH",
        "resource_type": "data_flow",
        "resource_id": sprintf("%s -> %s (external)", [flow.source_system, flow.destination_system]),
        "violation": "External data sharing lacks contractual governance",
        "details": "External data sharing must be covered by data processing agreement",
        "remediation": "Establish DPA/NDA with external recipient and document reference"
    }
}

data_security_violations[v] if {
    some flow in input.data_flows
    
    # Test data must not use production data (Data-11)
    flow.environment == "test"
    flow.environment == "dev"
    flow.uses_production_data == true
    flow.data_anonymized != true
    flow.data_masked != true
    
    v := {
        "control": "Data-11",
        "standard": "CIS_3 / CIS_16",
        "severity": "HIGH",
        "resource_type": "data_flow",
        "resource_id": sprintf("%s (non-prod)", [flow.source_system]),
        "violation": "Non-production environment using live production data",
        "details": "Test/dev environments must not use production data unless anonymized/masked",
        "remediation": "Replace with anonymized test data or apply data masking"
    }
}

# Helper: Is classification sensitive?
is_sensitive_classification(classification) if {
    sensitive := {"Confidential", "Highly Confidential", "PCI", "GDPR", "Healthcare"}
    classification in sensitive
}

# ──────────────────────────────────────────────────────────────────────────────
# CLOUD SECURITY DOMAIN: Azure, Network Isolation, Key Vault
# ──────────────────────────────────────────────────────────────────────────────

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # PaaS resources must use private endpoints (Cloud-02)
    is_paas_service(resource.resource_type)
    resource.private_endpoint_enabled != true
    
    v := {
        "control": "Cloud-02",
        "standard": "CIS_12",
        "severity": "CRITICAL",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("%s (%s)", [resource.name, resource.resource_type]),
        "violation": "PaaS service missing private endpoint",
        "details": sprintf("%s in %s (environment: %s) lacks private endpoint", 
                          [resource.resource_type, resource.location, resource.environment]),
        "remediation": "Enable private endpoint and disable public access for PaaS service"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # All cloud resources must be encrypted (Cloud-04 / Enc-Rest)
    not is_non_encrypted_service(resource.resource_type)
    resource.encryption_enabled != true
    
    v := {
        "control": "Cloud-04 / Enc-Rest",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("%s (%s)", [resource.name, resource.resource_type]),
        "violation": "Cloud resource missing encryption",
        "details": sprintf("%s requires encryption enabled", [resource.resource_type]),
        "remediation": "Enable encryption at rest using customer-managed or Microsoft-managed keys"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # All cloud resources must have logging (Cloud-01 / Cloud-09)
    resource.logging_enabled != true
    
    v := {
        "control": "Cloud-01 / Cloud-09 / CIS_8",
        "standard": "CIS_8",
        "severity": "HIGH",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("%s (%s)", [resource.name, resource.resource_type]),
        "violation": "Cloud resource logging disabled",
        "details": "Diagnostic settings / monitoring not enabled for resource",
        "remediation": "Enable logging/diagnostics and forward to central Log Analytics workspace"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    resource.resource_type == "Azure_KeyVault"
    
    # Key Vault must have soft delete (Cloud-04)
    resource.soft_delete_enabled != true
    
    v := {
        "control": "Cloud-04",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("KeyVault: %s", [resource.name]),
        "violation": "Key Vault soft delete not enabled",
        "details": "Soft delete protects against accidental key deletion",
        "remediation": "Enable soft delete on Key Vault"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    resource.resource_type == "Azure_KeyVault"
    
    # Key Vault must have purge protection (Cloud-04)
    resource.purge_protection_enabled != true
    
    v := {
        "control": "Cloud-04",
        "standard": "CIS_3",
        "severity": "CRITICAL",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("KeyVault: %s", [resource.name]),
        "violation": "Key Vault purge protection not enabled",
        "details": "Purge protection prevents deletion during soft delete retention period",
        "remediation": "Enable purge protection on Key Vault"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # Workloads should use managed identity (Cloud-03)
    resource.resource_type in ["Azure_AppService", "Azure_VM", "Azure_AKS", "Azure_FunctionApp"]
    resource.managed_identity_enabled != true
    
    v := {
        "control": "Cloud-03",
        "standard": "CIS_5 / CIS_6 / CIS_16",
        "severity": "HIGH",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("%s (%s)", [resource.name, resource.resource_type]),
        "violation": "Workload not using managed identity",
        "details": "Workloads should use Managed Identity instead of storing credentials",
        "remediation": "Enable System/User-assigned Managed Identity and remove credential secrets"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # Network security groups must have deny-by-default inbound (Cloud-08)
    is_nsg_resource(resource)
    count(resource.inbound_rules) > 0
    not has_default_deny_inbound(resource.inbound_rules)
    
    v := {
        "control": "Cloud-08",
        "standard": "CIS_12",
        "severity": "HIGH",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("NSG: %s", [resource.name]),
        "violation": "Network Security Group lacks deny-by-default inbound rules",
        "details": "NSG should explicitly allow only required ports, deny all else",
        "remediation": "Restructure NSG rules: explicit allows followed by deny *"
    }
}

cloud_violations[v] if {
    some resource in input.cloud_resources
    
    # VNets should be segmented by tier (Cloud-08)
    resource.resource_type == "Azure_VirtualNetwork"
    count(resource.subnets) < 3
    
    v := {
        "control": "Cloud-08",
        "standard": "CIS_12",
        "severity": "MEDIUM",
        "resource_type": "cloud_resource",
        "resource_id": sprintf("VNet: %s", [resource.name]),
        "violation": "Virtual Network lacks multi-tier segmentation",
        "details": "VNet should have separate subnets for web/app/data tiers",
        "remediation": "Create separate subnets for presentation, application, and data layers"
    }
}

# Helpers for cloud checks
is_paas_service(resource_type) if {
    paas_types := ["Azure_AppService", "Azure_SQLDatabase", "Azure_CosmosDB", 
                   "Azure_StorageAccount", "Azure_FunctionApp", "Azure_ApiManagement"]
    resource_type in paas_types
}

is_non_encrypted_service(resource_type) if {
    # Some services don't have encryption toggles
    resource_type in ["Azure_LoadBalancer", "Azure_PublicIP"]
}

is_nsg_resource(resource) if {
    resource.resource_type == "Azure_NetworkSecurityGroup"
}

has_default_deny_inbound(inbound_rules) if {
    some rule in inbound_rules
    rule.priority > 65000  # Default rules start at 65000
    rule.action == "Deny"
    rule.source_address_prefix == "*"
}

# ──────────────────────────────────────────────────────────────────────────────
# IDENTITY & ACCESS MANAGEMENT DOMAIN
# ──────────────────────────────────────────────────────────────────────────────

iam_violations[v] if {
    some identity_op in input.identity_operations
    
    # IAM-1: All access requests must have MFA enforced
    identity_op.authentication_method == "password_only"
    
    v := {
        "control": "IAM-1",
        "standard": "CIS_5 / CIS_6",
        "severity": "CRITICAL",
        "resource_type": "identity_operation",
        "resource_id": sprintf("User: %s", [identity_op.user_id]),
        "violation": "User authentication without MFA",
        "details": sprintf("User %s uses password-only auth (no MFA)", [identity_op.user_id]),
        "remediation": "Enforce MFA for all user accounts via Azure AD Conditional Access"
    }
}

iam_violations[v] if {
    some identity_op in input.identity_operations
    
    # IAM-3: Privileged access requires approval
    identity_op.operation_type == "elevated_access"
    identity_op.approval_status != "approved"
    
    v := {
        "control": "IAM-3",
        "standard": "CIS_5",
        "severity": "CRITICAL",
        "resource_type": "identity_operation",
        "resource_id": sprintf("User: %s (op: %s)", [identity_op.user_id, identity_op.action]),
        "violation": "Elevated access request lacking approval",
        "details": sprintf("Privileged access %s by %s requires approval and justification", 
                          [identity_op.action, identity_op.user_id]),
        "remediation": "Route all PIM requests through approval workflow with justification"
    }
}

iam_violations[v] if {
    some identity_op in input.identity_operations
    
    # IAM-3: Privileged access must be time-limited
    identity_op.operation_type == "elevated_access"
    identity_op.expiry_date == null
    
    v := {
        "control": "IAM-3",
        "standard": "CIS_5",
        "severity": "HIGH",
        "resource_type": "identity_operation",
        "resource_id": sprintf("User: %s (op: %s)", [identity_op.user_id, identity_op.action]),
        "violation": "Elevated access lacks expiry date",
        "details": "Privileged access must have time limit to prevent standing admin roles",
        "remediation": "Set activation duration for PIM access (e.g., 8-hour maximum)"
    }
}

iam_violations[v] if {
    some identity_op in input.identity_operations
    
    # IAM-8: All access operations must be logged
    identity_op.logged == false
    
    v := {
        "control": "IAM-8 / Cloud-09",
        "standard": "CIS_8",
        "severity": "HIGH",
        "resource_type": "identity_operation",
        "resource_id": sprintf("User: %s (op: %s)", [identity_op.user_id, identity_op.action]),
        "violation": "Identity operation not logged",
        "details": sprintf("Access operation %s by %s not recorded in audit logs", 
                          [identity_op.action, identity_op.user_id]),
        "remediation": "Enable Azure AD audit logging and forward to SIEM/Log Analytics"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE SUMMARY & SCORING
# ──────────────────────────────────────────────────────────────────────────────

critical_violations := {v | v := violations[_]; v.severity == "CRITICAL"}

high_violations := {v | v := violations[_]; v.severity == "HIGH"}

compliant_controls := all_controls - violated_controls

violated_controls := {c | v := violations[_]; c := v.control}

all_controls := {
    "IAM-1", "IAM-2", "IAM-3", "IAM-4", "IAM-6", "IAM-8", "IAM-9",
    "Data-01", "Data-10", "Data-11", "Enc-Rest", "Enc-Transit", "Backup",
    "Cloud-01", "Cloud-02", "Cloud-03", "Cloud-04", "Cloud-06", "Cloud-08", "Cloud-09",
    "CIS_3", "CIS_4.8", "CIS_5", "CIS_6", "CIS_8", "CIS_12", "CIS_12.2", "CIS_13.6"
}

calculate_risk_score(viols) := score if {
    critical_count := count({v | v := viols[_]; v.severity == "CRITICAL"})
    high_count := count({v | v := viols[_]; v.severity == "HIGH"})
    medium_count := count({v | v := viols[_]; v.severity == "MEDIUM"})
    
    # Risk formula: 100 points per CRITICAL, 25 per HIGH, 5 per MEDIUM
    score := (critical_count * 100) + (high_count * 25) + (medium_count * 5)
}

compliance_summary := summary if {
    summary := {
        "status": "COMPLIANT",
        "violations_found": 0,
        "critical_issues": 0,
        "high_issues": 0,
        "controls_passing": count(all_controls),
        "controls_failing": 0,
        "overall_risk": "LOW"
    }
    count(violations) == 0
}

compliance_summary := summary if {
    critical := count(critical_violations)
    high := count(high_violations)
    
    critical > 0
    risk_level := "CRITICAL"
    
    summary := {
        "status": "NON-COMPLIANT",
        "violations_found": count(violations),
        "critical_issues": critical,
        "high_issues": high,
        "controls_passing": count(compliant_controls),
        "controls_failing": count(violated_controls),
        "overall_risk": risk_level
    }
    count(violations) > 0
}

compliance_summary := summary if {
    critical := count(critical_violations)
    high := count(high_violations)
    
    critical == 0
    high > 0
    risk_level := "HIGH"
    
    summary := {
        "status": "NON-COMPLIANT",
        "violations_found": count(violations),
        "critical_issues": critical,
        "high_issues": high,
        "controls_passing": count(compliant_controls),
        "controls_failing": count(violated_controls),
        "overall_risk": risk_level
    }
    count(violations) > 0
}

compliance_summary := summary if {
    critical := count(critical_violations)
    high := count(high_violations)
    
    critical == 0
    high == 0
    risk_level := "MEDIUM"
    
    summary := {
        "status": "NON-COMPLIANT",
        "violations_found": count(violations),
        "critical_issues": critical,
        "high_issues": high,
        "controls_passing": count(compliant_controls),
        "controls_failing": count(violated_controls),
        "overall_risk": risk_level
    }
    count(violations) > 0
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

tls_version_acceptable(version) if {
    acceptable := {"TLS_1.2", "TLS_1.3", "1.2", "1.3"}
    version in acceptable
}
