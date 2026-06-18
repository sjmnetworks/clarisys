package policy.integrated_compliance

import data.policy.firewall_compliance
import data.policy.nfr_compliance

# ──────────────────────────────────────────────────────────────────────────────
# INTEGRATED COMPLIANCE DECISION
# Combines firewall rule evaluation with comprehensive NFR compliance checking
# Returns a unified assessment across all Clarisys security standards
# ──────────────────────────────────────────────────────────────────────────────

# Main integrated decision
integrated_decision := result if {
    result := {
        "firewall_compliance": firewall_result,
        "nfr_compliance": nfr_result,
        "overall_status": overall_compliance_status,
        "total_violations": count(nfr_compliance.violations) + firewall_violations_count,
        "critical_issues": count(nfr_compliance.critical_violations) + firewall_critical_count,
        "compliance_score": calculate_compliance_score,
        "audit_trail": build_audit_trail
    }
}

# Get firewall compliance result
firewall_result := firewall_compliance.compliance_summary

# Get NFR compliance result  
nfr_result := nfr_compliance.nfr_decision

# Count firewall violations
firewall_violations_count := count(firewall_result.warnings)

firewall_critical_count := count({w | w := firewall_result.warnings[_]; contains(w, "CRITICAL")})

# Audit trail helper
build_audit_trail := trail if {
    trail := {
        "firewall_rules_evaluated": count(input.firewall_rules),
        "data_flows_evaluated": count(input.data_flows),
        "cloud_resources_evaluated": count(input.cloud_resources),
        "identity_ops_evaluated": count(input.identity_operations),
        "decision_timestamp": now_timestamp,
        "evaluation_framework": "CIS_v8.1_IG3 + ISO_27001 + NIST_CSF + PCI_DSS"
    }
}

overall_compliance_status := "COMPLIANT" if {
    firewall_result.compliant == true
    nfr_result.compliant == true
}

overall_compliance_status := "NON-COMPLIANT" if {
    firewall_result.compliant == false
}

overall_compliance_status := "NON-COMPLIANT" if {
    nfr_result.compliant == false
}

# ──────────────────────────────────────────────────────────────────────────────
# OVERALL RISK CALCULATION
# Priority: CRITICAL > HIGH > MEDIUM
# ──────────────────────────────────────────────────────────────────────────────

calculate_overall_risk := "CRITICAL" if {
    critical_count := count(nfr_compliance.critical_violations) + firewall_critical_count
    critical_count > 0
}

calculate_overall_risk := "HIGH" if {
    critical_count := count(nfr_compliance.critical_violations) + firewall_critical_count
    critical_count == 0
    count(nfr_compliance.high_violations) > 0
}

calculate_overall_risk := "MEDIUM" if {
    critical_count := count(nfr_compliance.critical_violations) + firewall_critical_count
    critical_count == 0
    count(nfr_compliance.high_violations) == 0
    count(nfr_result.violations) > 0
}

calculate_overall_risk := "LOW" if {
    critical_count := count(nfr_compliance.critical_violations) + firewall_critical_count
    critical_count == 0
    count(nfr_compliance.high_violations) == 0
    count(nfr_result.violations) == 0
    firewall_violations_count == 0
}

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE SCORE (0-100)
# ──────────────────────────────────────────────────────────────────────────────

calculate_compliance_score := 100 if {
    count(nfr_result.violations) == 0
    firewall_violations_count == 0
}

calculate_compliance_score := score if {
    count(nfr_result.violations) > 0
    total_controls := 30
    passed_controls := total_controls - count(nfr_result.violations) - firewall_violations_count
    raw_score := (passed_controls / total_controls) * 100
    score := raw_score
}

calculate_compliance_score := score if {
    firewall_violations_count > 0
    count(nfr_result.violations) == 0
    total_controls := 30
    passed_controls := total_controls - count(nfr_result.violations) - firewall_violations_count
    raw_score := (passed_controls / total_controls) * 100
    score := raw_score
}

# REMEDIATION PLAN
# Prioritized by severity and business impact

get_remediation_plan := plan if {
    critical := {v | v := nfr_result.violations[_]; v.severity == "CRITICAL"}
    high := {v | v := nfr_result.violations[_]; v.severity == "HIGH"}
    
    plan := {
        "immediate_actions": [item | item := build_remediation_items_critical],
        "30_day_actions": [item | item := build_remediation_items_high],
        "priority_sequence": generate_priority_sequence(critical, high)
    }
}

build_remediation_items_critical := build_remediation_item(v) if {
    v := nfr_result.violations[_]
    v.severity == "CRITICAL"
}

build_remediation_items_high := build_remediation_item(v) if {
    v := nfr_result.violations[_]
    v.severity == "HIGH"
}

build_remediation_item(violation) := item if {
    item := {
        "control": violation.control,
        "resource": violation.resource_id,
        "issue": violation.violation,
        "remediation": violation.remediation,
        "severity": violation.severity,
        "estimated_effort": estimate_effort(violation.severity),
        "business_impact": get_impact(violation.control)
    }
}

estimate_effort(severity) := "1-2 hours" if {
    severity == "CRITICAL"
}

estimate_effort(severity) := "2-4 hours" if {
    severity == "HIGH"
}

estimate_effort(severity) := "4-8 hours" if {
    severity == "MEDIUM"
}

get_impact(control) := "Prevents unauthorized access" if {
    control == "IAM-1"
}

get_impact(control) := "Ensures privilege accountability" if {
    control == "IAM-3"
}

get_impact(control) := "Protects data confidentiality in transit" if {
    control == "Enc-Transit"
}

get_impact(control) := "Protects data confidentiality at rest" if {
    control == "Enc-Rest"
}

get_impact(control) := "Restricts cloud service access to private networks" if {
    control == "Cloud-02"
}

get_impact(control) := "Protects encryption keys" if {
    control == "Cloud-04"
}

get_impact(control) := "Implements zero-trust network segmentation" if {
    control == "Cloud-08"
}

get_impact(control) := "Improves security posture" if {
    not control in ["IAM-1", "IAM-3", "Enc-Transit", "Enc-Rest", "Cloud-02", "Cloud-04", "Cloud-08"]
}

# ──────────────────────────────────────────────────────────────────────────────
# PRIORITY SEQUENCE
# Returns ordered list of actions by criticality and business impact
# ──────────────────────────────────────────────────────────────────────────────

generate_priority_sequence(critical_viol, high_viol) := sequence if {
    # Critical IAM and encryption violations first
    priority_1 := {v | v := critical_viol[_]; v.control in ["IAM-1", "IAM-3", "Enc-Transit", "Enc-Rest"]}
    
    # Then cloud security
    priority_2 := {v | v := critical_viol[_]; v.control in ["Cloud-02", "Cloud-04", "Cloud-08"]}
    
    # Then remaining critical (all others)
    priority_3 := critical_viol
    
    # Then high priority
    priority_4 := high_viol
    
    sequence := [
        {"priority": 1, "actions": array_from_set(priority_1)},
        {"priority": 2, "actions": array_from_set(priority_2)},
        {"priority": 3, "actions": array_from_set(priority_3)},
        {"priority": 4, "actions": array_from_set(priority_4)}
    ]
}

# COMPLIANCE REPORT
# Summary suitable for executive/audit review

get_compliance_report := {
    "report_title": "Clarisys Integrated Compliance Assessment",
    "report_date": now_timestamp,
    "overall_status": overall_compliance_status,
    "compliance_score": calculate_compliance_score,
    "risk_level": calculate_overall_risk,
    "total_violations": count(nfr_result.violations),
    "critical_issues": count({v | v := nfr_result.violations[_]; v.severity == "CRITICAL"}),
    "high_issues": count({v | v := nfr_result.violations[_]; v.severity == "HIGH"}),
    "firewall_violations": firewall_violations_count,
    "next_review": add_days(now_timestamp, 30)
}

assess_standard(standard_name) := assessment if {
    violations_for_std := {v | v := nfr_result.violations[_]; contains(v.standard, standard_name)}
    count(violations_for_std) == 0
    
    assessment := {
        "standard": standard_name,
        "violations": count(violations_for_std),
        "status": "COMPLIANT",
        "coverage": count({c | c := nfr_result.compliant_controls[_]; contains(c, standard_name)})
    }
}

assess_standard(standard_name) := assessment if {
    violations_for_std := {v | v := nfr_result.violations[_]; contains(v.standard, standard_name)}
    count(violations_for_std) > 0
    
    assessment := {
        "standard": standard_name,
        "violations": count(violations_for_std),
        "status": "NON-COMPLIANT",
        "coverage": count({c | c := nfr_result.compliant_controls[_]; contains(c, standard_name)})
    }
}

generate_key_findings := findings if {
    nfr_result.critical_violations > 0
    findings := [
        sprintf("CRITICAL: %s - %s", [v.control, v.violation]) |
        v := nfr_result.violations[_];
        v.severity == "CRITICAL"
    ]
}

generate_key_findings := ["No critical violations found"] if {
    nfr_result.critical_violations == 0
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

now_timestamp := ts if {
    # In real Rego, use time.now_ns() - for testing, use placeholder
    ts := "2026-05-15T15:30:00Z"
}

array_from_set(s) := arr if {
    arr := [item | item := s[_]]
}

add_days(timestamp, days) := result if {
    # Placeholder - would use time functions in production
    result := sprintf("%s (+ %d days)", [timestamp, days])
}
