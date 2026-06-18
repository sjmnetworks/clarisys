package policy.request_standards_test

import data.policy.request_standards as request_standards

# ──────────────────────────────────────────────────────────────────────────────
# TEST: COMPLIANT REQUESTS
# ──────────────────────────────────────────────────────────────────────────────

test_tcp_443_request_with_explicit_segmentation_is_compliant if {
    input_data := {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "tcp",
        "port": 443,
        "log": "all",
        "action": "accept",
        "source_interface": "finance-src",
        "destination_interface": "analytics-dst",
        "data_classification": "Internal",
        "approved_external_sharing": false,
    }

    result := request_standards.decision with input as input_data
    result.compliant
    result.violations_count == 0
    result.summary.overall_risk == "LOW"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: SEGMENTATION AND PERMISSIVE PROTOCOL REGRESSIONS
# ──────────────────────────────────────────────────────────────────────────────

test_placeholder_interfaces_are_rejected if {
    input_data := {
        "source": "10.10.1.1",
        "destination": "8.8.8.8",
        "protocol": "udp",
        "port": 53,
        "log": "all",
        "action": "accept",
        "source_interface": "proposed-src",
        "destination_interface": "proposed-dst",
    }

    result := request_standards.decision with input as input_data
    not result.compliant
    some v in result.violations
    v.control == "Cloud-08 / CIS_12.2"
    v.severity == "HIGH"
}

test_any_protocol_is_flagged_as_overly_permissive if {
    input_data := {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "any",
        "port": 443,
        "log": "all",
        "action": "accept",
        "source_interface": "finance-src",
        "destination_interface": "analytics-dst",
    }

    result := request_standards.decision with input as input_data
    not result.compliant
    some v in result.violations
    v.control == "CIS_4.8"
    v.violation == "Protocol ANY is overly permissive"
    result.summary.failed_controls == ["CIS_4.8"]
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: ENCRYPTION REGRESSION
# ──────────────────────────────────────────────────────────────────────────────

test_udp_443_is_not_treated_as_encrypted if {
    input_data := {
        "source": "10.157.26.5",
        "destination": "payment-switch",
        "protocol": "udp",
        "port": 443,
        "log": "all",
        "action": "accept",
        "source_interface": "retail-src",
        "destination_interface": "payment-dst",
        "data_classification": "Confidential",
        "approved_external_sharing": false,
    }

    result := request_standards.decision with input as input_data
    not result.compliant
    some v in result.violations
    v.control == "Enc-Transit"
    v.severity == "CRITICAL"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: PER-STANDARD GATING (CIS_13.6)
# ──────────────────────────────────────────────────────────────────────────────

test_deny_no_log_with_ms_nfr_only_does_not_trigger_cis_13_6 if {
    # Clarisys NFR does not mandate dropped-traffic logging; CIS_13.6 must stay silent.
    input_data := {
        "source": "10.10.1.1",
        "destination": "10.10.2.1",
        "protocol": "tcp",
        "port": 443,
        "log": "no_log",
        "action": "deny",
        "source_interface": "app-src",
        "destination_interface": "app-dst",
        "standards": ["Clarisys NFR"],
    }

    result := request_standards.decision with input as input_data
    result.compliant
    result.violations_count == 0
}

test_deny_no_log_with_iso27001_triggers_cis_13_6 if {
    input_data := {
        "source": "10.10.1.1",
        "destination": "10.10.2.1",
        "protocol": "tcp",
        "port": 443,
        "log": "no_log",
        "action": "deny",
        "source_interface": "app-src",
        "destination_interface": "app-dst",
        "standards": ["Clarisys NFR", "ISO 27001"],
    }

    result := request_standards.decision with input as input_data
    not result.compliant
    some v in result.violations
    v.control == "CIS_13.6"
    v.severity == "MEDIUM"
}

test_deny_no_log_with_pci_dss_only_does_not_trigger_cis_13_6 if {
    # PCI-DSS does not own CIS_13.6; opted-in PCI-DSS should not activate it.
    input_data := {
        "source": "10.10.1.1",
        "destination": "10.10.2.1",
        "protocol": "tcp",
        "port": 443,
        "log": "no_log",
        "action": "deny",
        "source_interface": "app-src",
        "destination_interface": "app-dst",
        "standards": ["Clarisys NFR", "PCI-DSS"],
    }

    result := request_standards.decision with input as input_data
    result.compliant
    result.violations_count == 0
}
