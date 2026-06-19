package policy.request_standards

import future.keywords.if

default decision := {
    "compliant": true,
    "violations_count": 0,
    "violations": [],
    "summary": {
        "status": "COMPLIANT",
        "overall_risk": "LOW",
        "violations_found": 0,
        "controls_failing": 0,
        "failed_controls": [],
        "controls_passing": 5,
    },
}

requested_standards := object.get(input, "standards", ["Clarisys NFR"])

iso27001_requested if {
    some s in requested_standards
    s == "ISO 27001"
}

cis_v81_requested if {
    some s in requested_standards
    s == "CIS v8.1"
}

pci_dss_requested if {
    some s in requested_standards
    s == "PCI-DSS"
}

cyber_essentials_requested if {
    some s in requested_standards
    s == "Cyber Essentials"
}

# CIS_13.6 belongs to ISO 27001, CIS v8.1 and Cyber Essentials; PCI-DSS does not require
# dropped-traffic logging and Clarisys NFR does not mandate it for deny rules.
cis_13_6_applicable if { iso27001_requested }
cis_13_6_applicable if { cis_v81_requested }
cis_13_6_applicable if { cyber_essentials_requested }

decision := {
    "compliant": count(violations) == 0,
    "violations_count": count(violations),
    "violations": violations,
    "summary": {
        "status": status,
        "overall_risk": overall_risk,
        "violations_found": count(violations),
        "controls_failing": count({v.control | v := violations[_]}),
        "failed_controls": sort([c | c := {v.control | v := violations[_]}[_]]),
        "controls_passing": 5 - count({v.control | v := violations[_]}),
    },
} if {
    status := "COMPLIANT"
    count(violations) == 0
    overall_risk := "LOW"
}

decision := {
    "compliant": false,
    "violations_count": count(violations),
    "violations": violations,
    "summary": {
        "status": "NON-COMPLIANT",
        "overall_risk": overall_risk,
        "violations_found": count(violations),
        "controls_failing": count({v.control | v := violations[_]}),
        "failed_controls": sort([c | c := {v.control | v := violations[_]}[_]]),
        "controls_passing": 5 - count({v.control | v := violations[_]}),
    },
} if {
    count(violations) > 0
    overall_risk := risk_level
}

violations contains v if {
    lower(object.get(input, "protocol", "")) == "any"
    v := {
        "control": "CIS_4.8",
        "standard": "CIS v8.1 / ISO 27001 / Clarisys NFR / Cyber Essentials",
        "severity": "HIGH",
        "violation": "Protocol ANY is overly permissive",
        "details": "Protocol ANY broadens the request beyond least-privilege scope.",
        "remediation": "Use the specific protocol required by the service.",
    }
}

violations contains v if {
    input.action == "accept"
    input.log == "no_log"
    v := {
        "control": "IAM-8 / Cloud-09 / CIS_8.2",
        "standard": "ISO 27001 / CIS v8.1 / Clarisys NFR / Cyber Essentials",
        "severity": "HIGH",
        "violation": "Allow request does not enable logging",
        "details": "ISO 27001 and CIS IG3 require an audit trail for permitted traffic.",
        "remediation": "Set log to all, utm, or an equivalent audited mode.",
    }
}

violations contains v if {
    input.action == "deny"
    input.log == "no_log"
    cis_13_6_applicable
    v := {
        "control": "CIS_13.6",
        "standard": "ISO 27001 / CIS v8.1 / Cyber Essentials",
        "severity": "MEDIUM",
        "violation": "Deny request does not enable dropped-traffic logging",
        "details": "Dropped traffic should be logged for SOC visibility and forensics.",
        "remediation": "Enable logging for deny requests.",
    }
}

violations contains v if {
    input.action == "accept"
    input.port == 0
    input.protocol != "icmp"
    v := {
        "control": "CIS_4.8",
        "standard": "CIS v8.1 / ISO 27001 / Clarisys NFR / Cyber Essentials",
        "severity": "HIGH",
        "violation": "Request is overly permissive",
        "details": "Port 0 implies unrestricted service scope and violates least privilege.",
        "remediation": "Specify the minimum required protocol and destination port.",
    }
}

violations contains v if {
    not segmented
    v := {
        "control": "Cloud-08 / CIS_12.2",
        "standard": "CIS v8.1 / ISO 27001 / Clarisys NFR / Cyber Essentials",
        "severity": "HIGH",
        "violation": "Request lacks network segmentation metadata",
        "details": "Source and destination interface context should be supplied for zero-trust segmentation checks.",
        "remediation": "Provide non-empty source_interface and destination_interface values.",
    }
}

violations contains v if {
    sensitive_request
    not encrypted_in_transit
    v := {
        "control": "Enc-Transit",
        "standard": encryption_standard,
        "severity": "CRITICAL",
        "violation": "Sensitive traffic lacks TLS 1.2+ protection",
        "details": "Sensitive or payment-related traffic must enforce encryption in transit.",
        "remediation": "Use HTTPS/TLS 1.2+ and set encryption_required=true with tls_version_minimum=1.2 or higher.",
    }
}

violations contains v if {
    input.approved_external_sharing == true
    missing_contract_reference
    v := {
        "control": "Data-10",
        "standard": "ISO 27001 / Clarisys NFR",
        "severity": "HIGH",
        "violation": "Approved external sharing lacks contractual governance",
        "details": "External data sharing must reference a DPA, NDA, or equivalent contract.",
        "remediation": "Supply contract_reference for the approved external data exchange.",
    }
}

segmented if {
    trim(input.source_interface, " ") != ""
    trim(input.destination_interface, " ") != ""
    lower(trim(input.source_interface, " ")) != "proposed-src"
    lower(trim(input.destination_interface, " ")) != "proposed-dst"
}

sensitive_request if {
    classification := lower(object.get(input, "data_classification", ""))
    classification == "confidential"
}

sensitive_request if {
    classification := lower(object.get(input, "data_classification", ""))
    classification == "highly confidential"
}

sensitive_request if {
    contains(lower(input.destination), "payment")
}

sensitive_request if {
    contains(lower(input.destination), "pos")
}

sensitive_request if {
    contains(lower(input.destination), "card")
}

encrypted_in_transit if {
    input.protocol == "tcp"
    input.port == 443
}

encrypted_in_transit if {
    input.protocol == "tcp"
    input.encryption_required == true
    input.tls_version_minimum == "1.2"
}

encrypted_in_transit if {
    input.protocol == "tcp"
    input.encryption_required == true
    input.tls_version_minimum == "1.3"
}

missing_contract_reference if {
    object.get(input, "contract_reference", null) == null
}

missing_contract_reference if {
    trim(object.get(input, "contract_reference", ""), " ") == ""
}

encryption_standard := "ISO 27001 / CIS v8.1 / Clarisys NFR / PCI-DSS / Cyber Essentials" if {
    contains(lower(input.destination), "payment")
}

encryption_standard := "ISO 27001 / CIS v8.1 / Clarisys NFR / PCI-DSS / Cyber Essentials" if {
    contains(lower(input.destination), "pos")
}

encryption_standard := "ISO 27001 / CIS v8.1 / Clarisys NFR / PCI-DSS / Cyber Essentials" if {
    contains(lower(input.destination), "card")
}

encryption_standard := "ISO 27001 / CIS v8.1 / Clarisys NFR / Cyber Essentials" if {
    sensitive_request
    not contains(lower(input.destination), "payment")
    not contains(lower(input.destination), "pos")
    not contains(lower(input.destination), "card")
}

risk_level := "CRITICAL" if {
    some v in violations
    v.severity == "CRITICAL"
}

risk_level := "HIGH" if {
    not some_critical
    some v in violations
    v.severity == "HIGH"
}

risk_level := "MEDIUM" if {
    not some_critical
    not some_high
    some v in violations
    v.severity == "MEDIUM"
}

some_critical if {
    some v in violations
    v.severity == "CRITICAL"
}

some_high if {
    some v in violations
    v.severity == "HIGH"
}