package policy.firewall_compliance

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE-AWARE FIREWALL POLICY
# Evaluates network traffic against M&S security standards:
#   CIS Controls v8.1 (IG3), PCI-DSS v3.2.1, ISO 27001, NIST CSF
# ──────────────────────────────────────────────────────────────────────────────

# Default: implicit deny
default decision := {
    "allow": false,
    "reason": "No matching rule found - implicit deny",
    "matched_rule": null,
    "compliance": [],
    "security_level": 0,
    "warnings": [],
    "category": "DENY"
}

# Main decision: first matching rule wins
decision := result if {
    some rule in data.rules
    matches_rule(rule, input)
    standards := collect_applicable_standards(rule, input)
    level     := determine_security_level(rule, input, standards)
    warnings  := validate_against_standards(rule, input, standards)
    result := {
        "allow":          rule.action == "accept",
        "reason":         rule.name,
        "matched_rule":   rule.id,
        "action":         rule.action,
        "log":            rule.log,
        "comments":       rule.comments,
        "compliance":     standards,
        "security_level": level,
        "warnings":       warnings,
        "category":       get_rule_category(rule)
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# APPLICABLE STANDARDS
# CIS v8.1 + ISO 27001 + NIST CSF apply to all rules.
# PCI-DSS additionally applies to payment-related rules.
# ──────────────────────────────────────────────────────────────────────────────

collect_applicable_standards(rule, req) := standards if {
    base  := {"CIS_v8.1", "ISO_27001", "NIST_CSF"}
    pci   := {s | is_payment_system(rule, req); s := "PCI_DSS"}
    standards := base | pci
}

is_payment_system(rule, _) if { contains(rule.name, "POS") }
is_payment_system(rule, _) if { contains(rule.name, "Payment") }
is_payment_system(rule, _) if { contains(rule.name, "payment") }
is_payment_system(rule, _) if {
    some addr in rule.destination.addresses
    contains(lower(addr), "payment")
}
is_payment_system(rule, _) if {
    some addr in rule.destination.addresses
    contains(lower(addr), "pos")
}
is_payment_system(rule, _) if {
    some addr in rule.destination.addresses
    contains(lower(addr), "card")
}

# ──────────────────────────────────────────────────────────────────────────────
# SECURITY LEVEL (1=low to 4=critical)
# ──────────────────────────────────────────────────────────────────────────────

determine_security_level(rule, req, _) := 4 if { is_payment_system(rule, req) }

determine_security_level(rule, _, _) := 4 if { contains(upper(rule.name), "CRITICAL") }

determine_security_level(rule, req, _) := 2 if {
    not is_payment_system(rule, req)
    not contains(upper(rule.name), "CRITICAL")
    contains(upper(rule.name), "INTERNAL")
}

determine_security_level(rule, req, _) := 3 if {
    not is_payment_system(rule, req)
    not contains(upper(rule.name), "CRITICAL")
    not contains(upper(rule.name), "INTERNAL")
}

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE WARNINGS
# Each standard contributes its own warning set, then all merged.
# ──────────────────────────────────────────────────────────────────────────────

validate_against_standards(rule, req, standards) := warnings if {
    w_pci := {w |
        "PCI_DSS" in standards
        is_payment_system(rule, req)
        rule.nat == false
        w := "PCI-DSS Req 4.1: Payment data in transit requires TLS 1.2+ encryption"
    }
    w_iso := {w |
        "ISO_27001" in standards
        is_payment_system(rule, req)
        rule.log == "no_log"
        w := "ISO 27001 A.12.4: Sensitive data access must be logged"
    }
    w_nist := {w |
        "NIST_CSF" in standards
        count(rule.source.interfaces) == 0
        w := "NIST CSF PR.AC-5: Traffic should specify source interface for network segmentation"
    }
    w_cis8 := {w |
        "CIS_v8.1" in standards
        rule.log == "no_log"
        w := "CIS v8.1 Control 8.2/8.5: All firewall traffic must be logged (IG3 requirement)"
    }
    w_cis12 := {w |
        "CIS_v8.1" in standards
        count(rule.source.interfaces) == 0
        count(rule.source.addresses) == 0
        w := "CIS v8.1 Control 12.2: Rule has no source interface or address - review for segmentation compliance"
    }
    w_cis13 := {w |
        "CIS_v8.1" in standards
        rule.action == "deny"
        rule.log == "no_log"
        w := "CIS v8.1 Control 13.6: Deny rules must log dropped traffic for flow log retention"
    }
    w_cis4 := {w |
        "CIS_v8.1" in standards
        some svc in rule.services
        svc == "ALL"
        w := "CIS v8.1 Control 4.8: Rule permits ALL services - restrict to minimum required ports/protocols"
    }
    warnings := w_pci | w_iso | w_nist | w_cis8 | w_cis12 | w_cis13 | w_cis4
}

# ──────────────────────────────────────────────────────────────────────────────
# RULE CATEGORY
# ──────────────────────────────────────────────────────────────────────────────

get_rule_category(rule) := "CRITICAL"    if { contains(upper(rule.name), "CRITICAL") }
get_rule_category(rule) := "CRITICAL"    if { contains(upper(rule.name), "PAYMENT") }
get_rule_category(rule) := "CRITICAL"    if { contains(upper(rule.name), "POS") }
get_rule_category(rule) := "SECURITY"    if { contains(upper(rule.name), "DENY") }
get_rule_category(rule) := "OPERATIONAL" if { contains(upper(rule.name), "INTERNAL") }
get_rule_category(rule) := "BUSINESS"    if {
    not contains(upper(rule.name), "CRITICAL")
    not contains(upper(rule.name), "PAYMENT")
    not contains(upper(rule.name), "POS")
    not contains(upper(rule.name), "DENY")
    not contains(upper(rule.name), "INTERNAL")
}

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE SUMMARY
# ──────────────────────────────────────────────────────────────────────────────

compliance_summary := summary if {
    decision.allow == true
    summary := {
        "compliant":            count(decision.warnings) == 0,
        "risk_level":           decision.security_level,
        "applicable_standards": decision.compliance,
        "action_required":      count(decision.warnings) > 0,
        "warnings":             decision.warnings
    }
}

compliance_summary := summary if {
    decision.allow == false
    summary := {
        "compliant":            false,
        "status":               "DENIED",
        "risk_level":           0,
        "applicable_standards": [],
        "action_required":      false,
        "warnings":             []
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# AUDIT TRAIL
# ──────────────────────────────────────────────────────────────────────────────

audit := {
    "request":            input,
    "decision":           decision,
    "all_matching_rules": all_matching_rules
}

all_matching_rules[r.id] := r.name if {
    some r in data.rules
    matches_rule(r, input)
}

# ──────────────────────────────────────────────────────────────────────────────
# RULE MATCHING LOGIC
# ──────────────────────────────────────────────────────────────────────────────

matches_rule(rule, req) if {
    matches_source(rule.source, req)
    matches_destination(rule.destination, req)
    matches_service(rule.services, req)
}

matches_source(src_spec, _) if {
    count(src_spec.interfaces) == 0
    count(src_spec.addresses) == 0
}

matches_source(src_spec, req) if {
    count(src_spec.addresses) > 0
    matches_any_address(src_spec.addresses, req.source)
}

matches_destination(dst_spec, _) if {
    count(dst_spec.interfaces) == 0
    count(dst_spec.addresses) == 0
}

matches_destination(dst_spec, req) if {
    count(dst_spec.addresses) > 0
    matches_any_address(dst_spec.addresses, req.destination)
}

matches_service(svc_list, _) if {
    count(svc_list) == 0
}

matches_service(svc_list, req) if {
    count(svc_list) > 0
    some svc in svc_list
    svc_def := data.service_definitions[svc]
    svc_def.match_all == true
}

matches_service(svc_list, req) if {
    count(svc_list) > 0
    some svc in svc_list
    svc_def := data.service_definitions[svc]
    svc_def.match_all == false
    some entry in svc_def.entries
    entry_matches(entry, req)
}

entry_matches(entry, req) if {
    entry.protocol == req.protocol
    entry.protocol == "icmp"
}

entry_matches(entry, req) if {
    entry.protocol == req.protocol
    req.protocol != "icmp"
    port_matches(entry, req.port)
}

port_matches(entry, port) if { entry.port == port }
port_matches(entry, port) if {
    entry.port_min <= port
    entry.port_max >= port
}

matches_any_address(addr_names, target) if {
    some addr_name in addr_names
    addr_def := data.address_groups[addr_name]
    matches_address_def(addr_def, target)
}

matches_address_def(addr_def, target) if {
    count(target.ip) > 0
    some cidr in addr_def.cidrs
    ip_in_cidr(target.ip, cidr)
}

matches_address_def(addr_def, target) if {
    count(target.ip) > 0
    some ip_range in addr_def.ip_ranges
    ip_in_range(target.ip, ip_range)
}

matches_address_def(addr_def, target) if {
    count(target.fqdn) > 0
    some fqdn in addr_def.fqdns
    fqdn_matches(fqdn, target.fqdn)
}

# ──────────────────────────────────────────────────────────────────────────────
# IP MATCHING HELPERS
# ──────────────────────────────────────────────────────────────────────────────

ip_in_cidr(ip, cidr) if {
    contains(cidr, "/")
    parts      := split(cidr, "/")
    net_ip     := parts[0]
    prefix_len := to_number(parts[1])
    ips_in_same_network(ip, net_ip, prefix_len)
}

ip_in_range(ip, range_str) if {
    contains(range_str, "-")
    parts     := split(range_str, "-")
    so        := split(parts[0], ".")
    eo        := split(parts[1], ".")
    io        := split(ip, ".")
    start_num := (to_number(so[0]) * 16777216) + (to_number(so[1]) * 65536) + (to_number(so[2]) * 256) + to_number(so[3])
    end_num   := (to_number(eo[0]) * 16777216) + (to_number(eo[1]) * 65536) + (to_number(eo[2]) * 256) + to_number(eo[3])
    ip_num    := (to_number(io[0]) * 16777216) + (to_number(io[1]) * 65536) + (to_number(io[2]) * 256) + to_number(io[3])
    ip_num >= start_num
    ip_num <= end_num
}

ips_in_same_network(ip1, ip2, 32) if { ip1 == ip2 }

ips_in_same_network(ip1, ip2, 24) if {
    p1 := split(ip1, "."); p2 := split(ip2, ".")
    p1[0] == p2[0]; p1[1] == p2[1]; p1[2] == p2[2]
}

ips_in_same_network(ip1, ip2, 16) if {
    p1 := split(ip1, "."); p2 := split(ip2, ".")
    p1[0] == p2[0]; p1[1] == p2[1]
}

ips_in_same_network(ip1, ip2, 8) if {
    p1 := split(ip1, "."); p2 := split(ip2, ".")
    p1[0] == p2[0]
}

fqdn_matches(pattern, target) if { pattern == target }

fqdn_matches(pattern, target) if {
    startswith(pattern, "*.")
    suffix := trim_prefix(pattern, "*")
    endswith(target, suffix)
}
