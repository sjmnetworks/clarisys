package policy.firewall

# ──────────────────────────────────────────────────────────────────────────────
# FIREWALL POLICY EVALUATION
# Evaluates network traffic requests against Marks & Spencer store firewall rules
# ──────────────────────────────────────────────────────────────────────────────

# Allow/Deny decision with explanation
default decision := {
    "allow": false,
    "reason": "No matching rule found - implicit deny",
    "matched_rule": null,
    "debug": {}
}

# Main decision logic: iterate through rules in order and find first match
decision := result if {
    some rule in data.rules
    matches_rule(rule, input)
    result := {
        "allow": rule.action == "accept",
        "reason": rule.name,
        "matched_rule": rule.id,
        "action": rule.action,
        "log": rule.log,
        "comments": rule.comments
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# RULE MATCHING LOGIC
# ──────────────────────────────────────────────────────────────────────────────

# A rule matches if source, destination, and service all match
matches_rule(rule, req) if {
    matches_source(rule.source, req)
    matches_destination(rule.destination, req)
    matches_service(rule.services, req)
}

# Source matching: check interface and address
matches_source(src_spec, req) if {
    src_iface := src_spec.interfaces
    src_addr := src_spec.addresses
    
    # Empty source means "any"
    count(src_iface) == 0
    count(src_addr) == 0
}

matches_source(src_spec, req) if {
    src_addr := src_spec.addresses
    count(src_addr) > 0
    matches_any_address(src_addr, req.source)
}

# Destination matching: check interface and address
matches_destination(dst_spec, req) if {
    dst_iface := dst_spec.interfaces
    dst_addr := dst_spec.addresses
    
    # Empty destination means "any"
    count(dst_iface) == 0
    count(dst_addr) == 0
}

matches_destination(dst_spec, req) if {
    dst_addr := dst_spec.addresses
    count(dst_addr) > 0
    matches_any_address(dst_addr, req.destination)
}

# Service/Protocol matching
matches_service(svc_list, req) if {
    # Empty service list or "ALL" means any protocol/port
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
    matches_service_entry(svc_def.entries, req)
}

# Check if request matches any service entry
matches_service_entry(entries, req) if {
    some entry in entries
    entry_matches(entry, req)
}

# Individual service entry matching
entry_matches(entry, req) if {
    entry.protocol == req.protocol
    entry.protocol == "icmp"
}

entry_matches(entry, req) if {
    entry.protocol == req.protocol
    req.protocol != "icmp"
    port_matches(entry, req.port)
}

# Port matching logic
port_matches(entry, port) if {
    entry.port == port
}

port_matches(entry, port) if {
    entry.port_min <= port
    entry.port_max >= port
}

# ──────────────────────────────────────────────────────────────────────────────
# ADDRESS MATCHING LOGIC
# ──────────────────────────────────────────────────────────────────────────────

# Match address against one or more address group/definition names
matches_any_address(addr_names, target) if {
    some addr_name in addr_names
    addr_def := data.address_groups[addr_name]
    matches_address_def(addr_def, target)
}

# Handle address variable references (e.g., "$(store_main_data_summary)")
matches_any_address(addr_names, target) if {
    some addr_name in addr_names
    startswith(addr_name, "$(")
    # Dynamic variable - would need runtime substitution
    # For now, treat as unresolved (will not match)
    false
}

# Check if target IP matches an address definition
matches_address_def(addr_def, target) if {
    target_ip := target.ip
    count(target_ip) > 0
    
    # Try CIDR matching
    some cidr in addr_def.cidrs
    ip_in_cidr(target_ip, cidr)
}

matches_address_def(addr_def, target) if {
    target_ip := target.ip
    count(target_ip) > 0
    
    # Try IP range matching
    some ip_range in addr_def.ip_ranges
    ip_in_range(target_ip, ip_range)
}

matches_address_def(addr_def, target) if {
    target_fqdn := target.fqdn
    count(target_fqdn) > 0
    
    # Try FQDN matching
    some fqdn in addr_def.fqdns
    fqdn_matches(fqdn, target_fqdn)
}

# ──────────────────────────────────────────────────────────────────────────────
# IP/CIDR UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

# Check if IP is in CIDR block
ip_in_cidr(ip, cidr) if {
    contains(cidr, "/")
    parts := split(cidr, "/")
    net_ip := parts[0]
    prefix_len := to_number(parts[1])
    
    # Simple check: normalize IPs and compare
    ips_in_same_network(ip, net_ip, prefix_len)
}

# Check if IP is in a range (e.g., "10.221.126.33-10.221.126.34")
ip_in_range(ip, range_str) if {
    contains(range_str, "-")
    parts := split(range_str, "-")
    start_ip := parts[0]
    end_ip := parts[1]
    
    # Convert IPs to numbers for comparison
    start_octets := split(start_ip, ".")
    end_octets := split(end_ip, ".")
    ip_octets := split(ip, ".")
    
    start_num := (to_number(start_octets[0]) * 256 * 256 * 256) +
                 (to_number(start_octets[1]) * 256 * 256) +
                 (to_number(start_octets[2]) * 256) +
                 to_number(start_octets[3])
    
    end_num := (to_number(end_octets[0]) * 256 * 256 * 256) +
               (to_number(end_octets[1]) * 256 * 256) +
               (to_number(end_octets[2]) * 256) +
               to_number(end_octets[3])
    
    ip_num := (to_number(ip_octets[0]) * 256 * 256 * 256) +
              (to_number(ip_octets[1]) * 256 * 256) +
              (to_number(ip_octets[2]) * 256) +
              to_number(ip_octets[3])
    
    ip_num >= start_num
    ip_num <= end_num
}

# Simplified network check (real implementation would use binary math)
# For demonstration, supports common /32, /24, /16, /8 cases
ips_in_same_network(ip1, ip2, 32) if {
    ip1 == ip2
}

ips_in_same_network(ip1, ip2, 24) if {
    parts1 := split(ip1, ".")
    parts2 := split(ip2, ".")
    parts1[0] == parts2[0]
    parts1[1] == parts2[1]
    parts1[2] == parts2[2]
}

ips_in_same_network(ip1, ip2, 16) if {
    parts1 := split(ip1, ".")
    parts2 := split(ip2, ".")
    parts1[0] == parts2[0]
    parts1[1] == parts2[1]
}

ips_in_same_network(ip1, ip2, 8) if {
    parts1 := split(ip1, ".")
    parts2 := split(ip2, ".")
    parts1[0] == parts2[0]
}

# FQDN matching (supports wildcards)
fqdn_matches(pattern, target) if {
    pattern == target
}

fqdn_matches(pattern, target) if {
    startswith(pattern, "*.")
    suffix := trim_prefix(pattern, "*")
    endswith(target, suffix)
}

# ──────────────────────────────────────────────────────────────────────────────
# AUDIT & LOGGING
# ──────────────────────────────────────────────────────────────────────────────

# Audit trail with all relevant decision details
audit := {
    "timestamp": "2026-05-15T00:00:00Z",
    "request": input,
    "decision": decision,
    "matching_rules": all_matching_rules
}

# Find all matching rules (for audit/debugging)
all_matching_rules[r.id] := r if {
    some r in data.rules
    matches_rule(r, input)
}
