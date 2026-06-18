# Marks & Spencer Store Firewall Policy (OPA/Rego)

This directory contains the Open Policy Agent (OPA) implementation of the M&S store firewall ruleset.

## Files

- **data.json** - Extracted firewall rules, address groups, and service definitions from the Firewall Policy.xlsx spreadsheet
- **firewall.rego** - OPA policy rules for firewall decision-making
- **example_input.json** - Example request to evaluate against the policy
- **generate_data.py** - Python script to regenerate data.json from the spreadsheet

## Quick Start

### Test the policy locally

```bash
# Evaluate a single request
opa eval -i example_input.json -d data.json -d firewall.rego 'data.policy.firewall.decision'

# Get full audit trail
opa eval -i example_input.json -d data.json -d firewall.rego 'data.policy.firewall.audit'

# List all matching rules (debug)
opa eval -i example_input.json -d data.json -d firewall.rego 'data.policy.firewall.all_matching_rules'
```

### Run as a server

```bash
opa run --server -d data.json -d firewall.rego
```

Then query via HTTP:

```bash
# POST the input and get decision
curl -X POST http://localhost:8181/v1/data/policy/firewall/decision \
  -H 'Content-Type: application/json' \
  -d @example_input.json

# Or use the default decision endpoint
curl -X POST http://localhost:8181 \
  -H 'Content-Type: application/json' \
  -d '{"input": '$(cat example_input.json)'}'
```

## Input Format

Requests to evaluate must follow this JSON structure:

```json
{
  "source": {
    "ip": "10.x.x.x",
    "fqdn": "host.domain.com"
  },
  "destination": {
    "ip": "10.x.x.x",
    "fqdn": "api.marksandspencer.com"
  },
  "protocol": "tcp|udp|icmp",
  "port": 443,
  "interface_in": "VLAN114",
  "interface_out": "SDWAN.CORP-WAN"
}
```

## Output Format

Decisions are returned in the following format:

```json
{
  "allow": true,
  "reason": "VLAN114 HTTPs Endpoints",
  "matched_rule": 15,
  "action": "accept",
  "log": "log_all_sessions",
  "comments": ""
}
```

## Policy Rules

The ruleset contains **34 rules** covering:

1. **Intra-corporate LAN access** - Allow VLAN-to-VLAN communication on specific protocols
2. **Internal infrastructure** - DNS, NTP, ICMP between data/mgmt/voice VLANs  
3. **GPU cluster access** - Restricted port access (8081-8102, 13102, 18001-18049)
4. **External apps** - SaaS, CDNs, Microsoft 365 via DIA or corporate WAN
5. **CCTV/Monitoring** - MITIE CCTV connectivity
6. **Catch-all rules** - Default routes to Zscaler ZIA or implicit deny

## Address Groups (35 total)

- **G_STORE-APPS-DIA** - Store applications via Direct Internet Access
- **G_STORE-APPS-DPDIA** - Store applications via dual-path DIA
- **G_MNS-INTERNAL** - M&S internal networks (RFC1918 + corporate subnets)
- **G_DIGITAL-CAFE-STORE** - Digital Cafe POS systems
- **G_API-IDENTITY**, **G_API-PREPROD** - API endpoints
- And many more vendor/service-specific groups

## Service Definitions (8 standard)

- ALL - Any protocol/port
- ALL_TCP - TCP ports 1-65535
- ALL_ICMP - ICMP/Any
- DNS - TCP/UDP 53
- NTP - TCP/UDP 123
- HTTP/HTTPS - TCP 80/443
- FTP - TCP 21

Plus 15+ custom port definitions (8081-8102, 13102, 18001-18049, etc.)

## Regenerating Data

If the spreadsheet changes, regenerate the data file:

```bash
python3 generate_data.py
```

This parses `Firewall Policy.xlsx` and outputs updated `data.json`.

## Notes

- Some address groups reference Fortinet Internet Service Database (ISDB) objects like `Microsoft-Azure`, `Akamai-CDN` which require external resolution
- Dynamic address variables (e.g., `$(store_main_data_summary)`) are per-store and must be populated at runtime
- The policy evaluates rules in sequence; the first matching rule determines allow/deny
- Implicit deny rule (#34) is applied if no prior rule matches

## Testing Examples

### Example 1: Allow TRAS traffic to GPU servers

**Input:**
```json
{
  "source": {"ip": "10.157.26.50", "fqdn": ""},
  "destination": {"ip": "10.221.126.34", "fqdn": ""},
  "protocol": "tcp",
  "port": 443,
  "interface_in": "SDWAN.CORP-WAN",
  "interface_out": "VLAN1432"
}
```

**Expected:** Allow (Rule 4 - "TRAS to VLAN1432" / ID 42)

**Command:**
```bash
opa eval -i test_rule4.json -d data.json -d firewall.rego 'data.policy.firewall.decision'
```

**Result:**
```json
{
  "allow": true,
  "reason": "TRAS to VLAN1432",
  "matched_rule": 42,
  "action": "accept",
  "log": "log_all_sessions",
  "comments": ""
}
```

### Example 2: Deny unmatched traffic

**Input:**
```json
{
  "source": {"ip": "10.111.1.1", "fqdn": ""},
  "destination": {"ip": "10.0.0.1", "fqdn": ""},
  "protocol": "tcp",
  "port": 22,
  "interface_in": "VLAN111",
  "interface_out": "SDWAN.CORP-WAN"
}
```

**Expected:** Deny (No matching rule - implicit deny)

**Result:**
```json
{
  "allow": false,
  "reason": "No matching rule found - implicit deny",
  "matched_rule": null
}
```

### Example 3: Get full audit trail

**Command:**
```bash
opa eval -i test_rule4.json -d data.json -d firewall.rego 'data.policy.firewall.audit'
```

**Result:** Returns complete decision with:
- Original request
- Matching rule (with all details)
- Decision outcome
- Timestamp for audit logging
