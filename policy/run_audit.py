#!/usr/bin/env python3
import json

with open('data.json') as f:
    data = json.load(f)

rules = data['rules']

def audit_rule(r):
    seq      = r['seq']
    name     = r['name']
    action   = r['action']
    services = r.get('services', [])
    log      = r.get('log', '')
    src      = r['source'].get('addresses', [])
    dst      = r['destination'].get('addresses', [])
    src_str  = ' '.join(src).lower()
    dst_str  = ' '.join(dst).lower()
    has_ALL  = 'ALL' in services and 'ALL_ICMP' not in str(services) and 'ALL_TCP' not in str(services)
    # Allow ALL_ICMP and ALL_TCP as they are scoped
    has_ALL_unrestricted = 'ALL' in services

    violations = []

    # CIS-8.2 / IAM-8: Accept rules must log
    if action == 'accept' and log == 'no_log':
        violations.append(("CRITICAL", "CIS-8.2/IAM-8", "No logging on accept rule — audit trail impossible"))

    # CIS-4.8 / IAM-2: ALL services on accept rules
    if action == 'accept' and has_ALL_unrestricted and services == ['ALL']:
        violations.append(("HIGH", "CIS-4.8/IAM-2", "ALL services permitted — violates least privilege"))

    # CIS-12.2 / Cloud-08: Destination 'all' on accept
    if action == 'accept' and ('all' in dst or len(dst) == 0) and 'Implicit' not in name:
        violations.append(("HIGH", "CIS-12.2/Cloud-08", "Destination is ANY — no network segmentation"))

    # PCI-DSS 4.1 / Data-Enc-Transit: VLAN116 is payment zone
    if 'vlan116' in src_str and action == 'accept':
        if services == ['ALL']:
            violations.append(("CRITICAL", "PCI-DSS-4.1/Data-Enc-Transit", "Payment VLAN116 allows ALL services — must restrict to HTTPS only"))

    # Data-10 / NFR-Data10: External destinations with ALL services
    external_keywords = ['epayments', 'microsoft', 'akamai', 'amazon', 'google', 'zscaler']
    dst_is_external = any(kw in dst_str for kw in external_keywords)
    dst_is_any = 'all' in dst or len(dst) == 0
    if action == 'accept' and (dst_is_external or dst_is_any) and services == ['ALL'] and 'Implicit' not in name:
        violations.append(("HIGH", "Data-10/NFR-Data10", "External/ANY destination with ALL services — must use minimal scope (Data Sharing Controls)"))

    # Cloud-08: Broad /8 source with no dest restriction
    if action == 'accept' and '10.0.0.0_8' in src_str and ('all' in dst or len(dst) == 0):
        violations.append(("CRITICAL", "Cloud-08", "Broad /8 source with ANY destination — violates deny-by-default network isolation"))

    # Determine recommendation
    is_catch_all_no_log = log == 'no_log' and action == 'accept' and services == ['ALL']
    is_pci_remove       = any('PCI-DSS' in v[1] for v in violations) and services == ['ALL']
    n_critical          = sum(1 for v in violations if v[0] == 'CRITICAL')

    if is_catch_all_no_log:
        rec = "REMOVE"
    elif n_critical >= 2 or is_pci_remove:
        rec = "REMOVE or RESTRICT"
    elif len(violations) >= 2:
        rec = "RESTRICT"
    elif len(violations) == 1:
        rec = "REMEDIATE"
    else:
        rec = "COMPLIANT"

    return {"seq": seq, "name": name, "action": action, "services": services,
            "log": log, "violations": violations, "rec": rec}

results = [audit_rule(r) for r in rules]

non_compliant = [r for r in results if r['rec'] != 'COMPLIANT']
compliant     = [r for r in results if r['rec'] == 'COMPLIANT']

print("=" * 110)
print("Clarisys STORE FIREWALL COMPLIANCE AUDIT — 2026-05-15")
print("Standards: CIS v8.1 IG3 + ISO 27001 + PCI-DSS 4.1 + Clarisys NFRs (IAM, Data, Cloud)")
print("=" * 110)

print(f"\n{'─'*110}")
print(f"  NON-COMPLIANT RULES ({len(non_compliant)} of {len(rules)})")
print(f"{'─'*110}\n")

for r in non_compliant:
    svcs = ','.join(r['services'])
    print(f"  Rule {r['seq']:>2} │ {r['name']:<45} │ {r['action']:>6} │ svc={svcs:<20} │ [{r['rec']}]")
    for sev, ctrl, msg in r['violations']:
        icon = "🔴" if sev == "CRITICAL" else "🟠"
        print(f"           {icon} [{sev:<8}] {ctrl:<30} {msg}")
    print()

print(f"{'─'*110}")
print(f"  COMPLIANT RULES ({len(compliant)} of {len(rules)})")
print(f"{'─'*110}\n")
for r in compliant:
    svcs = ','.join(r['services'])[:35]
    print(f"  Rule {r['seq']:>2} │ {r['name']:<45} │ svc={svcs}")

print(f"\n{'='*110}")
to_remove   = [r['seq'] for r in non_compliant if 'REMOVE' in r['rec']]
to_restrict = [r['seq'] for r in non_compliant if r['rec'] == 'RESTRICT']
to_remediate= [r['seq'] for r in non_compliant if r['rec'] == 'REMEDIATE']
print(f"  TOTAL: {len(rules)} rules  │  ❌ Non-compliant: {len(non_compliant)}  │  ✅ Compliant: {len(compliant)}")
print(f"  🔴 REMOVE/REMOVE-or-RESTRICT : Rules {to_remove}")
print(f"  🟠 RESTRICT                  : Rules {to_restrict}")
print(f"  🟡 REMEDIATE                 : Rules {to_remediate}")
print(f"{'='*110}")
