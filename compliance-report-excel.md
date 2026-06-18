# Firewall Ruleset Compliance Report

- **Generated:** 2026-06-15T14:01:45Z
- **Schema detected:** `raw`
- **Total rules evaluated:** 17
- **Acceptable:** 5
- **Denied:** 12
- **Invalid rows:** 17
- **Overall status:** **NON-COMPLIANT**

## Failed controls

| Control | Occurrences |
|---|---|
| CIS_4.8 | 12 |

## Failed standards

| Standard | Occurrences |
|---|---|
| CIS v8.1 | 12 |
| ISO 27001 | 12 |
| M&S NFR | 12 |

## Per-rule findings

### Row 2 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan102_net) → IP/Netmask: $(store_main_vlan1432_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 3 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan102_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 4 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan101_dns_server) tcp/53
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 5 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: 10.250.255.3/255.255.255.255 tcp/53
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 6 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan102_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 7 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: 10.141.2.11/255.255.255.255 tcp/123
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 8 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan111_net) → IP/Netmask: 0.0.0.0/0.0.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 9 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.250.2.4/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 10 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 128.134.5.21/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 11 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.128.0.0/255.255.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 12 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.130.150.30/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 13 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.130.150.34/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 14 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 0.0.0.0/0.0.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 15 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.141.2.11/255.255.255.255 tcp/123
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 16 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan116_net) → Group Member (2): H_MSSSRSTOREP0031, H_MSSSRSTOREP8031 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 17 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan104_net) → Group Member (8): redirect.juniper.net, cdn.juniper.net, ztp.eu.mist.com, jma-terminator.eu.mist.com, redirect.mist.com, portal.eu.mist.com, ep-terminator.mistsys.net, ep-terminator.eu.mist.com tcp/443
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 18 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan104_net) → Group Member (1): oc-term.eu.mist.com tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

## Invalid rows

| Row | Errors | Raw |
|---|---|---|
| 2 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "IP/Netmask: $(store_main_data_summary)", "protocol": "all", "port": "0", "log": "no_log", "action": "accept", "source_interface": "VLAN101", "destination_interface": "VLAN101", "rule_name": "INTRA CORP LAN ZONE"}` |
| 5 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: 10.157.26.0/255.255.255.0", "destination": "IP Range: 10.221.126.33-10.221.126.34", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "SDWAN.CORP-WAN", "destination_interface": "VLAN1432", "rule_name": "TRAS to VLAN1432"}` |
| 6 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan1432_net)", "destination": "IP/Netmask: 0.0.0.0/0.0.0.0", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN1432", "destination_interface": "SDWAN.ZIA", "rule_name": "Catch all to Zscaler_1432"}` |
| 12 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan111_net)", "destination": "IP/Netmask: 10.159.5.67/255.255.255.255", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN111", "destination_interface": "SDWAN.CORP-CCTV", "rule_name": "VLAN111 to MITIE"}` |
| 13 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: 10.159.5.67/255.255.255.255", "destination": "IP/Netmask: $(store_main_vlan111_net)", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "SDWAN.CORP-CCTV", "destination_interface": "VLAN111", "rule_name": "MITIE to VLAN111"}` |
| 14 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan111_nuc)", "destination": "Group Member (15): N_10.0.0.0/8, N_128.43.0.0/16, N_128.134.0.0/16, N_158.1.0.0/16, N_158.20.0.0/14, N_158.40.0.0/16, N_158.44.0.0/16, N_158.46.0.0/15, N_158.48.0.0/16, N_158.50.0.0/16, N_158.78.0.0/24, N_158.89.0.0/16, N_158.98.0.0/23, N_172.16.0.0/12, N_192.168.0.0/16", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "deny", "source_interface": "VLAN111", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "VLAN111 HOSTS to INTERNAL DENY"}` |
| 15 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan111_net)", "destination": "IP/Netmask: 0.0.0.0/0.0.0.0", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN111", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "VLAN111 to INTERNAL PERMIT"}` |
| 24 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan116_net)", "destination": "Group Member (15): N_10.0.0.0/8, N_128.43.0.0/16, N_128.134.0.0/16, N_158.1.0.0/16, N_158.20.0.0/14, N_158.40.0.0/16, N_158.44.0.0/16, N_158.46.0.0/15, N_158.48.0.0/16, N_158.50.0.0/16, N_158.78.0.0/24, N_158.89.0.0/16, N_158.98.0.0/23, N_172.16.0.0/12, N_192.168.0.0/16", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "deny", "source_interface": "VLAN116", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "VLAN116 to M and S"}` |
| 25 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_vlan116_net)", "destination": "IP/Netmask: 0.0.0.0/0.0.0.0", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN116", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "VLAN116 to DPDIA"}` |
| 26 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "IP/Netmask: 10.0.0.0/255.0.0.0", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "10/8 via SDWAN HUB Out"}` |
| 27 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: 10.0.0.0/255.0.0.0", "destination": "IP/Netmask: $(store_main_data_summary)", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "SDWAN.CORP-WAN", "destination_interface": "VLAN101", "rule_name": "10/8 via SDWAN HUB In"}` |
| 28 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "Group Member (7): G_FALCON, G_EUROCHANGE-VERIFONE, G_ESEL-STORE, G_DYNATRACE-STORE, G_DIGITAL-CAFE-STORE, G_MERCURYSSO-SAAS-APP, G_MICROSOFT-STORE", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.DIA", "rule_name": "Apps via DIA"}` |
| 29 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "Group Member (13): G_SPPD, assist.store.marksandspencer.com, cssm-lcsapi-prod.rtl.apps.mnscorp.net, mcm.services.ingenico.com, mns-oa-pr1.jdadelivers.com, G_API-IDENTITY, G_API-PREPROD, G_DIGITALCONTENT, G_HHT-DC-SR, G_MNS-LEARNING-URLS, G_PLANOGRAMS-URLS, G_STORE-MNS, G_TA-URLS", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.CORP-WAN", "rule_name": "Apps via DPDIA"}` |
| 30 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "Predefined", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.DIA", "rule_name": "Microsoft SaaS via DIA"}` |
| 31 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "Predefined", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.DIA", "rule_name": "CDNs via DIA"}` |
| 34 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: $(store_main_data_summary)", "destination": "IP/Netmask: 0.0.0.0/0.0.0.0", "protocol": "all", "port": "0", "log": "no_log", "action": "accept", "source_interface": "VLAN101", "destination_interface": "SDWAN.ZIA", "rule_name": "Catch all to Zscaler"}` |
| 35 | 1 validation error for TrafficRequest protocol   Value error, protocol must be one of ['any', 'icmp', 'tcp', 'udp'] [type=value_error, input_value='all', input_type=str]     For further information visit https://errors.pydantic.dev/2.13/v/value_error | `{"source": "IP/Netmask: 0.0.0.0/0.0.0.0", "destination": "IP/Netmask: 0.0.0.0/0.0.0.0", "protocol": "all", "port": "0", "log": "log_all_sessions", "action": "deny", "source_interface": "any", "destination_interface": "any", "rule_name": "Implicit Deny"}` |
