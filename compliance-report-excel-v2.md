# Firewall Ruleset Compliance Report

- **Generated:** 2026-06-15T14:02:52Z
- **Schema detected:** `raw`
- **Total rules evaluated:** 34
- **Acceptable:** 5
- **Denied:** 29
- **Invalid rows:** 0
- **Overall status:** **NON-COMPLIANT**

## Failed controls

| Control | Occurrences |
|---|---|
| CIS_4.8 | 29 |
| IAM-8 / Cloud-09 / CIS_8.2 | 2 |

## Failed standards

| Standard | Occurrences |
|---|---|
| CIS v8.1 | 29 |
| ISO 27001 | 29 |
| M&S NFR | 29 |

## Per-rule findings

### Row 2 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → IP/Netmask: $(store_main_data_summary) any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8, IAM-8 / Cloud-09 / CIS_8.2.
- **Failed controls:** CIS_4.8, IAM-8 / Cloud-09 / CIS_8.2
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.
  - **IAM-8 / Cloud-09 / CIS_8.2** (HIGH) — Allow request does not enable logging
    - Remediation: Set log to all, utm, or an equivalent audited mode.

### Row 3 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan102_net) → IP/Netmask: $(store_main_vlan1432_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 4 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan102_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 5 — DENY (HIGH)

- **Target:** IP/Netmask: 10.157.26.0/255.255.255.0 → IP Range: 10.221.126.33-10.221.126.34 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 6 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: 0.0.0.0/0.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 7 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan101_dns_server) tcp/53
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 8 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: 10.250.255.3/255.255.255.255 tcp/53
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 9 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: $(store_main_vlan102_net) tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 10 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan1432_net) → IP/Netmask: 10.141.2.11/255.255.255.255 tcp/123
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 11 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan111_net) → IP/Netmask: 0.0.0.0/0.0.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 12 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan111_net) → IP/Netmask: 10.159.5.67/255.255.255.255 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 13 — DENY (HIGH)

- **Target:** IP/Netmask: 10.159.5.67/255.255.255.255 → IP/Netmask: $(store_main_vlan111_net) any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 14 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan111_nuc) → Group Member (15): N_10.0.0.0/8, N_128.43.0.0/16, N_128.134.0.0/16, N_158.1.0.0/16, N_158.20.0.0/14, N_158.40.0.0/16, N_158.44.0.0/16, N_158.46.0.0/15, N_158.48.0.0/16, N_158.50.0.0/16, N_158.78.0.0/24, N_158.89.0.0/16, N_158.98.0.0/23, N_172.16.0.0/12, N_192.168.0.0/16 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 15 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan111_net) → IP/Netmask: 0.0.0.0/0.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 16 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.250.2.4/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 17 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 128.134.5.21/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 18 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.128.0.0/255.255.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 19 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.130.150.30/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 20 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.130.150.34/255.255.255.255 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 21 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 0.0.0.0/0.0.0.0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 22 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan114_net) → IP/Netmask: 10.141.2.11/255.255.255.255 tcp/123
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 23 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan116_net) → Group Member (2): H_MSSSRSTOREP0031, H_MSSSRSTOREP8031 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 24 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan116_net) → Group Member (15): N_10.0.0.0/8, N_128.43.0.0/16, N_128.134.0.0/16, N_158.1.0.0/16, N_158.20.0.0/14, N_158.40.0.0/16, N_158.44.0.0/16, N_158.46.0.0/15, N_158.48.0.0/16, N_158.50.0.0/16, N_158.78.0.0/24, N_158.89.0.0/16, N_158.98.0.0/23, N_172.16.0.0/12, N_192.168.0.0/16 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 25 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan116_net) → IP/Netmask: 0.0.0.0/0.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 26 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → IP/Netmask: 10.0.0.0/255.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 27 — DENY (HIGH)

- **Target:** IP/Netmask: 10.0.0.0/255.0.0.0 → IP/Netmask: $(store_main_data_summary) any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 28 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → Group Member (7): G_FALCON, G_EUROCHANGE-VERIFONE, G_ESEL-STORE, G_DYNATRACE-STORE, G_DIGITAL-CAFE-STORE, G_MERCURYSSO-SAAS-APP, G_MICROSOFT-STORE any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 29 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → Group Member (13): G_SPPD, assist.store.marksandspencer.com, cssm-lcsapi-prod.rtl.apps.mnscorp.net, mcm.services.ingenico.com, mns-oa-pr1.jdadelivers.com, G_API-IDENTITY, G_API-PREPROD, G_DIGITALCONTENT, G_HHT-DC-SR, G_MNS-LEARNING-URLS, G_PLANOGRAMS-URLS, G_STORE-MNS, G_TA-URLS any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 30 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → Predefined any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 31 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → Predefined any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.

### Row 32 — ACCEPTABLE (LOW)

- **Target:** IP/Netmask: $(store_main_vlan104_net) → Group Member (8): redirect.juniper.net, cdn.juniper.net, ztp.eu.mist.com, jma-terminator.eu.mist.com, redirect.mist.com, portal.eu.mist.com, ep-terminator.mistsys.net, ep-terminator.eu.mist.com tcp/443
- **Reason:** Permitted: the proposed request is compliant with M&S NFR controls.

### Row 33 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_vlan104_net) → Group Member (1): oc-term.eu.mist.com tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.

### Row 34 — DENY (HIGH)

- **Target:** IP/Netmask: $(store_main_data_summary) → IP/Netmask: 0.0.0.0/0.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8, IAM-8 / Cloud-09 / CIS_8.2.
- **Failed controls:** CIS_4.8, IAM-8 / Cloud-09 / CIS_8.2
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.
  - **IAM-8 / Cloud-09 / CIS_8.2** (HIGH) — Allow request does not enable logging
    - Remediation: Set log to all, utm, or an equivalent audited mode.

### Row 35 — DENY (HIGH)

- **Target:** IP/Netmask: 0.0.0.0/0.0.0.0 → IP/Netmask: 0.0.0.0/0.0.0.0 any/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, M&S NFR failures: CIS_4.8.
- **Failed controls:** CIS_4.8
- **Failed standards:** CIS v8.1, ISO 27001, M&S NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Protocol ANY is overly permissive
    - Remediation: Use the specific protocol required by the service.
