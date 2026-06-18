  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0# Firewall Ruleset Compliance Report

- **Generated:** 2026-06-15T13:52:32Z
- **Schema detected:** `raw`
- **Total rules evaluated:** 94
- **Acceptable:** 0
- **Denied:** 94
- **Invalid rows:** 0
- **Overall status:** **NON-COMPLIANT**

## Failed controls

| Control | Occurrences |
|---|---|
| CIS_4.8 | 20 |
| Cloud-08 / CIS_12.2 | 94 |
| IAM-8 / Cloud-09 / CIS_8.2 | 1 |

## Failed standards

| Standard | Occurrences |
|---|---|
| CIS v8.1 | 94 |
| ISO 27001 | 94 |
| Clarisys NFR | 94 |

## Per-rule findings

### Row 2 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 3 — DENY (HIGH)

- **Target:** 10.221.0.0/16 → 10.221.126.33 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 4 — DENY (HIGH)

- **Target:** 10.221.0.0/16 → 10.221.126.34 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 5 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.221.0.0/16 tcp/13102
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 6 — DENY (HIGH)

- **Target:** 10.157.26.0/24 → 10.221.126.33 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 7 — DENY (HIGH)

- **Target:** 10.157.26.0/24 → 10.221.126.34 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 8 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 9 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.1.1.0/24 udp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 10 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.1.1.0/24 tcp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 11 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.250.255.3/32 udp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 12 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.250.255.3/32 tcp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 13 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.221.0.0/16 icmp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 14 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.141.2.11/32 udp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 15 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.141.2.11/32 tcp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 16 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.96.3.70/32 udp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 17 — DENY (HIGH)

- **Target:** 10.221.126.0/24 → 10.96.3.70/32 tcp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 18 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 icmp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 19 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 udp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 20 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/53
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 21 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 udp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 22 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 23 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.159.5.67/32 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 24 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.159.5.68/32 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 25 — DENY (HIGH)

- **Target:** 10.159.5.67/32 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 26 — DENY (HIGH)

- **Target:** 10.159.5.68/32 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 27 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 28 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 29 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.250.2.4/32 tcp/80
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 30 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.250.2.4/32 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 31 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.1.1.0/24 tcp/80
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 32 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.1.1.0/24 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 33 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.106.1.0/24 tcp/80
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 34 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.106.1.0/24 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 35 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.50.5.0/24 tcp/80
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 36 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.50.5.0/24 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 37 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.96.0.0/16 tcp/80
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 38 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.96.0.0/16 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 39 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 128.134.5.21/32 tcp/21
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 40 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 128.43.5.30/32 tcp/21
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 41 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.128.0.0/16 tcp/162
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 42 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.96.0.0/16 tcp/162
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 43 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.30/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 44 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.30/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 45 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.30/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 46 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.30/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 47 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.31/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 48 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.31/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 49 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.31/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 50 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.31/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 51 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.32/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 52 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.32/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 53 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.32/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 54 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.32/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 55 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.33/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 56 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.33/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 57 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.33/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 58 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.33/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 59 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.4/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 60 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.4/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 61 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.4/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 62 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.4/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 63 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.5/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 64 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.5/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 65 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.5/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 66 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.5/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 67 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.6/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 68 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.6/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 69 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.6/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 70 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.6/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 71 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.7/32 tcp/18001
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 72 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.7/32 tcp/18002
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 73 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.7/32 tcp/18017
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 74 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.7/32 tcp/18018
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 75 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.34/32 tcp/18049
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 76 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.130.150.8/32 tcp/18049
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 77 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 78 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.141.2.11/32 tcp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 79 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.141.2.11/32 udp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 80 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.96.3.70/32 tcp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 81 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.96.3.70/32 udp/123
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 82 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 udp/67
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 83 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 udp/68
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 84 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 85 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 86 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 87 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 10.0.0.0/8 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 88 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 89 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 91.208.214.0/24 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 90 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 91 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 92 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/443
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 93 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/2200
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks100 54061  100 46432  100  7629   171k  28928 --:--:-- --:--:-- --:--:--  200k
 network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.

### Row 94 — DENY (HIGH)

- **Target:** 10.0.0.0/8 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: CIS_4.8, Cloud-08 / CIS_12.2, IAM-8 / Cloud-09 / CIS_8.2.
- **Failed controls:** CIS_4.8, Cloud-08 / CIS_12.2, IAM-8 / Cloud-09 / CIS_8.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **CIS_4.8** (HIGH) — Request is overly permissive
    - Remediation: Specify the minimum required protocol and destination port.
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.
  - **IAM-8 / Cloud-09 / CIS_8.2** (HIGH) — Allow request does not enable logging
    - Remediation: Set log to all, utm, or an equivalent audited mode.

### Row 95 — DENY (HIGH)

- **Target:** 0.0.0.0/0 → 0.0.0.0/0 tcp/0
- **Reason:** Denied due to CIS v8.1, ISO 27001, Clarisys NFR failures: Cloud-08 / CIS_12.2.
- **Failed controls:** Cloud-08 / CIS_12.2
- **Failed standards:** CIS v8.1, ISO 27001, Clarisys NFR
- **Violations:**
  - **Cloud-08 / CIS_12.2** (HIGH) — Request lacks network segmentation metadata
    - Remediation: Provide non-empty source_interface and destination_interface values.
