# Release Handoff - 2026-06-10

## Scope

Monitoring and Grafana reliability hardening for OPA policy API, including Nginx /grafana pathing, ROI dashboard data-source fixes, and release-gate smoke coverage.

## Outcomes

- Grafana reachable via Nginx subpath at /grafana.
- Live ROI dashboard data restored (Prometheus datasource binding normalized).
- Retired business-case ROI dashboard removed from both live provisioning and repo sync paths.
- Release gate now includes ingress + Grafana + ROI target checks.
- Smoke script added for fast post-deploy verification.

## Key Runtime Verifications

- Grafana service active after restarts.
- Nginx config valid and reloaded successfully.
- Prometheus ROI metric series present:
  - firewall_rules_processed_total
  - firewall_hips_freed_total
  - firewall_cost_saved_gbp_total
  - firewall_fte_redeployed_total
- Prometheus target firewall-api-roi is up.
- tools/release_gate_check.py passes with ingress and ROI checks enabled.

## Current Dashboard State

- Kept: opa-roi-live-dashboard.json
- Removed: opa-roi-dashboard.json (business-case dashboard)

## New Operational Checks Added

- tools/smoke_monitoring.sh
  - Checks /health via ingress host header
  - Checks /grafana/login HTML response
  - Checks Prometheus target firewall-api-roi is up
- tools/release_gate_check.py
  - Added ingress checks and Prometheus ROI target validation
  - Base URL default aligned to http://127.0.0.1:8001

## Relevant Files Updated In This Workstream

- deploy/nginx-opa-api.conf
- deploy/monitoring/grafana/opa-roi-live-dashboard.json
- deploy/monitoring/grafana/firewall-api-observability-dashboard.json
- deploy/monitoring/sync_grafana_dashboards_bundle.sh
- deploy/monitoring/QUICK_OPS.md
- deploy/monitoring/RUNBOOK.md
- tools/smoke_monitoring.sh
- tools/release_gate_check.py

## Notes

- Host-to-own-public-IP curl may timeout due to cloud hairpin behavior; localhost TLS checks with Host header were used for deterministic validation.
- Deprecated service opa-api.service is disabled/inactive; monitored service remains opa-api-8001.service.
