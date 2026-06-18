# Firewall Policy API - Rollback Triggers and Actions

Use this matrix during production releases to decide when to rollback.

## Immediate Rollback Triggers

Rollback now if any of these occur and do not recover within the grace period.

| Trigger | Threshold | Grace Period | Action |
| --- | ---: | ---: | --- |
| API error rate spike | error_rate >= 0.05 | 5 min | Rollback immediately |
| Critical alert status | status = `critical` | 5 min | Rollback unless clearly non-release-related |
| OPA unavailable events | `opa_unavailable` increments continuously | 3 min | Rollback and restore last known good |
| Health endpoint degraded | `/health.status` = `degraded` after deploy | 3 min | Rollback immediately |
| Core endpoint failure | `/evaluate` or `/evaluate/bulk` returns repeated 5xx | 3 min | Rollback immediately |

## Conditional Rollback Triggers

Rollback if unresolved by on-call within the stated window.

| Trigger | Threshold | Window | Action |
| --- | ---: | ---: | --- |
| p95 latency regression | p95 > 1500ms sustained | 10 min | Scale/tune; rollback if unchanged |
| Slack dispatch failures | dispatch failures increasing and unresolved | 15 min | Fix webhook/network; rollback if release caused regression |
| Digest backlog growth | backlog > threshold and keeps rising | 15 min | Flush/tune; rollback if release introduced issue |
| Evidence archive write issues | persist=true report fails or archive unreadable | 15 min | Fix storage path/perm; rollback if introduced by release |

## Fast Verification Commands

```bash
curl -s 'http://127.0.0.1:8000/health' | jq
curl -s 'http://127.0.0.1:8000/metrics/slo' | jq '{error_rate, latency_p95_ms, opa_unavailable, requests_error, requests_total}'
curl -s 'http://127.0.0.1:8000/metrics/alerts' | jq '{status, active_alerts_count, active_alerts}'
curl -s 'http://127.0.0.1:8000/notifications/slack/metrics' | jq '{dispatch_failures, digest_items_buffered, last_error, last_error_at}'
```

## Rollback Procedure (Generic)

- [ ] Announce rollback in incident/change channel.
- [ ] Restore last known good release artifact/config.
- [ ] Restart service and verify startup cleanly.

```bash
systemctl restart opa-api.service
systemctl status opa-api.service --no-pager
journalctl -u opa-api.service -n 120 --no-pager
```

- [ ] Re-run health and metrics checks.
- [ ] Confirm alert status returns to `ok` or stable `warn` baseline.
- [ ] Capture incident summary and root-cause follow-up actions.

## Ownership

- Deployment owner: executes release and rollback.
- On-call engineer: validates trigger conditions and confirms stabilization.
- Service owner: signs off final incident summary and corrective actions.
