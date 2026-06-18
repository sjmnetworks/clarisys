# Test Traffic Identification & Isolation

## Overview

All test requests are automatically marked with a `test-` prefix on their request ID, enabling identification in logs, metrics, and dashboards. This allows filtering of test traffic from production monitoring without breaking metrics-recording tests.

## How It Works

### Test Request Marking

When `TESTING=true` environment variable is set:
- `logging_setup.new_request_id()` generates IDs like `test-<uuid>` instead of `<uuid>`
- All request logs include this prefixed request_id
- Request IDs propagate through the entire request lifecycle

### Test Isolation

Tests use conftest.py to:
1. **Redirect state files** to per-session tmpdir (not ~/firewall-api/)
2. **Set TESTING=true** so requests are marked as test traffic
3. **Clean up** tmpdir on exit with atexit handler

Production and test metrics **never mix** because:
- Tests write SLO metrics to `/tmp/opa-tests-XXXX/slo-metrics.json`
- Live API writes to `~/.firewall-api/slo-metrics.json`
- Prometheus scrapes only from the live API endpoint (127.0.0.1:8001)

### Filtering Test Traffic

If needed to exclude test requests from Grafana dashboards or logs:

#### In Grafana Prometheus Queries
Use request_id label filter (if available in custom metrics):
```promql
# Exclude test requests
firewall_metric{request_id!~"^test-.*"}

# Include only test requests (for debugging)
firewall_metric{request_id=~"^test-.*"}
```

#### In Log Aggregation (Splunk/Datadog/CloudWatch)
Filter by request_id field:
```
request_id!~"^test-.*"
```

#### In Application Code
```python
# Skip metrics recording for test requests
if request_id.startswith("test-"):
    return  # Skip recording

# Or check environment
from os import environ
if environ.get("TESTING", "").lower() == "true":
    return  # Skip in test mode
```

## Current Status

✅ **Test isolation**: Working—tests don't touch production files  
✅ **Test marking**: Implemented—all test requests have `test-` prefix  
✅ **Metrics recording**: Working—tests verify metrics correctly  
✅ **State cleanup**: Automatic via atexit handler  

## Regression Test

The isolation contract is verified by:
```python
# tests/test_state_isolation.py
test_roi_state_file_redirected_to_tmp()
test_evaluate_does_not_touch_prod_state_files()
```

Running tests will fail loudly if any state isolation is broken.

## Example

When you run `pytest`, observe request logs:
```json
{"request_id": "test-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "path": "/evaluate", "method": "POST"}
```

When the live API processes a request:
```json
{"request_id": "x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4", "path": "/evaluate", "method": "POST"}
```

The test- prefix makes them distinguishable in all downstream systems.
