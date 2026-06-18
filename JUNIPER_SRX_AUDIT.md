# Juniper SRX JSON Audit Support

## Overview
The firewall compliance audit API now supports direct extraction and evaluation of Juniper SRX policy configurations from their native JSON export format.

## Endpoints

### 1. `/audit/json/html` (POST)
Extract policies from Juniper SRX JSON and return HTML compliance report.

**Request:**
```bash
curl -X POST http://127.0.0.1:8001/audit/json/html \
  -H 'X-API-Key: your-api-key' \
  -F 'file=@srx-policies.json'
```

**Response:**
- `Content-Type: text/html`
- Headers:
  - `X-Audit-Valid-Rows`: Number of policies extracted
  - `X-Audit-Acceptable`: Count meeting all standards
  - `X-Audit-Denied`: Count failing controls

### 2. `/audit/json/cleaned` (POST)
Extract normalized rules from SRX JSON as artifacts.

**Request:**
```bash
curl -X POST 'http://127.0.0.1:8001/audit/json/cleaned?fmt=csv' \
  -H 'X-API-Key: your-api-key' \
  -F 'file=@srx-policies.json'
```

**Query Parameters:**
- `fmt`: Output format — `csv` or `json` (default: `csv`)

**Response:**
- `Content-Type: text/csv; charset=utf-8` or `application/json`
- CSV columns: source, destination, protocol, port, log, action, source_interface, destination_interface, standards
- JSON: Array of TrafficRequest objects with all audit fields

## JSON Schema (Input)

The Juniper SRX JSON must follow this structure:

```json
{
  "policies": [
    {
      "policy": [
        {
          "from-zone-name": { "data": "trust" },
          "to-zone-name": { "data": "untrust" },
          "policy": [
            {
              "name": { "data": "policy-name" },
              "match": [
                {
                  "source-address": [{ "data": "10.0.0.0/24" }],
                  "destination-address": [{ "data": "0.0.0.0/0" }],
                  "application": [{ "data": "http" }]
                }
              ],
              "then": [{ "permit": [{}] }]
            }
          ]
        }
      ]
    }
  ],
  "zones": [...]  // Optional; for reference only
}
```

## Parser Behavior

### Extraction
- **from-zone-name.data** → `source_interface`
- **to-zone-name.data** → `destination_interface`
- **policy.name.data** → `rule_name`
- **match[0].source-address[0].data** → `source`
- **match[0].destination-address[0].data** → `destination`
- **match[0].application[0].data** → Application (logged but not parsed to port)
- **then[0].permit** → Action = `accept`
- **then[0].deny/reject** → Action = `deny`

### Defaults
- `protocol`: `any`
- `port`: `0` (port extraction not available in SRX JSON)
- `log`: `log_all_sessions`

### Error Handling
- Invalid JSON: Returns 400 with error detail
- Empty policies: Returns 400 (no rules to evaluate)
- Malformed rules: Skipped with row-level error logged

## Web UI Integration

The public audit upload form at `https://13.43.195.150/firewall-audit-ui/` accepts `.json` files. The page is publicly reachable, but every upload still requires a valid `X-API-Key`. Upload a Juniper SRX policy export:
1. Choose a `.json` file
2. Select output format for cleaned artifact (CSV or JSON)
3. Download HTML report and (optionally) cleaned artifact

## Testing

Sample SRX JSON file:
```bash
curl -X POST 'http://127.0.0.1:8001/audit/json/html' \
  -H 'X-API-Key: testkey' \
  -F 'file=@deploy/srx-sample.json'
```

Sample file: `deploy/srx-sample.json` contains 5 test policies across 2 zone pairs.

## Compliance Evaluation

Policies extracted from SRX JSON are evaluated against:
- **M&S NFR**: Requires specific protocol and port, not `any`
- **CIS v8.1**: Requires logging and least-privilege design
- **ISO 27001**: Requires approval and data classification
- **PCI-DSS**: Requires encryption for payment data paths

All SRX policies evaluated as "raw" schema (source/dest/protocol/port only; no app/env context).
