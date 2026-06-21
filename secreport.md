# Clarisys Security Report

**Date:** 2026-06-21  
**Scope:** Full codebase & architecture review — API, auth, infrastructure, dependencies, deployment  
**Assessor:** Seccy (automated security agent)

---

## RAG Summary

| Area | Status | Finding Count |
|------|--------|---------------|
| Authentication & Secrets | 🟡 AMBER | 3 |
| Input Validation & Injection | 🟢 GREEN | 1 (informational) |
| Infrastructure (Terraform/Docker/k8s) | 🟡 AMBER | 4 |
| Dependencies & Supply Chain | 🟡 AMBER | 2 |
| Access Control & Authorization | 🟢 GREEN | 0 |
| Data Protection (encryption, audit) | 🟢 GREEN | 0 |
| Network & Transport Security | 🟡 AMBER | 1 |

**Overall Posture: 🟡 AMBER** — No critical vulnerabilities. Several medium-severity items require attention before production hardening sign-off.

---

## Findings

### [MEDIUM] JWT Secret Auto-Generation on Startup — CWE-330

**Location:** [api/main.py](api/main.py#L3996)  
**Description:** If `JWT_SECRET` env var is unset, the application generates a random secret at startup via `secrets.token_urlsafe(48)`. In a multi-worker or multi-container deployment, each instance generates a different secret, causing tokens issued by one instance to be invalid on another. Additionally, every restart invalidates all outstanding sessions.  
**Attack path:** An attacker cannot directly exploit this, but operational brittleness leads to auth bypass workarounds (e.g., disabling auth to "fix" logins).  
**Fix:** Always require `JWT_SECRET` in production. Fail fast if unset when `APP_ENV=production`:
```python
if IS_PRODUCTION and not os.environ.get("JWT_SECRET"):
    raise RuntimeError("JWT_SECRET must be set in production")
```

---

### [MEDIUM] XML External Entity (XXE) — No defusedxml — CWE-611

**Location:** [api/main.py](api/main.py#L9) (import), [api/main.py](api/main.py#L5121) (usage)  
**Description:** Juniper SRX XML parsing uses `xml.etree.ElementTree.fromstring()`. While CPython's ElementTree doesn't resolve external entities by default (unlike lxml), it is still vulnerable to billion-laughs (entity expansion DoS) in some configurations. The `defusedxml` library is not used.  
**Attack path:** A crafted XML payload with deeply nested entity expansion could cause memory exhaustion (DoS). External entity resolution is not a risk with ET, but defense-in-depth dictates using `defusedxml`.  
**Fix:** Replace `import xml.etree.ElementTree as ET` with:
```python
import defusedxml.ElementTree as ET
```
Add `defusedxml>=0.7.1` to `requirements.txt`.

---

### [MEDIUM] OPA Binary Not Integrity-Verified in Docker Build — CWE-494

**Location:** [Dockerfile](Dockerfile#L25-L33)  
**Description:** The OPA binary is downloaded from the internet but SHA-256 verification is commented out with a `PLACEHOLDER_SHA256_FILL_BEFORE_RELEASE` value. A supply chain attack or CDN compromise would inject a malicious OPA binary.  
**Attack path:** Compromised OPA binary → all policy decisions are controlled by attacker → all firewall rules evaluate as "allow".  
**Fix:** Populate `OPA_SHA256` with the real checksum and uncomment the verification line:
```dockerfile
ARG OPA_SHA256=<real-sha256-from-opa-releases>
RUN echo "${OPA_SHA256}  /tmp/opa" | sha256sum -c -
```

---

### [MEDIUM] Uvicorn `--forwarded-allow-ips=*` Trusts All Proxies — CWE-346

**Location:** [Dockerfile](Dockerfile#L102)  
**Description:** The `--forwarded-allow-ips=*` flag instructs uvicorn to trust `X-Forwarded-For` and `X-Forwarded-Proto` headers from any source. If the container is ever exposed directly (not behind an ALB), an attacker can spoof their IP address, bypassing IP-based rate limiting and audit trail accuracy.  
**Attack path:** Attacker sets `X-Forwarded-For: 127.0.0.1` → bypasses rate limit keyed on IP → brute-forces auth.  
**Fix:** Restrict to the ALB/proxy CIDR:
```
--forwarded-allow-ips=10.0.0.0/16
```
Or use the VPC private subnet range in ECS deployments.

---

### [MEDIUM] ALB Serves HTTP Without TLS When No Domain Configured — CWE-319

**Location:** [infra/alb.tf](infra/alb.tf#L60-L68)  
**Description:** When `var.domain_name` is empty (which it was in the recent deployment), the ALB listener on port 80 forwards traffic in plaintext. JWT tokens, API keys, and firewall rule data transit unencrypted between client and ALB.  
**Attack path:** Network eavesdropper (same network segment, ISP, coffee shop) captures bearer tokens from HTTP traffic → full account takeover.  
**Fix:** Always deploy with a domain and ACM certificate. Add a validation rule:
```hcl
variable "domain_name" {
  type = string
  validation {
    condition     = var.domain_name != ""
    error_message = "domain_name is required for production deployments (TLS)"
  }
}
```

---

### [LOW] SHA-1 Used for Rule Fingerprinting — CWE-328

**Location:** [api/main.py](api/main.py#L1453-L1458)  
**Description:** `hashlib.sha1` is used to generate 10-character rule fingerprints. While SHA-1 collision attacks exist, this usage is non-security-critical (display-only deduplication, not authentication). The truncation to 10 hex chars (40 bits) means collisions are possible regardless of algorithm.  
**Attack path:** No direct exploitation — informational only. An attacker cannot forge a meaningful collision in a truncated fingerprint that would bypass any security control.  
**Fix:** Consider migrating to SHA-256 for consistency, but this is low priority.

---

### [LOW] Pilot API Key Hashed with SHA-256 (No Salt) — CWE-916

**Location:** [api/pilot_users.py](api/pilot_users.py#L51)  
**Description:** Pilot API keys are stored as `SHA-256(key)` without a salt. If the `pilot_users.json` file is leaked, an attacker with the hash cannot easily reverse a 32-byte random key (256 bits of entropy from `secrets.token_urlsafe(32)`), so brute-force is infeasible. However, unsalted hashing means identical keys would have identical hashes (unlikely given the entropy).  
**Attack path:** Theoretical only. The 256-bit key space makes rainbow tables impractical. Risk is negligible given key generation uses `secrets.token_urlsafe(32)`.  
**Fix:** No immediate action needed. For defense-in-depth, consider HMAC-based storage with a server-side pepper, or bcrypt for lower-entropy keys if ever introduced.

---

### [LOW] `hmac.new` Typo (Should Be `hmac.HMAC` or Use `hmac.new` Correctly) — CWE-327

**Location:** [api/main.py](api/main.py#L1155)  
**Description:** Code uses `hmac.new(...)` — Python's `hmac` module exposes `hmac.new()` as an alias for `hmac.HMAC()`, so this works. However, `POLICY_SIGNING_KEY` defaults to empty string if unset. When empty, the signing operation still executes with a zero-length key, producing a valid but meaningless HMAC.  
**Attack path:** If signing is relied upon for policy integrity verification downstream, an attacker who knows the key is empty can forge signatures. Currently the signature is informational only (returned in `/policy/version` responses).  
**Fix:** Skip signing when key is empty (already done via `if _POLICY_SIGNING_KEY:` guard). Consider requiring the key in production.

---

### [LOW] EFS `ClientRootAccess` Granted to Task Role — CWE-250

**Location:** [infra/iam.tf](infra/iam.tf#L99-L104)  
**Description:** The ECS task role includes `elasticfilesystem:ClientRootAccess`. This allows the container to bypass POSIX permissions on the EFS filesystem. While the container runs as non-root (UID 1001), the IAM permission itself is overly broad.  
**Attack path:** Container escape → IAM role assumed → mount EFS as root → read/write all tenant data across all tasks sharing the filesystem.  
**Fix:** Remove `ClientRootAccess` and rely on the EFS access point's enforced UID/GID:
```hcl
Action = [
  "elasticfilesystem:ClientMount",
  "elasticfilesystem:ClientWrite"
]
```

---

## Positive Findings (Controls Working Well)

| Control | Evidence |
|---------|----------|
| **Password Storage** | bcrypt with auto-salt (`api/user_store.py:178`) |
| **Path Traversal Protection** | `resolve()` + prefix check in frontend serving (`api/main.py:6441-6443`) |
| **Input Validation** | Comprehensive allowlist validation module (`api/input_validation.py`) |
| **S3 Audit Integrity** | Object Lock (GOVERNANCE mode), versioning, SSE, public access blocked |
| **Non-Root Container** | UID 1001, read-only root filesystem (k8s), `allowPrivilegeEscalation: false` |
| **Network Segmentation** | ECS only reachable from ALB SG; EFS only from ECS SG; NetworkPolicy in k8s |
| **Secrets Management** | JWT_SECRET injected from AWS Secrets Manager in ECS; k8s uses Secret refs |
| **No Command Injection** | `subprocess` imported but never called; no `os.system`/`eval`/`exec` usage |
| **Rate Limiting** | Per-caller sliding window with configurable quotas |
| **Scope-Based AuthZ** | Fine-grained scope checks on every endpoint via `require_scope()` |
| **State File Not in Git** | `terraform.tfstate` properly gitignored, never committed |
| **Structured Logging** | `structlog` with request correlation IDs |
| **Body Size Limits** | 5 MiB default cap on uploads |

---

## Recommendations (Priority Order)

| # | Priority | Action | Effort |
|---|----------|--------|--------|
| 1 | HIGH | Enable OPA binary SHA-256 verification in Dockerfile | 10 min |
| 2 | HIGH | Require `JWT_SECRET` env var in production (fail-fast) | 5 min |
| 3 | HIGH | Deploy with TLS (ACM cert + domain) before exposing to users | 30 min |
| 4 | MEDIUM | Replace `xml.etree.ElementTree` with `defusedxml` | 10 min |
| 5 | MEDIUM | Restrict `--forwarded-allow-ips` to VPC CIDR | 5 min |
| 6 | MEDIUM | Remove `ClientRootAccess` from EFS IAM policy | 5 min |
| 7 | LOW | Migrate fingerprinting from SHA-1 to SHA-256 | 15 min |

---

## Methodology

- Static analysis of all Python source, Terraform HCL, Dockerfile, k8s manifests
- Grep-based secret scanning across all tracked files
- Git history verification (no secrets in commit log)
- Dependency version audit against known CVE databases
- OWASP Top 10 2021 mapping for web application risks
- CWE classification for all findings

---

*Report generated by Seccy security agent. Next review recommended after implementing HIGH-priority fixes.*
