# Phase 4: Secrets Rotation Strategy

**Last Updated:** 15 May 2026  
**Status:** Implementation guide for production hardening  
**Audience:** DevOps, Security, Platform Engineering

---

## Table of Contents
1. [Secret Inventory](#secret-inventory)
2. [Rotation Procedures](#rotation-procedures)
3. [Integration Patterns](#integration-patterns)
4. [Testing & Rollback](#testing--rollback)
5. [Monitoring & Audit](#monitoring--audit)
6. [Runbooks](#runbooks)

---

## Secret Inventory

### Authentication Secrets (Auth Service)

| Secret | Location | Sensitivity | Rotation Cadence | Type |
|--------|----------|--------------|------------------|------|
| `AUTH_ISSUER` | Entra ID tenant URL | High | Annual | OAuth 2.0 Issuer |
| `AUTH_AUDIENCE` | Service-registered client ID | High | Annual or on credential compromise | OAuth 2.0 Audience |
| `AUTH_JWKS_URL` | Entra ID JWKS endpoint | Medium | Never (Entra-managed) | Public JWKS endpoint |
| `AUTH_JWKS_PIN_CERT_FILE` | Pinned TLS cert for JWKS | Medium | Annual or on cert renewal | X.509 Certificate |

### Audit Storage Secrets (S3 Backend)

| Secret | Location | Sensitivity | Rotation Cadence | Type |
|--------|----------|--------------|------------------|------|
| `AUDIT_S3_ACCESS_KEY_ID` | AWS IAM User | **Critical** | 90 days (AWS recommendation) | AWS Access Key |
| `AUDIT_S3_SECRET_ACCESS_KEY` | AWS IAM User | **Critical** | 90 days (AWS recommendation) | AWS Secret Key |
| `AUDIT_S3_BUCKET` | S3 bucket name | Low | Never | Configuration |
| `AUDIT_S3_REGION` | AWS region | Low | Never | Configuration |

### Future: Encryption Keys (Phase 4 enhancements)

| Secret | Location | Sensitivity | Rotation Cadence | Type |
|--------|----------|--------------|------------------|------|
| `AUDIT_ENCRYPTION_KEY` | KMS or local keystore | **Critical** | 180 days | Symmetric encryption key |
| `AUDIT_SIGNING_KEY` | KMS or local keystore | **Critical** | 180 days | HMAC key or asymmetric private key |

---

## Rotation Procedures

### 1. Auth Credentials (AUTH_ISSUER, AUTH_AUDIENCE)

**Trigger:** Annual refresh, security incident, or credential compromise

**Pre-rotation checklist:**
- [ ] Notify all API consumers (Slack, email)
- [ ] Schedule maintenance window (off-peak)
- [ ] Backup current credentials (secure vault)
- [ ] Test new credentials in staging

**Procedure:**

```bash
# Step 1: Verify new credentials are valid
curl -s "https://${NEW_AUTH_ISSUER}/.well-known/openid-configuration" | jq '.issuer'

# Step 2: Deploy canary rollout (5% traffic)
kubectl set env deployment/firewall-api \
  AUTH_ISSUER="${NEW_AUTH_ISSUER}" \
  --record

# Step 3: Monitor error rate and logs
kubectl logs -f -l app=firewall-api | grep -i "auth\|jwt"
sleep 300  # 5-minute observation window

# Step 4: If errors detected, rollback
kubectl rollout undo deployment/firewall-api

# Step 5: If healthy, proceed to 100%
kubectl patch deployment firewall-api \
  -p '{"spec":{"replicas":3}}'

# Step 6: Verify all pods are running with new creds
kubectl get pods -o jsonpath='{.items[*].spec.containers[0].env[?(@.name=="AUTH_ISSUER")].value}'
```

**Validation:**
```bash
# Generate a test JWT with new issuer
python3 -c "
import jwt
token = jwt.encode({
    'sub': 'test-user',
    'iss': '${NEW_AUTH_ISSUER}',
    'aud': '${NEW_AUTH_AUDIENCE}',
    'exp': int(time.time()) + 3600
}, 'secret', algorithm='HS256')
print(token)
"

# Test against API
curl -H "Authorization: Bearer ${token}" \
  https://api.example.com/evaluate \
  -d '{"request_id":"test","svc_name":"test"}'
```

**Post-rotation:**
- [ ] Confirm all pods healthy
- [ ] Run smoke tests in production
- [ ] Update audit log with rotation timestamp
- [ ] Notify stakeholders of completion

---

### 2. AWS Credentials (AUDIT_S3_*)

**Trigger:** Every 90 days (AWS best practice)

**Pre-rotation checklist:**
- [ ] Verify no long-running batch processes using old key
- [ ] Create new IAM user or rotate existing user's access keys
- [ ] Test new credentials locally before deployment
- [ ] Ensure S3 Object Lock policy allows key rotation

**Procedure:**

```bash
# Step 1: Create new AWS access key in IAM
aws iam create-access-key --user-name firewall-audit-user
# Output:
# {
#   "AccessKey": {
#     "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
#     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#     "Status": "Active",
#     "CreateDate": "2026-05-15T10:00:00Z"
#   }
# }

# Step 2: Store new credentials in Kubernetes Secret
kubectl create secret generic firewall-audit-s3-new \
  --from-literal=access-key-id="AKIAIOSFODNN7EXAMPLE" \
  --from-literal=secret-access-key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  --dry-run=client -o yaml | kubectl apply -f -

# Step 3: Deploy rolling update with new credentials
kubectl set env deployment/firewall-api \
  AUDIT_S3_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE" \
  AUDIT_S3_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  --record

# Step 4: Verify new pods can write to S3
kubectl logs -f -l app=firewall-api | grep -i "audit\|s3"

# Step 5: Test audit write
curl -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{"request_id":"rotation-test","svc_name":"test"}' \
  https://api.example.com/intake/evaluate

# Step 6: Confirm S3 object was written
aws s3 ls s3://firewall-audit-bucket/ --recursive | tail -5

# Step 7: After 7 days (grace period), delete old access key
aws iam delete-access-key \
  --access-key-id AKIAIOSFODNN6EXAMPLE \
  --user-name firewall-audit-user
```

**Grace period justification:**
- Allows in-flight requests to complete
- Provides rollback window if issues arise
- Audit trail shows both old and new key activity

---

### 3. TLS Certificate Pinning (AUTH_JWKS_PIN_CERT_FILE)

**Trigger:** Annual refresh, cert renewal, or algorithm upgrade (e.g., SHA-256 → SHA-384)

**Procedure:**

```bash
# Step 1: Obtain new certificate from Entra ID
openssl s_client -connect login.microsoftonline.com:443 \
  -servername login.microsoftonline.com \
  -showcerts < /dev/null 2>&1 | \
  openssl x509 -outform PEM > /tmp/new_jwks_cert.pem

# Step 2: Verify certificate validity
openssl x509 -in /tmp/new_jwks_cert.pem -noout -dates
openssl x509 -in /tmp/new_jwks_cert.pem -noout -subject -issuer

# Step 3: Store in Kubernetes ConfigMap (non-sensitive storage)
kubectl create configmap firewall-jwks-cert \
  --from-file=/tmp/new_jwks_cert.pem \
  -o yaml --dry-run=client | kubectl apply -f -

# Step 4: Update deployment to mount new cert
kubectl patch deployment firewall-api \
  -p '{"spec":{"template":{"spec":{"volumes":[
    {"name":"jwks-cert","configMap":{"name":"firewall-jwks-cert"}}
  ]}}'

# Step 5: Rolling restart
kubectl rollout restart deployment/firewall-api

# Step 6: Verify pinning works
kubectl logs -f -l app=firewall-api | grep -i "pin\|cert"
```

---

## Integration Patterns

### Pattern 1: Kubernetes Secrets + ConfigMaps

**Best for:** Small-to-medium deployments, dev/staging environments

```yaml
---
# Credentials (Secret)
apiVersion: v1
kind: Secret
metadata:
  name: firewall-auth-secrets
type: Opaque
stringData:
  AUTH_ISSUER: "https://login.microsoftonline.com/tenant-id/v2.0"
  AUTH_AUDIENCE: "client-id"
  AUDIT_S3_ACCESS_KEY_ID: "AKIA..."
  AUDIT_S3_SECRET_ACCESS_KEY: "..."

---
# Certificates (ConfigMap, non-sensitive)
apiVersion: v1
kind: ConfigMap
metadata:
  name: firewall-jwks-cert
data:
  jwks.pem: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----

---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: firewall-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: firewall-api:latest
        envFrom:
        - secretRef:
            name: firewall-auth-secrets
        volumeMounts:
        - name: jwks-cert
          mountPath: /etc/firewall/certs
          readOnly: true
      volumes:
      - name: jwks-cert
        configMap:
          name: firewall-jwks-cert
```

**Rotation procedure:**
```bash
# 1. Update secret
kubectl patch secret firewall-auth-secrets \
  -p '{"data":{"AUTH_ISSUER":"'$(echo -n "new-issuer" | base64)'}}'

# 2. Force pod restart to pick up new values
kubectl rollout restart deployment/firewall-api

# 3. Monitor
kubectl rollout status deployment/firewall-api
```

### Pattern 2: HashiCorp Vault + Kubernetes Auth

**Best for:** Large enterprises, multi-team deployments, fine-grained audit

```hcl
# Vault KV secret engine
path "secret/data/firewall/*" {
  capabilities = ["read", "list"]
}

# Allow pods to authenticate via K8s service account
path "auth/kubernetes/login" {
  capabilities = ["create", "read"]
}
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: firewall-api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: firewall-api-vault
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: firewall-api-vault
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: firewall-api-vault
subjects:
- kind: ServiceAccount
  name: firewall-api
  namespace: default
```

**Init container to fetch secrets:**
```bash
#!/bin/bash
# init-vault.sh
set -e

VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com:8200}"
ROLE="firewall-api"
NAMESPACE="default"

# Authenticate using Kubernetes JWT
JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
VAULT_TOKEN=$(curl -s \
  -X POST \
  -d "{\"jwt\":\"$JWT\",\"role\":\"$ROLE\"}" \
  "${VAULT_ADDR}/v1/auth/kubernetes/login" | jq -r '.auth.client_token')

# Fetch secrets
curl -s \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/secret/data/firewall/auth" | \
  jq '.data.data' > /run/secrets/auth-secrets.json

# Fetch S3 credentials
curl -s \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/secret/data/firewall/audit-s3" | \
  jq '.data.data' > /run/secrets/s3-secrets.json

# Source env vars from secrets
export $(jq -r 'to_entries[] | "\(.key)=\(.value)"' /run/secrets/auth-secrets.json)
export $(jq -r 'to_entries[] | "\(.key)=\(.value)"' /run/secrets/s3-secrets.json)

# Start application
exec "$@"
```

### Pattern 3: AWS Secrets Manager + IAM Roles

**Best for:** AWS-native deployments, EKS clusters with IRSA

```bash
#!/bin/bash
# init-aws-secrets.sh

SECRET_NAME="firewall-api-secrets"
REGION="us-east-1"

# Retrieve secret (IAM role provides auth)
SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "${SECRET_NAME}" \
  --region "${REGION}" \
  --query SecretString \
  --output text)

# Export as env vars
export $(echo "$SECRET" | jq -r 'to_entries[] | "\(.key)=\(.value)"')

# Start application
exec "$@"
```

**Kubernetes deployment with IRSA:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: firewall-api
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/firewall-api-role

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: firewall-api
spec:
  template:
    spec:
      serviceAccountName: firewall-api
      containers:
      - name: api
        image: firewall-api:latest
        volumeMounts:
        - name: init-script
          mountPath: /init
      initContainers:
      - name: secrets-init
        image: amazon/aws-cli:latest
        command:
        - /bin/sh
        - -c
        - /init/init-aws-secrets.sh && cp /run/secrets/env-vars /run/shared/
        volumeMounts:
        - name: init-script
          mountPath: /init
        - name: shared-data
          mountPath: /run/shared
      volumes:
      - name: init-script
        configMap:
          name: secrets-init-script
          defaultMode: 0755
      - name: shared-data
        emptyDir: {}
```

---

## Testing & Rollback

### Pre-rotation Testing

```bash
#!/bin/bash
# test-rotation.sh

set -e

# Test 1: Verify new credentials syntax
echo "Testing credential format..."
[[ -n "${NEW_AUTH_ISSUER}" ]] || exit 1
[[ -n "${NEW_AUTH_AUDIENCE}" ]] || exit 1
[[ -n "${NEW_AUDIT_S3_KEY}" ]] || exit 1

# Test 2: Auth connectivity
echo "Testing Entra ID connectivity..."
curl -s "https://${NEW_AUTH_ISSUER}/.well-known/openid-configuration" \
  | jq -e '.issuer' > /dev/null

# Test 3: S3 write permissions
echo "Testing S3 write access..."
aws s3 cp /dev/null "s3://${AUDIT_S3_BUCKET}/rotation-test-$(date +%s).txt" \
  --region "${AUDIT_S3_REGION}"

# Test 4: API smoke tests
echo "Running API smoke tests..."
pytest tests/smoke/ -v

# Test 5: Audit trail verification
echo "Verifying audit trail is being recorded..."
curl -s https://api.example.com/audit/csv \
  -H "Authorization: Bearer ${JWT_TOKEN}" | head -1

echo "✓ All pre-rotation tests passed"
```

### Rollback Procedure

```bash
#!/bin/bash
# rollback-rotation.sh

PREVIOUS_DEPLOYMENT=$(kubectl rollout history deployment/firewall-api | tail -2 | head -1)

echo "Rolling back to deployment #${PREVIOUS_DEPLOYMENT}..."
kubectl rollout undo deployment/firewall-api --to-revision=${PREVIOUS_DEPLOYMENT}

# Wait for rollback to complete
kubectl rollout status deployment/firewall-api

# Verify old credentials are restored
kubectl get secret firewall-auth-secrets -o jsonpath='{.data.AUTH_ISSUER}' | base64 -d
```

---

## Monitoring & Audit

### Metrics to Monitor During Rotation

```yaml
# Prometheus alerts
groups:
- name: secrets-rotation
  rules:
  - alert: FailedAuthRequests
    expr: rate(http_requests_total{status="401"}[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High rate of auth failures — possible credential mismatch"

  - alert: S3WriteFailures
    expr: rate(audit_write_errors_total[5m]) > 0.05
    for: 2m
    annotations:
      summary: "S3 audit writes failing — check AUDIT_S3_* credentials"

  - alert: CertificatePinningFailures
    expr: rate(tls_pinning_failures_total[5m]) > 0.01
    for: 2m
    annotations:
      summary: "TLS cert pinning failures — JWKS cert may be outdated"
```

### Audit Trail Entries

Every rotation must be recorded:

```json
{
  "timestamp": "2026-05-15T10:30:00Z",
  "event_type": "secrets-rotation",
  "secret_name": "AUTH_ISSUER",
  "old_value_hash": "sha256:abc123...",
  "new_value_hash": "sha256:def456...",
  "initiated_by": "devops-team@example.com",
  "status": "success",
  "duration_seconds": 180,
  "pods_restarted": 3,
  "audit_location": "s3://firewall-audit-bucket/rotations/2026-05-15-auth-issuer.json"
}
```

---

## Runbooks

### 🔄 Runbook: Emergency Auth Credential Rotation

**Trigger:** Security incident or token compromise  
**Duration:** ~10 minutes  
**Owner:** Security + DevOps

```markdown
1. [ ] Declare incident (Slack #security-incidents)
2. [ ] Revoke old credentials in Entra ID
3. [ ] Obtain new credentials from Entra ID admin
4. [ ] Test new credentials in staging
5. [ ] Update K8s secret (kubectl patch)
6. [ ] Monitor error rate (5 min window)
7. [ ] If errors: kubectl rollout undo
8. [ ] If healthy: Confirm all pods restarted
9. [ ] Run smoke tests
10. [ ] Close incident ticket
11. [ ] Post-mortem scheduled for next week
```

### 🔄 Runbook: Scheduled AWS Credential Rotation (Monthly)

**Trigger:** Monthly maintenance window (2nd Tuesday, 02:00 UTC)  
**Duration:** ~15 minutes  
**Owner:** DevOps

```markdown
1. [ ] Notify #firewall-api-oncall of upcoming rotation
2. [ ] Create new AWS access key (aws iam create-access-key)
3. [ ] Test new key locally
4. [ ] Store in K8s secret + HashiCorp Vault
5. [ ] Deploy rolling update (kubectl set env)
6. [ ] Monitor logs for S3 errors (10 min window)
7. [ ] Run audit CSV export test
8. [ ] Deactivate old key (aws iam update-access-key-status)
9. [ ] Verify no errors after 24h
10. [ ] Delete old key (aws iam delete-access-key)
11. [ ] Update runbook log
```

### 🔄 Runbook: TLS Cert Renewal (Annual)

**Trigger:** Certificate expiry warning from Entra ID  
**Duration:** ~20 minutes  
**Owner:** Security + DevOps

```markdown
1. [ ] Retrieve new cert from Entra ID or cert provider
2. [ ] Validate cert (openssl x509)
3. [ ] Create K8s ConfigMap with new cert
4. [ ] Verify configmap was created
5. [ ] Update deployment to reference new configmap
6. [ ] Trigger rolling restart
7. [ ] Monitor logs for pinning errors
8. [ ] Run integration tests
9. [ ] Keep old cert in archive for 30 days
10. [ ] Document in runbook log
```

---

## Implementation Checklist

- [ ] Map all secrets (auth, S3, keys, certs)
- [ ] Define rotation cadences per secret type
- [ ] Choose integration pattern (K8s Secrets, Vault, AWS Secrets Manager)
- [ ] Create init container or sidecar for secret fetching
- [ ] Write pre-rotation test scripts
- [ ] Document rollback procedures
- [ ] Set up Prometheus alerts
- [ ] Create runbooks for each rotation type
- [ ] Train DevOps team on procedures
- [ ] Schedule first rotation
- [ ] Audit initial rotation and document lessons learned

---

## Security Best Practices

1. **Principle of Least Privilege:** Each secret has minimal access scope
2. **Encryption in Transit:** All secrets transmitted over TLS
3. **Encryption at Rest:** Secrets stored in encrypted K8s etcd or Vault
4. **Audit Trail:** Every rotation logged with timestamp, initiator, and status
5. **Grace Periods:** Allow 7-day overlap between old and new credentials
6. **Monitoring:** Real-time alerts on auth/S3 failures during rotation
7. **Testing:** All rotations validated in staging before production
8. **Approval Workflow:** Multi-person sign-off for critical credentials

---

## References

- [NIST SP 800-153: Password Policies](https://csrc.nist.gov/publications/detail/sp/800-153)
- [AWS Best Practices for Managing Credentials](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
- [HashiCorp Vault Authentication Methods](https://www.vaultproject.io/docs/auth)
- [Kubernetes Secrets Best Practices](https://kubernetes.io/docs/concepts/configuration/secret/)
