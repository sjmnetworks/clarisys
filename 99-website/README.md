# 99-website

Clarisys website — React + Astro, deployed to S3/CloudFront.

## Getting started

```bash
npm install
npm run dev
```

## Deploying

```bash
./deploy-website.sh dev   # deploy to dev
./deploy-website.sh prod  # deploy to prod
```

Configure S3 bucket names, CloudFront IDs, and FQDNs in `env.config.json`.

### Prerequisites

- AWS CLI configured with appropriate credentials
- `jq` installed
