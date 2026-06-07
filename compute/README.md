# Compliance Evidence Vault — Compute Layer
**Owner: Ankita Das | CS6620**

This module owns:
- SAST scanner container (regex, 11 vuln types)
- Pentest scanner container (HTTP probing, 6 categories)
- ECS Fargate task definitions + ECR repos (Terraform)
- S3 lifecycle policy (Standard → Glacier)

---

## Directory structure

```
compute/
├── sast-scanner/
│   ├── scanner.py          ← core SAST logic
│   ├── Dockerfile
│   └── requirements.txt
├── pentest-scanner/
│   ├── scanner.py          ← core Pentest logic
│   ├── Dockerfile
│   └── requirements.txt
├── terraform/
│   └── main.tf             ← ECS, ECR, IAM, S3 lifecycle
└── local-test/
    ├── docker-compose.yml  ← full local stack
    ├── init-db.sql         ← shared DB schema
    ├── local_test_runner.py← mock-based test (no Docker needed)
    ├── sample_vulnerable_app.py ← SAST test input
    ├── push_to_ecr.sh      ← ECR deploy script
    └── target-app/         ← vulnerable Flask app for pentest
        ├── app.py
        └── Dockerfile
```

---

## Option A — Quickest: run scanners without Docker

Needs Python 3.12+ and `pip install requests`.

```bash
cd compute/local-test

# SAST — scans sample_vulnerable_app.py
python local_test_runner.py sast

# Pentest — needs a target; start the target app first:
cd target-app && pip install flask && python app.py &
cd ..
python local_test_runner.py pentest --url http://localhost:5000

# Both:
python local_test_runner.py all --url http://localhost:5000
```

Expected SAST output:
```
=== SAST Scanner starting | job_id=... ===
sample_vulnerable_app.py: 12 finding(s)
Scan complete — 12 total findings
[MOCK S3] Would upload 4,832 bytes → s3://compliance-vault-reports/reports/sast/.../report.json
RDS write complete — job marked COMPLETED
Total: 12  |  HIGH: 5, MEDIUM: 4, LOW: 3
```

---

## Option B — Full Docker Compose stack (closest to prod)

Needs Docker Desktop + Docker Compose v2.

```bash
cd compute/local-test

# 1. Start infrastructure (postgres + localstack)
docker compose up postgres localstack setup target -d

# Wait for healthy (watch docker compose ps)

# 2. Run SAST scanner
docker compose --profile sast run --rm \
  -e JOB_ID=00000000-0000-0000-0000-000000000001 \
  -e S3_PRESIGNED_URL="$(python3 make_presigned.py)" \
  sast

# 3. Run Pentest scanner
docker compose --profile pentest run --rm \
  -e JOB_ID=00000000-0000-0000-0000-000000000002 \
  pentest

# 4. Check findings in postgres
docker compose exec postgres psql -U vaultuser -d vault \
  -c "SELECT vuln_type, severity, COUNT(*) FROM findings GROUP BY 1,2 ORDER BY 2,3 DESC;"

# 5. Check report in LocalStack S3
docker compose exec localstack \
  awslocal s3 ls s3://compliance-vault-reports/reports/ --recursive
```

### Making a pre-signed URL for local SAST testing

```bash
# Upload the sample zip to LocalStack first
cd local-test
zip test-upload.zip sample_vulnerable_app.py

AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:4566 \
  s3 cp test-upload.zip s3://compliance-vault-reports/uploads/test-upload.zip

# Generate a pre-signed URL (valid 1 hour)
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:4566 \
  s3 presign s3://compliance-vault-reports/uploads/test-upload.zip --expires-in 3600
```

---

## Option C — Deploy to AWS (after Terraform apply)

```bash
# 1. Run Terraform
cd compute/terraform
terraform init
terraform apply \
  -var="vpc_id=<from-ishit>" \
  -var='private_subnet_ids=["subnet-xxx","subnet-yyy"]' \
  -var="rds_security_group_id=<from-ishit>" \
  -var="report_bucket_name=<your-bucket>"

# 2. Push images to ECR
cd ../local-test
chmod +x push_to_ecr.sh
./push_to_ecr.sh <account-id> us-east-1

# 3. Verify ECR image scan results
aws ecr describe-image-scan-findings \
  --repository-name compliance-vault-compute-sast-scanner \
  --image-id imageTag=latest
```

---

## Environment variables reference

| Variable         | Description                        | Example                              |
|------------------|------------------------------------|--------------------------------------|
| `JOB_ID`         | UUID of the job                    | `abc123...`                          |
| `S3_PRESIGNED_URL`| Pre-signed URL to source .zip (SAST)| `https://s3.amazonaws.com/...`      |
| `TARGET_URL`     | URL to probe (Pentest)             | `https://myapp.example.com`          |
| `REPORT_BUCKET`  | S3 bucket for reports              | `compliance-vault-reports`           |
| `DB_HOST`        | RDS/Postgres hostname              | `vault-db.xxx.rds.amazonaws.com`     |
| `DB_NAME`        | Database name                      | `vault`                              |
| `DB_USER`        | DB username                        | `vaultuser`                          |
| `DB_PASSWORD`    | DB password (use SSM in prod)      | `...`                                |
| `DB_SSLMODE`     | `require` (AWS) / `disable` (local)| `require`                            |