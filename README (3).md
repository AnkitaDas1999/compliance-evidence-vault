# Compliance Evidence Vault

> A combined SAST and API Penetration Testing platform with automated evidence storage, audit trails, and long-term report archival — built for CS6620 Cloud Computing (Spring 2026) at Northeastern University.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [AWS Services](#aws-services)
- [Project Structure](#project-structure)
- [Data Flow](#data-flow)
- [Prerequisites](#prerequisites)
- [Setup and Deployment](#setup-and-deployment)
- [Environment Variables](#environment-variables)
- [Database Schema](#database-schema)
- [S3 Bucket Structure](#s3-bucket-structure)
- [Retention Policy](#retention-policy)
- [API Reference](#api-reference)
- [Contributors](#contributors)

---

## Overview

The Compliance Evidence Vault is a cloud-native security platform that runs SAST (Static Application Security Testing) and API Penetration Testing scans on demand and stores the results as tamper-evident compliance evidence. It is designed for regulated organizations that need demonstrable records of security testing.

**What it does:**

- Accepts scan requests through a web dashboard
- Dispatches scans asynchronously via AWS Lambda to ECS Fargate containers
- Stores full JSON scan reports in S3 with versioning and encryption
- Records scan metadata in RDS PostgreSQL for fast dashboard queries
- Archives reports automatically after 30 days (simulating Glacier for long-term retention)
- Logs every API action via CloudTrail for a tamper-evident audit trail
- Enforces least-privilege access through IAM roles on every service boundary

**Tools used:**

| Tool | Type | What it scans |
|------|------|---------------|
| SAST Scanner | Static | JavaScript source code — detects hardcoded secrets, SQLi, XSS, path traversal, weak crypto, and 6 more |
| API Pentest | Dynamic | Live HTTP APIs — tests for missing auth, SQLi, NoSQLi, rate limiting, security headers, sensitive data exposure |

---

## Architecture

```
User (Browser)
     │
     ▼
ECS Fargate — Dashboard (React + Node.js proxy)
     │
     ▼
API Gateway  ─────────────────────────────────────────┐
     │                                                 │
     ▼                                                 │
Lambda — Dispatcher                                    │
     │  inserts pending row ──────────────────► RDS PostgreSQL
     │                                          (scan metadata)
     ├──── ECS RunTask ──► ECS Fargate — SAST Scanner
     │                          │
     └──── ECS RunTask ──► ECS Fargate — Pentest Scanner
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
           S3 — evidence-store      RDS PostgreSQL
           (full JSON reports)      (status = complete)
                    │
          lifecycle after 30 days
                    │
                    ▼
           S3 — archive-store
           (long-term retention)

CloudTrail ── logs all API calls account-wide ──► S3 — cloudtrail-logs
IAM ── least-privilege roles on every service boundary
```

---

## AWS Services

| Service | Role | Justification |
|---------|------|---------------|
| **ECS Fargate** | Dashboard + scanner containers | No servers to manage; containers scale to zero when idle; each scan runs in full isolation; satisfies Docker containerization requirement |
| **API Gateway** | Managed HTTP entry point | Decouples dashboard from Lambda; provides throttling (100 req/s burst), request validation, and a managed endpoint without exposing scanners publicly |
| **Lambda** | Async scan dispatcher | Stateless; costs nothing when idle; turns synchronous scan requests into async jobs so the dashboard never times out on long scans |
| **RDS PostgreSQL** | Scan metadata and queries | Fixed schema, relational queries, ACID guarantees; dashboard needs SQL for sorting and filtering by date, severity, and tool type |
| **S3 (evidence-store)** | Active scan report storage | Cheaper than RDS blobs for large JSON files; presigned URLs let the browser download directly; versioning provides report change history |
| **S3 (archive-store)** | Long-term report archival | Simulates Glacier (unavailable in Learner Lab); lifecycle rule auto-transitions objects after 30 days; demonstrates retention policy in practice |
| **CloudTrail** | Immutable API access log | Captures every AWS API call account-wide; log file validation makes logs tamper-evident; directly satisfies the audit trail deliverable |
| **IAM** | Least-privilege access control | Each service has only the permissions it needs — Lambda can only call ECS RunTask, Fargate can only write to S3 and RDS, dashboard can only read |

---

## Project Structure

```
compliance-evidence-vault/
├── sast/
│   └── backend/
│       ├── Dockerfile
│       ├── package.json
│       ├── server.js               # Express app — scan routes
│       └── reportPipeline.js       # S3 upload + RDS metadata write
├── pentest/
│   └── backend/
│       ├── Dockerfile
│       ├── package.json
│       ├── server.js               # Express app — pentest routes
│       ├── test-target.js          # Deliberately vulnerable test API
│       └── reportPipeline.js       # S3 upload + RDS metadata write
├── dashboard/
│   ├── Dockerfile
│   ├── package.json
│   ├── proxy/
│   │   └── server.js               # Express proxy backend
│   └── frontend/
│       ├── src/
│       │   ├── App.jsx
│       │   ├── views/
│       │   │   ├── ScanList.jsx    # All scans from RDS
│       │   │   ├── ScanDetail.jsx  # Report from S3 + presigned download
│       │   │   └── NewScan.jsx     # Trigger SAST or Pentest
│       └── index.html
├── lambda/
│   └── dispatcher/
│       ├── index.js                # Lambda handler
│       └── package.json
├── infra/
│   ├── iam-roles.json              # IAM policy documents
│   ├── lifecycle-rule.json         # S3 lifecycle rule config
│   ├── task-definitions/
│   │   ├── sast-task.json          # ECS task definition
│   │   ├── pentest-task.json
│   │   └── dashboard-task.json
│   └── deploy.sh                   # Full deployment script
├── docker-compose.yml              # Local development
└── README.md
```

---

## Data Flow

The end-to-end flow when a user triggers a scan:

1. **User opens dashboard** — accesses the ECS Fargate dashboard container directly via the public EC2/ECS DNS
2. **Dashboard calls API Gateway** — sends `POST /scan` with `{ tool, target }`
3. **API Gateway validates and forwards** — throttles at 100 req/s, validates request schema, forwards to Lambda
4. **Lambda dispatches** — generates a `job_id`, inserts a `pending` row into RDS, calls `ecs.runTask()` with the appropriate task definition, returns `{ job_id }` immediately
5. **Fargate scanner runs** — container starts, reads `JOB_ID` and `TARGET` from environment variables, runs the scan
6. **Results written** — scanner uploads full JSON report to `s3://evidence-store/{tool}/{timestamp}-{job_id}.json`, updates RDS row to `status=complete` with severity counts and S3 key
7. **Dashboard polls** — frontend polls `GET /scan/:jobId/status` every 3 seconds until complete, then fetches the report via a presigned S3 URL (15-minute expiry)
8. **Archival** — S3 lifecycle rule moves objects from `evidence-store` to `archive-store` after 30 days automatically

---

## Prerequisites

- Node.js 18+
- Docker and Docker Compose
- AWS CLI configured with Learner Lab credentials
- Access to an AWS Academy Learner Lab environment

---

## Setup and Deployment

### 1. Clone the repository

```bash
git clone https://github.com/<your-org>/compliance-evidence-vault.git
cd compliance-evidence-vault
```

### 2. Run locally with Docker Compose

```bash
docker-compose up
```

This starts:
- SAST scanner on `http://localhost:3001`
- Pentest scanner on `http://localhost:3002`
- Vulnerable test target on `http://localhost:4000`
- Dashboard on `http://localhost:3000`

### 3. Test the scanners locally

```bash
# Test SAST scanner
curl -X POST http://localhost:3001/scan/code \
  -H "Content-Type: application/json" \
  -d '{"code": "const password = \"admin123\";"}'

# Test pentest scanner against the vulnerable target
curl -X POST http://localhost:3002/scan \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://localhost:4000/api/users"}'
```

### 4. Deploy to AWS

```bash
# Set your environment variables first (see below)
chmod +x infra/deploy.sh
./infra/deploy.sh
```

The deploy script:
1. Creates S3 buckets (`evidence-store`, `archive-store`, `cloudtrail-logs`)
2. Enables versioning and SSE-S3 on `evidence-store`
3. Applies the lifecycle rule (30-day transition to `archive-store`)
4. Enables CloudTrail with log file validation
5. Creates IAM roles with least-privilege policies
6. Pushes Docker images to ECR
7. Registers ECS task definitions
8. Creates the ECS cluster and services
9. Deploys Lambda dispatcher and wires API Gateway

---

## Environment Variables

Never hardcode credentials. All secrets are stored in AWS Secrets Manager and passed as environment variables to ECS task definitions.

| Variable | Used by | Description |
|----------|---------|-------------|
| `DB_SECRET_ARN` | Fargate, Lambda | ARN of the RDS password secret in Secrets Manager |
| `DB_HOST` | Fargate, Lambda | RDS endpoint hostname |
| `DB_NAME` | Fargate, Lambda | PostgreSQL database name |
| `S3_EVIDENCE_BUCKET` | Fargate | Name of the evidence-store S3 bucket |
| `S3_ARCHIVE_BUCKET` | Fargate | Name of the archive-store S3 bucket |
| `ECS_CLUSTER` | Lambda | ECS cluster name for RunTask calls |
| `SAST_TASK_DEF` | Lambda | ECS task definition ARN for SAST scanner |
| `PENTEST_TASK_DEF` | Lambda | ECS task definition ARN for pentest scanner |
| `JOB_ID` | Fargate scanner | Injected at runtime by Lambda per scan |
| `TARGET` | Fargate scanner | Scan target (file path or URL), injected by Lambda |

> **Important:** Never commit `.env` files or hardcode any of the above values. The project rubric explicitly penalizes hardcoded credentials.

---

## Database Schema

```sql
CREATE TABLE scans (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id       UUID NOT NULL UNIQUE,
  tool         TEXT NOT NULL CHECK (tool IN ('sast', 'pentest')),
  target       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'running', 'complete', 'failed')),
  critical     INT DEFAULT 0,
  high         INT DEFAULT 0,
  medium       INT DEFAULT 0,
  low          INT DEFAULT 0,
  s3_key       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX idx_scans_job_id     ON scans (job_id);
```

---

## S3 Bucket Structure

### evidence-store

```
evidence-store/
├── sast/
│   └── 2026-05-28T14:00:00Z-<job_id>.json
└── pentest/
    └── 2026-05-28T15:30:00Z-<job_id>.json
```

Settings: versioning enabled, SSE-S3 encryption, public access blocked, bucket policy restricts writes to `fargate-scanner-role` only.

### archive-store

Same key structure as `evidence-store`. Objects are transitioned here automatically by the S3 lifecycle rule after 30 days. Settings: same encryption, object lock for compliance.

### cloudtrail-logs

```
cloudtrail-logs/
└── AWSLogs/<account-id>/CloudTrail/<region>/<year>/<month>/<day>/
    └── <account-id>_CloudTrail_<region>_<timestamp>_<hash>.json.gz
```

Log file validation is enabled — each log file includes a digest file with a hash chain so any tampering is detectable.

---

## Retention Policy

| Phase | Storage | Duration | Access |
|-------|---------|----------|--------|
| Active | S3 evidence-store | 0 to 30 days | `fargate-scanner-role` (write), `dashboard-role` (read) |
| Archive | S3 archive-store | 30 days to 1 year | `evidence-reader-role` (read-only) |
| Deletion | — | After 1 year | Automated by S3 lifecycle expiration rule |

This policy is framed against **SOC 2 Type II** requirements, which mandate that security testing evidence be retained for a minimum of 12 months and be accessible to auditors on request.

---

## API Reference

### API Gateway — `POST /scan`

Triggers a new scan asynchronously.

**Request:**
```json
{
  "tool": "sast",
  "target": "/path/to/source"
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending"
}
```

---

### Dashboard Proxy — `GET /scan/:jobId/status`

Polls scan status from RDS.

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "complete",
  "critical": 2,
  "high": 5,
  "medium": 3,
  "low": 1,
  "completed_at": "2026-05-28T14:02:33Z"
}
```

---

### Dashboard Proxy — `GET /scan/:jobId/download`

Returns a presigned S3 URL valid for 15 minutes.

**Response:**
```json
{
  "url": "https://evidence-store.s3.amazonaws.com/sast/2026-05-28T14:00:00Z-<job_id>.json?X-Amz-Expires=900&..."
}
```

---

### Dashboard Proxy — `GET /scans`

Returns all scan records from RDS ordered by date descending.

**Response:**
```json
[
  {
    "job_id": "...",
    "tool": "sast",
    "target": "/src/app.js",
    "status": "complete",
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1,
    "created_at": "2026-05-28T14:00:00Z",
    "completed_at": "2026-05-28T14:02:33Z"
  }
]
```

---

## Contributors

| Name | Role |
|------|------|
| **Shubham Kumar** | Infrastructure, Lambda + API Gateway, CloudTrail, IAM, architecture diagram, tradeoff analysis, retention policy |
| **Ankita Das** | Docker, ECS Fargate scanner deployment, S3 upload pipeline, RDS write logic, evidence storage demo |
| **Ishit Arhatia** | ECS Fargate dashboard, Node.js proxy backend, React frontend, audit log explanation document |

---

*CS6620 Fundamentals of Cloud Computing — Spring 2026 — Northeastern University, Khoury College of Computer Sciences*
