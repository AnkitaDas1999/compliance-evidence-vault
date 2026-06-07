-- Compliance Evidence Vault — RDS Schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid()

CREATE TABLE IF NOT EXISTS jobs (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_type        VARCHAR(10) NOT NULL CHECK (scan_type IN ('SAST','PENTEST')),
  status           VARCHAR(10) NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED')),
  s3_key           TEXT,
  s3_report_key    TEXT,
  report_sha256    CHAR(64),
  error_message    TEXT,
  created_at       TIMESTAMPTZ DEFAULT now(),
  updated_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id       UUID        NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  severity     VARCHAR(8)  NOT NULL CHECK (severity IN ('HIGH','MEDIUM','LOW')),
  vuln_type    TEXT        NOT NULL,
  detail       TEXT,
  file_path    TEXT,
  line_number  INTEGER,
  snippet      TEXT,
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- Indexes for dashboard queries
CREATE INDEX IF NOT EXISTS idx_findings_job_id  ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_jobs_status       ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_scan_type    ON jobs(scan_type);

-- Seed a test job so scanners can update it immediately
INSERT INTO jobs (id, scan_type, status)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'SAST',    'PENDING'),
  ('00000000-0000-0000-0000-000000000002', 'PENTEST', 'PENDING')
ON CONFLICT DO NOTHING;