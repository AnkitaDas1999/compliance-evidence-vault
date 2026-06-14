-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Jobs table: one row per scan submission
CREATE TABLE IF NOT EXISTS jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type   VARCHAR(10)  NOT NULL CHECK (scan_type IN ('SAST', 'PENTEST')),
    status      VARCHAR(10)  NOT NULL DEFAULT 'PENDING'
                             CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    s3_key      TEXT,
    error_msg   TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Findings table: one row per vulnerability found during a scan
CREATE TABLE IF NOT EXISTS findings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id      UUID         NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    severity    VARCHAR(8)   NOT NULL CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
    vuln_type   TEXT         NOT NULL,
    detail      TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Index so GET /jobs/{id} and scanner writes are fast
CREATE INDEX IF NOT EXISTS idx_findings_job_id ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status     ON jobs(status);

-- Auto-update updated_at on every status change
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_jobs_updated_at
    BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
