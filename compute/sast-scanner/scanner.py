"""
SAST Scanner — Compliance Evidence Vault
Ankita Das | CS6620

Reads a .zip from S3 (pre-signed URL passed via env),
runs regex-based static analysis across 11 vulnerability
types, writes findings to RDS PostgreSQL, and uploads
a hashed JSON report back to S3.
"""

import os
import re
import json
import uuid
import hashlib
import zipfile
import tempfile
import logging
import boto3
import psycopg2
import requests
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 11 vulnerability patterns (OWASP-aligned)
# ---------------------------------------------------------------------------
VULN_PATTERNS = {
    "SQL_INJECTION": {
        "severity": "HIGH",
        "patterns": [
            r'execute\s*\(\s*["\'].*?\%',                    # string formatting in SQL
            r'cursor\.execute\s*\(\s*f["\']',                # f-string in execute
            r'SELECT.*\+.*request\.',                        # string concat with request
            r'query\s*=\s*["\'].*\+',                        # query built by concat
        ],
        "description": "Potential SQL injection via unsanitised input in query construction",
    },
    "HARDCODED_SECRET": {
        "severity": "HIGH",
        "patterns": [
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            r'(?i)(api_key|apikey|secret_key|auth_token)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?i)aws_secret_access_key\s*=\s*["\'][^"\']+["\']',
            r'(?i)private_key\s*=\s*["\']-----BEGIN',
        ],
        "description": "Hardcoded credential or secret detected in source code",
    },
    "COMMAND_INJECTION": {
        "severity": "HIGH",
        "patterns": [
            r'os\.system\s*\(',
            r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True',
            r'eval\s*\(\s*request\.',
            r'exec\s*\(\s*request\.',
        ],
        "description": "Potential OS command injection via unsanitised input",
    },
    "XSS": {
        "severity": "MEDIUM",
        "patterns": [
            r'innerHTML\s*=\s*(?!`[^$])',                    # direct innerHTML assignment
            r'document\.write\s*\(',
            r'dangerouslySetInnerHTML',
            r'render_template_string\s*\(.*request\.',
        ],
        "description": "Potential Cross-Site Scripting (XSS) vulnerability",
    },
    "INSECURE_DESERIALIZATION": {
        "severity": "HIGH",
        "patterns": [
            r'pickle\.loads\s*\(',
            r'yaml\.load\s*\([^,)]*\)',                      # yaml.load without Loader
            r'marshal\.loads\s*\(',
            r'jsonpickle\.decode\s*\(',
        ],
        "description": "Insecure deserialization — arbitrary object instantiation possible",
    },
    "PATH_TRAVERSAL": {
        "severity": "MEDIUM",
        "patterns": [
            r'open\s*\(\s*request\.',
            r'open\s*\(.*\+.*request\.',
            r'os\.path\.join\s*\(.*request\.',
            r'send_file\s*\(.*request\.',
        ],
        "description": "Potential path traversal — user input used in file path construction",
    },
    "WEAK_CRYPTO": {
        "severity": "MEDIUM",
        "patterns": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'DES\s*\(',
            r'Cipher\.new\s*\(.*MODE_ECB',
        ],
        "description": "Weak or deprecated cryptographic algorithm detected",
    },
    "INSECURE_RANDOM": {
        "severity": "LOW",
        "patterns": [
            r'random\.random\s*\(',
            r'random\.randint\s*\(',
            r'Math\.random\s*\(',
        ],
        "description": "Non-cryptographic RNG used — use secrets or os.urandom for security-sensitive values",
    },
    "OPEN_REDIRECT": {
        "severity": "MEDIUM",
        "patterns": [
            r'redirect\s*\(\s*request\.',
            r'HttpResponseRedirect\s*\(\s*request\.',
            r'res\.redirect\s*\(\s*req\.',
        ],
        "description": "Potential open redirect — redirect target derived from user input",
    },
    "SSRF": {
        "severity": "HIGH",
        "patterns": [
            r'requests\.get\s*\(\s*request\.',
            r'urllib\.request\.urlopen\s*\(\s*request\.',
            r'fetch\s*\(\s*req\.',
            r'axios\.(get|post)\s*\(\s*req\.',
        ],
        "description": "Potential Server-Side Request Forgery (SSRF) — URL derived from user input",
    },
    "DEBUG_ENABLED": {
        "severity": "LOW",
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'app\.run\s*\(.*debug\s*=\s*True',
            r'app\.config\[.DEBUG.\]\s*=\s*True',
        ],
        "description": "Debug mode enabled in production code",
    },
}

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".sh", ".yaml", ".yml", ".env",
}


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

def scan_file(filepath: Path, relative_path: str) -> list[dict]:
    """Scan a single file and return a list of finding dicts."""
    findings = []
    try:
        content = filepath.read_text(errors="replace")
        lines = content.splitlines()
    except Exception as e:
        log.warning(f"Could not read {relative_path}: {e}")
        return findings

    for vuln_type, meta in VULN_PATTERNS.items():
        for pattern in meta["patterns"]:
            for line_num, line in enumerate(lines, start=1):
                if re.search(pattern, line):
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "vuln_type": vuln_type,
                        "severity": meta["severity"],
                        "detail": meta["description"],
                        "file": relative_path,
                        "line": line_num,
                        "snippet": line.strip()[:200],
                    })
    return findings


def scan_zip(zip_path: str) -> list[dict]:
    """Extract zip and scan every scannable file."""
    all_findings = []
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)
        root = Path(tmpdir)
        for fpath in root.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in SCANNABLE_EXTENSIONS:
                relative = str(fpath.relative_to(root))
                findings = scan_file(fpath, relative)
                all_findings.extend(findings)
                if findings:
                    log.info(f"  {relative}: {len(findings)} finding(s)")
    return all_findings


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------

def download_from_presigned_url(url: str, dest: str) -> None:
    log.info("Downloading source zip from pre-signed URL...")
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    with open(dest, "wb") as f:
        f.write(r.content)
    log.info(f"Downloaded {len(r.content):,} bytes → {dest}")


def upload_report_to_s3(report: dict, bucket: str, key: str) -> str:
    """Serialize, hash, and upload the JSON report. Returns the SHA-256 hex digest."""
    payload = json.dumps(report, indent=2, default=str).encode()
    digest = hashlib.sha256(payload).hexdigest()
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=payload,
        ContentType="application/json",
        Metadata={"sha256": digest},
    )
    log.info(f"Report uploaded to s3://{bucket}/{key} (sha256={digest[:12]}…)")
    return digest


def get_db_conn():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connect_timeout=10,
        sslmode=os.environ.get("DB_SSLMODE", "require"),
    )


def write_to_rds(job_id: str, findings: list[dict], report_s3_key: str, sha256: str) -> None:
    log.info(f"Writing {len(findings)} findings to RDS for job {job_id}...")
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Mark job RUNNING (idempotent — Step Functions may have already done this)
                cur.execute(
                    "UPDATE jobs SET status='RUNNING', updated_at=now() WHERE id=%s AND status='PENDING'",
                    (job_id,),
                )
                # Insert findings
                for f in findings:
                    cur.execute(
                        """
                        INSERT INTO findings
                            (id, job_id, severity, vuln_type, detail, file_path, line_number, snippet)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            f["id"], job_id, f["severity"], f["vuln_type"],
                            f["detail"], f["file"], f["line"], f["snippet"],
                        ),
                    )
                # Mark job COMPLETED
                cur.execute(
                    """
                    UPDATE jobs
                    SET status='COMPLETED', s3_report_key=%s, report_sha256=%s, updated_at=now()
                    WHERE id=%s
                    """,
                    (report_s3_key, sha256, job_id),
                )
    finally:
        conn.close()
    log.info("RDS write complete — job marked COMPLETED")


def mark_job_failed(job_id: str, error: str) -> None:
    try:
        conn = get_db_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE jobs SET status='FAILED', error_message=%s, updated_at=now() WHERE id=%s",
                    (error[:500], job_id),
                )
        conn.close()
        log.info(f"Job {job_id} marked FAILED in RDS")
    except Exception as e:
        log.error(f"Could not mark job failed in RDS: {e}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    job_id         = os.environ["JOB_ID"]
    presigned_url  = os.environ["S3_PRESIGNED_URL"]
    report_bucket  = os.environ["REPORT_BUCKET"]
    report_key     = f"reports/sast/{job_id}/report.json"

    log.info(f"=== SAST Scanner starting | job_id={job_id} ===")

    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            zip_path = tmp.name

        download_from_presigned_url(presigned_url, zip_path)

        log.info("Starting static analysis...")
        findings = scan_zip(zip_path)
        log.info(f"Scan complete — {len(findings)} total findings")

        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        report = {
            "job_id":          job_id,
            "scan_type":       "SAST",
            "scanned_at":      datetime.now(timezone.utc).isoformat(),
            "total_findings":  len(findings),
            "severity_summary": severity_counts,
            "findings":        findings,
        }

        sha256 = upload_report_to_s3(report, report_bucket, report_key)
        write_to_rds(job_id, findings, report_key, sha256)

        log.info("=== SAST Scanner finished successfully ===")

    except Exception as e:
        log.error(f"Scanner failed: {e}", exc_info=True)
        mark_job_failed(job_id, str(e))
        raise


if __name__ == "__main__":
    main()