#!/usr/bin/env python3
"""
Runs SAST and Pentest scanners locally without Docker or AWS.

Usage:
    # SAST (no network needed):
    python local_test_runner.py sast

    # Pentest offline (no target app needed — uses mock responses):
    python local_test_runner.py pentest --offline

    # Pentest against real local target (start target-app/app.py first):
    python local_test_runner.py pentest --url http://localhost:8080

    # Both, offline:
    python local_test_runner.py all --offline
"""

import sys
import json
import importlib
import zipfile
import tempfile
import argparse
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# In-memory state (shared across both scanner runs)
# ---------------------------------------------------------------------------

class MockDB:
    def __init__(self):
        self.jobs = {
            "00000000-0000-0000-0000-000000000001": {"status": "PENDING", "scan_type": "SAST"},
            "00000000-0000-0000-0000-000000000002": {"status": "PENDING", "scan_type": "PENTEST"},
        }
        self.findings = []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if "status='RUNNING'" in s:
            jid = params[0] if params else None
            if jid in self.jobs:
                self.jobs[jid]["status"] = "RUNNING"
        elif "INSERT INTO findings" in s and params:
            self.findings.append({
                "id": params[0], "job_id": params[1], "severity": params[2],
                "vuln_type": params[3], "detail": params[4],
            })
        elif "COMPLETED" in s and "UPDATE jobs" in s and params:
            jid = params[-1]
            if jid in self.jobs:
                self.jobs[jid]["status"] = "COMPLETED"
        elif "status='FAILED'" in s and params:
            jid = params[-1]
            if jid in self.jobs:
                self.jobs[jid]["status"] = "FAILED"
                self.jobs[jid]["error"] = params[0]

    def __enter__(self): return self
    def __exit__(self, *a): pass

mock_db = MockDB()

class MockCursor:
    def execute(self, sql, params=None): mock_db.execute(sql, params)
    def __enter__(self): return self
    def __exit__(self, *a): pass

class MockConn:
    def cursor(self): return MockCursor()
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass

# ---------------------------------------------------------------------------
# Mock HTTP response factory (used in offline pentest mode)
# ---------------------------------------------------------------------------

def make_mock_response(status=200, headers=None, text="", cookies=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.text = text
    r.cookies = cookies or []
    r.raise_for_status = MagicMock()
    return r

OFFLINE_HEADERS = {
    # Intentionally missing most security headers so scanner fires findings
    "Server": "Apache/2.4.51",
    "X-Powered-By": "PHP/8.1",
    # NOT present: Strict-Transport-Security, Content-Security-Policy,
    # X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
}

def offline_requests_get(url, **kwargs):
    """Return a realistic-looking insecure response for every URL."""
    return make_mock_response(
        status=200,
        headers=OFFLINE_HEADERS,
        text=f"<html><body>Response for {url}</body></html>",
    )

def offline_requests_request(method, url, **kwargs):
    """TRACE and OPTIONS return 200 so dangerous-method probe fires."""
    if method in ("TRACE", "OPTIONS", "PUT", "DELETE"):
        return make_mock_response(status=200, headers=OFFLINE_HEADERS)
    return make_mock_response(status=405, headers=OFFLINE_HEADERS)

# ---------------------------------------------------------------------------
# SAST test
# ---------------------------------------------------------------------------

def run_sast_test():
    print("\n" + "=" * 60)
    print("SAST SCANNER — LOCAL TEST")
    print("=" * 60)

    sample = Path(__file__).parent / "sample_vulnerable_app.py"
    if not sample.exists():
        print(f"ERROR: {sample} not found.")
        print("Make sure you run this from the local-test/ directory.")
        sys.exit(1)

    # Build a zip of the sample vulnerable file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        zip_path = tmp.name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(sample, arcname="sample_vulnerable_app.py")

    zip_bytes = Path(zip_path).read_bytes()
    print(f"Test zip built: {len(zip_bytes):,} bytes, contains sample_vulnerable_app.py")

    job_id = "00000000-0000-0000-0000-000000000001"
    os.environ.update({
        "JOB_ID":           job_id,
        "S3_PRESIGNED_URL": "http://fake-s3/test.zip",
        "REPORT_BUCKET":    "compliance-vault-reports",
        "DB_HOST":          "localhost",
        "DB_NAME":          "vault",
        "DB_USER":          "vaultuser",
        "DB_PASSWORD":      "vaultpass",
        "DB_SSLMODE":       "disable",
    })

    # Add sast-scanner to path and force-reload the module so mock patches apply fresh
    sast_dir = str(Path(__file__).parent.parent / "sast-scanner")
    if sast_dir not in sys.path:
        sys.path.insert(0, sast_dir)

    # Remove cached module if present (fixes the 0-findings bug)
    if "scanner" in sys.modules:
        del sys.modules["scanner"]

    # Mock S3 response that returns our zip bytes
    mock_s3_response = MagicMock()
    mock_s3_response.content = zip_bytes
    mock_s3_response.raise_for_status = MagicMock()

    mock_boto3 = MagicMock()
    mock_boto3.client.return_value.put_object = MagicMock(side_effect=lambda **kw: print(
        f"  [MOCK S3] Upload → s3://{kw['Bucket']}/{kw['Key']}  ({len(kw['Body']):,} bytes)"
    ))

    with patch.dict("sys.modules", {"boto3": mock_boto3, "psycopg2": MagicMock()}):
        with patch("requests.get", return_value=mock_s3_response):
            import scanner as sast_scanner
            sast_scanner.get_db_conn = lambda: MockConn()
            sast_scanner.main()

    print("\n--- Findings in mock DB ---")
    job_findings = [f for f in mock_db.findings if f["job_id"] == job_id]
    sev_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in job_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
        print(f"  [{f['severity']:6}] {f['vuln_type']}")
    print(f"\n  Total: {len(job_findings)}  |  HIGH={sev_count['HIGH']}  MEDIUM={sev_count['MEDIUM']}  LOW={sev_count['LOW']}")
    print(f"  Job status: {mock_db.jobs[job_id]['status']}")

    Path(zip_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Pentest test
# ---------------------------------------------------------------------------

def run_pentest_test(target_url: str, offline: bool):
    print("\n" + "=" * 60)
    mode_label = "OFFLINE MODE (mock responses)" if offline else f"→ {target_url}"
    print(f"PENTEST SCANNER — LOCAL TEST {mode_label}")
    print("=" * 60)

    if offline:
        print("Running with mock HTTP responses — no target app needed.\n")

    job_id = "00000000-0000-0000-0000-000000000002"
    os.environ.update({
        "JOB_ID":        job_id,
        "TARGET_URL":    target_url,
        "REPORT_BUCKET": "compliance-vault-reports",
        "DB_HOST":       "localhost",
        "DB_NAME":       "vault",
        "DB_USER":       "vaultuser",
        "DB_PASSWORD":   "vaultpass",
        "DB_SSLMODE":    "disable",
    })

    pentest_dir = str(Path(__file__).parent.parent / "pentest-scanner")
    if pentest_dir not in sys.path:
        sys.path.insert(0, pentest_dir)

    # Remove cached sast scanner module so pentest scanner imports cleanly
    if "scanner" in sys.modules:
        del sys.modules["scanner"]

    mock_boto3 = MagicMock()
    mock_boto3.client.return_value.put_object = MagicMock(side_effect=lambda **kw: print(
        f"  [MOCK S3] Upload → s3://{kw['Bucket']}/{kw['Key']}  ({len(kw['Body']):,} bytes)"
    ))

    with patch.dict("sys.modules", {"boto3": mock_boto3, "psycopg2": MagicMock()}):
        if offline:
            with patch("requests.get",     side_effect=offline_requests_get), \
                 patch("requests.request", side_effect=offline_requests_request):
                import scanner as pentest_scanner
                pentest_scanner.get_db_conn = lambda: MockConn()
                pentest_scanner.main()
        else:
            import scanner as pentest_scanner
            pentest_scanner.get_db_conn = lambda: MockConn()
            pentest_scanner.main()

    print("\n--- Findings in mock DB ---")
    job_findings = [f for f in mock_db.findings if f["job_id"] == job_id]
    sev_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in job_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
        print(f"  [{f['severity']:6}] {f['vuln_type']:35} {f['detail'][:65]}")
    print(f"\n  Total: {len(job_findings)}  |  HIGH={sev_count['HIGH']}  MEDIUM={sev_count['MEDIUM']}  LOW={sev_count['LOW']}")
    print(f"  Job status: {mock_db.jobs[job_id]['status']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local scanner test runner")
    parser.add_argument("mode", choices=["sast", "pentest", "all"])
    parser.add_argument("--url",     default="http://localhost:8080",
                        help="Target URL for pentest (ignored in --offline mode)")
    parser.add_argument("--offline", action="store_true",
                        help="Pentest: use mock HTTP responses, no target app needed")
    args = parser.parse_args()

    if args.mode in ("sast", "all"):
        run_sast_test()
    if args.mode in ("pentest", "all"):
        run_pentest_test(args.url, offline=args.offline)

    print("\n✅ Local test complete.")