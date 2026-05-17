#!/usr/bin/env python3
"""
CloudTrail Log Forwarder — Phase 2 Middleware
=============================================
This script acts as middleware between LocalStack's CloudTrail (S3)
and the Wazuh SIEM agent. It:

1. Polls the S3 bucket for new CloudTrail log files
2. Downloads and decompresses them (gzipped JSON)
3. Parses individual events
4. Writes them as one-line JSON to /var/log/cloudtrail/cloudtrail.log
5. The Wazuh agent monitors that file and ships events to the SOC VM

Additionally, it monitors the SecureBank API container logs for
SSRF attempts, auth events, and suspicious activity, converting
them into CloudTrail-compatible JSON events.
"""

import boto3
import json
import gzip
import time
import os
import io
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────
S3_BUCKET         = os.getenv("S3_BUCKET", "company-cloudtrail-logs-local")
AWS_ENDPOINT      = os.getenv("AWS_ENDPOINT", "http://localstack:4566")
AWS_REGION        = os.getenv("AWS_REGION", "us-east-1")
LOG_OUTPUT        = os.getenv("LOG_OUTPUT", "/var/log/cloudtrail/cloudtrail.log")
POLL_INTERVAL     = int(os.getenv("POLL_INTERVAL", "30"))  # seconds
API_CONTAINER     = os.getenv("API_CONTAINER", "securebank_api")

# ── Logging setup ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FORWARDER] %(levelname)s  %(message)s"
)
log = logging.getLogger("cloudtrail_forwarder")

# ── S3 Client ──────────────────────────────────────────────────
s3 = boto3.client(
    "s3",
    endpoint_url=AWS_ENDPOINT,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name=AWS_REGION,
)

# Track processed objects to avoid duplicates
processed_keys = set()

def ensure_log_dir():
    """Create the output log directory if it doesn't exist."""
    Path(LOG_OUTPUT).parent.mkdir(parents=True, exist_ok=True)
    if not Path(LOG_OUTPUT).exists():
        Path(LOG_OUTPUT).touch()

def write_event(event: dict):
    """Write a single CloudTrail event as one JSON line to the output log."""
    line = json.dumps(event, separators=(",", ":"))
    with open(LOG_OUTPUT, "a") as f:
        f.write(line + "\n")
    log.info(f"  → Wrote event: {event.get('eventName', 'unknown')} "
             f"by {event.get('userIdentity', {}).get('userName', 'N/A')}")

def poll_s3_cloudtrail():
    """
    Poll the CloudTrail S3 bucket for new log files.
    CloudTrail stores logs as gzipped JSON in:
      s3://<bucket>/AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/<file>.json.gz
    """
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=S3_BUCKET):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key in processed_keys:
                    continue

                # Only process .json.gz CloudTrail files
                if not key.endswith(".json.gz"):
                    processed_keys.add(key)
                    continue

                log.info(f"📥 New CloudTrail log: {key}")
                try:
                    response = s3.get_object(Bucket=S3_BUCKET, Key=key)
                    compressed = response["Body"].read()

                    # Decompress and parse
                    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
                        data = json.loads(gz.read().decode("utf-8"))

                    records = data.get("Records", [])
                    log.info(f"   Found {len(records)} events in {key}")

                    for record in records:
                        write_event(record)

                except Exception as e:
                    log.warning(f"   Failed to process {key}: {e}")
                    # Try reading as plain JSON (LocalStack may not gzip)
                    try:
                        response = s3.get_object(Bucket=S3_BUCKET, Key=key)
                        raw = response["Body"].read().decode("utf-8")
                        data = json.loads(raw)
                        records = data.get("Records", [])
                        for record in records:
                            write_event(record)
                    except Exception as e2:
                        log.error(f"   Also failed as plain JSON: {e2}")

                processed_keys.add(key)

    except s3.exceptions.NoSuchBucket:
        log.warning(f"Bucket '{S3_BUCKET}' not found. Waiting for Terraform to create it...")
    except Exception as e:
        log.error(f"S3 polling error: {e}")

def parse_api_log_line(line: str) -> dict | None:
    """
    Parse a SecureBank API log line and convert it into a
    CloudTrail-compatible JSON event for Wazuh ingestion.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_ip = "unknown"

    # Extract IP from morgan combined log
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if ip_match:
        source_ip = ip_match.group(1)

    # ── SSRF Attempt ───────────────────────────────────────────
    ssrf_match = re.search(r"\[PAY-VERIFY\] user=(\S+) endpoint=(\S+) ip=(\S+)", line)
    if ssrf_match:
        user, endpoint, ip = ssrf_match.groups()
        event = {
            "eventVersion": "1.08",
            "eventSource": "securebank-api",
            "eventName": "SSRFAttempt",
            "eventTime": now,
            "awsRegion": AWS_REGION,
            "sourceIPAddress": ip,
            "userAgent": "securebank-api/verify-gateway",
            "userIdentity": {
                "type": "APIUser",
                "userName": user,
            },
            "requestParameters": endpoint,
            "eventType": "AwsApiCall",
            "recipientAccountId": "000000000000"
        }
        return event

    # ── Auth Failure ───────────────────────────────────────────
    auth_fail = re.search(r"\[AUTH FAILED\] user=(\S+) ip=(\S+)", line)
    if auth_fail:
        user, ip = auth_fail.groups()
        return {
            "eventVersion": "1.08",
            "eventSource": "securebank-api",
            "eventName": "ConsoleLoginFailure",
            "eventTime": now,
            "awsRegion": AWS_REGION,
            "sourceIPAddress": ip,
            "userIdentity": {"type": "APIUser", "userName": user},
            "responseElements": {"ConsoleLogin": "Failure"},
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "000000000000",
        }

    # ── Auth Success ───────────────────────────────────────────
    auth_ok = re.search(r"\[AUTH OK\] user=(\S+) ip=(\S+)", line)
    if auth_ok:
        user, ip = auth_ok.groups()
        return {
            "eventVersion": "1.08",
            "eventSource": "securebank-api",
            "eventName": "ConsoleLogin",
            "eventTime": now,
            "awsRegion": AWS_REGION,
            "sourceIPAddress": ip,
            "userIdentity": {"type": "APIUser", "userName": user},
            "responseElements": {"ConsoleLogin": "Success"},
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "000000000000",
        }

    # ── Transfer ───────────────────────────────────────────────
    transfer = re.search(r"\[TRANSFER\] (\S+) → (\S+) amount=(\S+)", line)
    if transfer:
        sender, recipient, amount = transfer.groups()
        return {
            "eventVersion": "1.08",
            "eventSource": "securebank-api",
            "eventName": "FundsTransfer",
            "eventTime": now,
            "awsRegion": AWS_REGION,
            "sourceIPAddress": source_ip,
            "userIdentity": {"type": "APIUser", "userName": sender},
            "requestParameters": {"recipient": recipient, "amount": amount},
            "eventType": "AwsApiCall",
            "recipientAccountId": "000000000000",
        }

    return None

def monitor_api_logs():
    """
    Read recent logs from the SecureBank API container and
    convert security-relevant entries to CloudTrail events.
    Uses docker logs --since to only get new entries.
    """
    try:
        result = subprocess.run(
            ["docker", "logs", "--since", f"{POLL_INTERVAL + 5}s", API_CONTAINER],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            event = parse_api_log_line(line)
            if event:
                write_event(event)
    except FileNotFoundError:
        log.warning("Docker CLI not available — skipping API log monitoring")
    except subprocess.TimeoutExpired:
        log.warning("Docker logs command timed out")
    except Exception as e:
        log.error(f"API log monitoring error: {e}")

# ══════════════════════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════════════════════
def main():
    log.info("=" * 60)
    log.info("  CloudTrail Forwarder — Starting")
    log.info(f"  S3 Bucket:    {S3_BUCKET}")
    log.info(f"  Endpoint:     {AWS_ENDPOINT}")
    log.info(f"  Output:       {LOG_OUTPUT}")
    log.info(f"  Poll interval: {POLL_INTERVAL}s")
    log.info("=" * 60)

    ensure_log_dir()

    while True:
        log.info("─── Polling cycle ───")
        poll_s3_cloudtrail()
        monitor_api_logs()
        log.info(f"💤 Sleeping {POLL_INTERVAL}s...")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
