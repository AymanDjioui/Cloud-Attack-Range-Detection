#!/usr/bin/env python3
"""
Mock AWS Instance Metadata Service (IMDS)
==========================================
Simulates the EC2 metadata service at 169.254.169.254.
In our lab, the SecureBank API's SSRF vulnerability can reach
this service via the Docker network (hostname: imds).

Returns fake IAM credentials that work against LocalStack.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [IMDS] %(message)s")
log = logging.getLogger("imds")

# ── Simulated IAM credentials ─────────────────────────────────
# These "stolen" creds work against LocalStack (which accepts any creds)
ROLE_NAME = "banking-api-role"
CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": "2026-04-17T04:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIA3EXAMPLESTOLEN01",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "FwoGZXIvYXdzEBAaDHka5example-session-token",
    "Expiration": "2026-04-18T04:00:00Z"
}

INSTANCE_ID = "i-0abc123def456ghi7"
INSTANCE_TYPE = "t3.medium"
LOCAL_IPV4 = "10.0.1.50"
AVAILABILITY_ZONE = "us-east-1a"


class IMDSHandler(BaseHTTPRequestHandler):
    """Handles IMDS v1 requests (no token required)."""

    def do_GET(self):
        path = self.path.rstrip("/")
        log.info(f"GET {path} from {self.client_address[0]}")

        routes = {
            "/latest/meta-data": "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\nplacement/\niam/",
            "/latest/meta-data/ami-id": "ami-0abcdef1234567890",
            "/latest/meta-data/instance-id": INSTANCE_ID,
            "/latest/meta-data/instance-type": INSTANCE_TYPE,
            "/latest/meta-data/local-ipv4": LOCAL_IPV4,
            "/latest/meta-data/placement/availability-zone": AVAILABILITY_ZONE,
            "/latest/meta-data/iam": "info\nsecurity-credentials/",
            "/latest/meta-data/iam/info": json.dumps({
                "Code": "Success",
                "InstanceProfileArn": f"arn:aws:iam::000000000000:instance-profile/{ROLE_NAME}",
                "InstanceProfileId": "AIPA3EXAMPLEPROFILE"
            }),
            "/latest/meta-data/iam/security-credentials": ROLE_NAME,
            f"/latest/meta-data/iam/security-credentials/{ROLE_NAME}": json.dumps(CREDENTIALS, indent=2),
        }

        if path in routes:
            response = routes[path]
            self.send_response(200)
            if path.endswith(ROLE_NAME) or path.endswith("info"):
                self.send_header("Content-Type", "application/json")
            else:
                self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.write_response(response)
        else:
            self.send_response(404)
            self.end_headers()
            self.write_response("Not Found")

    def do_PUT(self):
        """Handle IMDS v2 token requests."""
        if "/latest/api/token" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.write_response("mock-imds-token-v2")
        else:
            self.send_response(404)
            self.end_headers()

    def write_response(self, text):
        self.wfile.write(text.encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), IMDSHandler)
    log.info("═" * 50)
    log.info("  Mock IMDS Service — Running on port 80")
    log.info(f"  Role: {ROLE_NAME}")
    log.info("═" * 50)
    server.serve_forever()
