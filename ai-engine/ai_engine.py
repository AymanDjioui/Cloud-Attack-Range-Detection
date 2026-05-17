# AI Analysis Engine - Gemini-Powered Wazuh Alert Processor
#!/usr/bin/env python3
"""
AI Analysis Engine — Phase 5
=============================
Polls the Wazuh Manager API for new alerts, sends them to
Google Gemini AI for analysis, and stores the results in
PostgreSQL for the AI Insights web panel to display.
"""

import os
import json
import time
import logging
import requests
import urllib3
import psycopg2
from datetime import datetime, timezone

# Suppress SSL warnings for Wazuh self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ──────────────────────────────────────────────
WAZUH_INDEXER   = os.getenv("WAZUH_INDEXER", "https://wazuh.indexer:9200")
INDEXER_USER    = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS    = os.getenv("INDEXER_PASS", "SecretPassword")
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
DB_URL          = os.getenv("DATABASE_URL", "postgresql://admin:admin_password@db:5432/insights_db")
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "60"))
MIN_RULE_LEVEL  = int(os.getenv("MIN_RULE_LEVEL", "6"))  # Only analyze level 6+

# ── Logging ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AI-ENGINE] %(levelname)s  %(message)s"
)
log = logging.getLogger("ai_engine")

# Track processed alert IDs
processed_alerts = set()


def get_recent_alerts():
    """Fetch recent alerts from Wazuh Indexer (OpenSearch)."""
    try:
        query = {
            "size": 20,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}}
                    ]
                }
            }
        }
        r = requests.post(
            f"{WAZUH_INDEXER}/wazuh-alerts-4.x-*/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=False,
            timeout=15
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        alerts = [hit["_source"] for hit in hits]
        # Add _id as alert id
        for i, hit in enumerate(hits):
            alerts[i]["id"] = hit["_id"]
        return alerts
    except Exception as e:
        log.error(f"Failed to fetch alerts from indexer: {e}")
        return []



def analyze_with_gemini(alert):
    """Send an alert to Gemini AI for analysis."""
    if not GEMINI_API_KEY:
        return generate_local_analysis(alert)

    prompt = f"""You are a senior SOC analyst. Analyze this security alert from a Wazuh SIEM monitoring a cloud banking environment.

ALERT DATA:
- Rule ID: {alert.get('rule', {}).get('id', 'N/A')}
- Rule Level: {alert.get('rule', {}).get('level', 'N/A')}
- Description: {alert.get('rule', {}).get('description', 'N/A')}
- MITRE ATT&CK: {json.dumps(alert.get('rule', {}).get('mitre', {}), indent=2)}
- Source IP: {alert.get('data', {}).get('sourceIPAddress', alert.get('agent', {}).get('ip', 'N/A'))}
- Agent: {alert.get('agent', {}).get('name', 'N/A')}
- Timestamp: {alert.get('timestamp', 'N/A')}
- Full Data: {json.dumps(alert.get('data', {}), indent=2)}

Provide your analysis in this exact JSON format:
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "summary": "One-line plain-English summary of what happened",
    "analysis": "2-3 paragraph detailed analysis of the attack, what the attacker did, and the implications",
    "remediation": ["Step 1...", "Step 2...", "Step 3..."],
    "threat_hunting": ["Elasticsearch query to find similar activity", "Wazuh query to hunt for this attacker"],
    "ioc": ["List of Indicators of Compromise found"],
    "mitre_tactics": ["List of MITRE ATT&CK tactics and techniques used"]
}}

Respond ONLY with valid JSON, no markdown formatting."""

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024}
        }
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()

        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        # Clean markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]

        analysis = json.loads(text.strip())
        log.info(f"🧠 Gemini analysis: {analysis.get('severity', 'N/A')} — {analysis.get('summary', 'N/A')}")
        return analysis

    except Exception as e:
        log.error(f"Gemini API error: {e}")
        return generate_local_analysis(alert)


def generate_local_analysis(alert):
    """Fallback analysis when Gemini API is not available."""
    rule_id = alert.get("rule", {}).get("id", "")
    rule_desc = alert.get("rule", {}).get("description", "Unknown alert")
    rule_level = alert.get("rule", {}).get("level", 0)
    source_ip = alert.get("data", {}).get("sourceIPAddress", "unknown")
    user = alert.get("data", {}).get("userIdentity", {}).get("userName", "unknown")

    # Map rules to pre-built analysis
    analyses = {
        "100110": {
            "severity": "CRITICAL",
            "summary": f"Server-Side Request Forgery (SSRF) attack targeting AWS Instance Metadata Service detected from {source_ip}",
            "analysis": f"An attacker from IP {source_ip} exploited a Server-Side Request Forgery (SSRF) vulnerability in the SecureBank API's payment verification endpoint to access the AWS Instance Metadata Service (IMDS). This is a well-known cloud attack technique where the attacker tricks the server into making HTTP requests to internal services that should not be externally accessible.\n\nThe IMDS at 169.254.169.254 contains sensitive information including temporary IAM credentials. By accessing this endpoint, the attacker can steal AWS access keys and session tokens, effectively impersonating the server's IAM role. This is classified as credential theft and represents a critical security breach.\n\nThis attack matches the MITRE ATT&CK techniques T1190 (Exploit Public-Facing Application) and T1552.005 (Cloud Instance Metadata API). Immediate incident response is required.",
            "remediation": [
                "Block the source IP immediately in the WAF and security groups",
                "Rotate all IAM credentials and session tokens for the affected role",
                "Implement IMDS v2 (token-required) to prevent SSRF-based metadata access",
                "Add URL validation and allowlisting to the verify-gateway endpoint",
                "Enable VPC endpoint policies to restrict metadata service access",
                "Review CloudTrail logs for any unauthorized API calls using stolen credentials"
            ],
            "threat_hunting": [
                f"data.sourceIPAddress: {source_ip}",
                "rule.id: 100110 AND data.http_url: *169.254.169.254*"
            ],
            "ioc": [f"Source IP: {source_ip}", f"Compromised user: {user}", "Target: IMDS endpoint", "Technique: SSRF via verify-gateway"],
            "mitre_tactics": ["T1190 — Exploit Public-Facing Application", "T1552.005 — Cloud Instance Metadata API", "Initial Access", "Credential Access"]
        },
        "100111": {
            "severity": "HIGH",
            "summary": f"SSRF attempt detected from {source_ip} via payment verification endpoint",
            "analysis": f"A Server-Side Request Forgery attempt was detected from {source_ip}. The attacker is using the verify-gateway endpoint to probe internal network resources. While this specific request did not target the IMDS directly, it indicates active reconnaissance of internal services.\n\nThis is likely a precursor to a more targeted attack where the attacker maps internal services before attempting credential theft via the metadata service.",
            "remediation": ["Implement input validation on the verify-gateway endpoint", "Add URL allowlisting for external payment gateways only", "Monitor for follow-up IMDS access attempts"],
            "threat_hunting": [
                f"rule.id: 100111 AND data.sourceIPAddress: {source_ip}"
            ],
            "ioc": [f"Source IP: {source_ip}", f"User: {user}"],
            "mitre_tactics": ["T1190 — Exploit Public-Facing Application", "Discovery"]
        },
        "100121": {
            "severity": "MEDIUM",
            "summary": f"Failed authentication attempt for user '{user}' from {source_ip}",
            "analysis": f"A failed login attempt was recorded for user '{user}' from IP {source_ip}. Multiple failed attempts from the same source may indicate a brute-force or credential-stuffing attack against the SecureBank application.",
            "remediation": ["Implement account lockout after 5 failed attempts", "Enable CAPTCHA for login forms", "Consider implementing MFA"],
            "threat_hunting": [
                f"rule.id: 100121 AND data.userIdentity.userName: {user}"
            ],
            "ioc": [f"Source IP: {source_ip}", f"Target user: {user}"],
            "mitre_tactics": ["T1110 — Brute Force", "Credential Access"]
        },
        "100140": {
            "severity": "CRITICAL",
            "summary": f"DynamoDB full table scan detected — data exfiltration in progress from {source_ip}",
            "analysis": f"A full DynamoDB table scan was performed from {source_ip}, indicating active data exfiltration. The attacker is dumping the entire CompanyClients table which contains sensitive customer data including credit card numbers.\n\nThis is the final stage of the attack chain: SSRF → IMDS credential theft → DynamoDB exfiltration. The attacker has successfully compromised the cloud infrastructure.",
            "remediation": ["Revoke all stolen IAM credentials immediately", "Enable DynamoDB encryption at rest", "Implement fine-grained access control on DynamoDB tables", "Notify affected customers of the data breach"],
            "threat_hunting": [
                "data.eventName: Scan AND data.eventSource: dynamodb.amazonaws.com"
            ],
            "ioc": [f"Source IP: {source_ip}", "Table: CompanyClients", "Action: Full table scan"],
            "mitre_tactics": ["T1530 — Data from Cloud Storage", "T1005 — Data from Local System", "Exfiltration"]
        }
    }

    # Default analysis for unknown rules
    default = {
        "severity": "HIGH" if rule_level >= 12 else "MEDIUM" if rule_level >= 8 else "LOW",
        "summary": rule_desc,
        "analysis": f"Security alert triggered: {rule_desc}. Source: {source_ip}. This event requires investigation by the SOC team.",
        "remediation": ["Investigate the alert in the Wazuh dashboard", "Check for related events from the same source", "Escalate if confirmed malicious"],
        "threat_hunting": [f"data.sourceIPAddress: {source_ip}"],
        "ioc": [f"Source IP: {source_ip}"],
        "mitre_tactics": [str(m) for m in alert.get("rule", {}).get("mitre", {}).get("id", [])]
    }

    return analyses.get(rule_id, default)


def init_database():
    """Initialize the PostgreSQL database table."""
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_insights (
            id SERIAL PRIMARY KEY,
            alert_id TEXT UNIQUE,
            timestamp TIMESTAMPTZ DEFAULT NOW(),
            rule_id TEXT,
            rule_level INTEGER,
            rule_description TEXT,
            source_ip TEXT,
            agent_name TEXT,
            severity TEXT,
            ai_summary TEXT,
            ai_analysis TEXT,
            ai_remediation JSONB,
            threat_hunting JSONB,
            ai_ioc JSONB,
            mitre_tactics JSONB,
            raw_alert JSONB
        )
    """)
    # Add threat_hunting column if it doesn't exist (for existing databases)
    try:
        cur.execute("ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS threat_hunting JSONB")
    except Exception:
        pass
    conn.commit()
    cur.close()
    conn.close()
    log.info("✅ Database initialized")


def store_insight(alert, analysis):
    """Store the AI analysis in PostgreSQL."""
    alert_id = alert.get("id", str(time.time()))
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO ai_insights
                (alert_id, rule_id, rule_level, rule_description,
                 source_ip, agent_name, severity, ai_summary,
                 ai_analysis, ai_remediation, threat_hunting, ai_ioc, mitre_tactics, raw_alert)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (alert_id) DO NOTHING
        """, (
            alert_id,
            alert.get("rule", {}).get("id"),
            alert.get("rule", {}).get("level"),
            alert.get("rule", {}).get("description"),
            alert.get("data", {}).get("sourceIPAddress", "N/A"),
            alert.get("agent", {}).get("name", "N/A"),
            analysis.get("severity"),
            analysis.get("summary"),
            analysis.get("analysis"),
            json.dumps(analysis.get("remediation", [])),
            json.dumps(analysis.get("threat_hunting", [])),
            json.dumps(analysis.get("ioc", [])),
            json.dumps(analysis.get("mitre_tactics", [])),
            json.dumps(alert)
        ))
        conn.commit()
        log.info(f"💾 Insight stored: {alert_id}")
    except Exception as e:
        log.error(f"DB insert error: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()


def main():
    log.info("=" * 60)
    log.info("  🧠 AI Analysis Engine — Starting")
    log.info(f"  Indexer:     {WAZUH_INDEXER}")
    log.info(f"  Gemini:      {'✅ Enabled' if GEMINI_API_KEY else '⚠️ Disabled (using local analysis)'}")
    log.info(f"  Database:    {DB_URL.split('@')[1] if '@' in DB_URL else DB_URL}")
    log.info(f"  Min Level:   {MIN_RULE_LEVEL}")
    log.info(f"  Poll:        {POLL_INTERVAL}s")
    log.info("=" * 60)

    # Wait for DB to be ready
    for attempt in range(10):
        try:
            init_database()
            break
        except Exception as e:
            log.warning(f"DB not ready (attempt {attempt+1}/10): {e}")
            time.sleep(5)

    while True:
        # Fetch alerts from indexer
        alerts = get_recent_alerts()
        new_count = 0

        for alert in alerts:
            alert_id = alert.get("id", "")
            if alert_id in processed_alerts:
                continue

            rule_id = alert.get("rule", {}).get("id", "")
            # Only process our custom rules
            if not rule_id.startswith("100"):
                processed_alerts.add(alert_id)
                continue

            log.info(f"🔍 New alert: Rule {rule_id} — {alert.get('rule', {}).get('description', '')[:80]}")

            # Analyze with AI
            analysis = analyze_with_gemini(alert)

            # Store in database
            store_insight(alert, analysis)

            processed_alerts.add(alert_id)
            new_count += 1

        if new_count > 0:
            log.info(f"📊 Processed {new_count} new alerts")
        else:
            log.info("💤 No new custom alerts")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
