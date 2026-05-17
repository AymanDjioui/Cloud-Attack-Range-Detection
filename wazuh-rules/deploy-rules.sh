#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  Deploy Custom Wazuh Rules — SOC VM (192.168.100.10)
#  Phase 3: Detection Rules for Cloud Attack Range
# ══════════════════════════════════════════════════════════════

set -e

MANAGER_CONTAINER="single-node-wazuh.manager-1"

echo "═══════════════════════════════════════════════════════"
echo "  Deploying Custom Wazuh Rules — Phase 3"
echo "═══════════════════════════════════════════════════════"

# 1. Copy decoder to Wazuh Manager container
echo "[1/4] Installing custom CloudTrail decoder..."
docker cp cloudtrail_decoders.xml ${MANAGER_CONTAINER}:/var/ossec/etc/decoders/cloudtrail_decoders.xml

# 2. Copy rules to Wazuh Manager container
echo "[2/4] Installing custom detection rules..."
docker cp cloudtrail_rules.xml ${MANAGER_CONTAINER}:/var/ossec/etc/rules/cloudtrail_rules.xml

# 3. Validate the configuration
echo "[3/4] Validating Wazuh configuration..."
docker exec ${MANAGER_CONTAINER} /var/ossec/bin/wazuh-analysisd -t
if [ $? -ne 0 ]; then
    echo "❌ Configuration validation FAILED! Check the rules/decoders syntax."
    exit 1
fi
echo "✅ Configuration is valid!"

# 4. Restart Wazuh Manager to apply changes
echo "[4/4] Restarting Wazuh Manager..."
docker exec ${MANAGER_CONTAINER} /var/ossec/bin/wazuh-control restart

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ Custom rules deployed successfully!"
echo ""
echo "  Rules installed:"
echo "    100110 — SSRF targeting AWS IMDS (CRITICAL)"
echo "    100111 — SSRF to external endpoint (WARNING)"
echo "    100120 — Login success"
echo "    100121 — Login failure"
echo "    100122 — Brute force (5+ failures)"
echo "    100130 — IAM AssumeRole (credential theft)"
echo "    100131 — IAM GetSessionToken"
echo "    100132 — IAM CreateAccessKey (persistence)"
echo "    100133 — IAM policy modification"
echo "    100140 — DynamoDB Scan (data exfil)"
echo "    100141 — DynamoDB GetItem"
echo "    100142 — High-freq DynamoDB access"
echo "    100150 — S3 GetObject"
echo "    100151 — S3 ListBuckets (recon)"
echo "    100160 — Funds transfer"
echo "    100170 — Full attack chain correlation"
echo "═══════════════════════════════════════════════════════"
