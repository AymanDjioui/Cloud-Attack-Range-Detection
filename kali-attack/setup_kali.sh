#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  Kali VM Setup — Attacker Workstation (192.168.100.30)
#  Installs tools needed for the Cloud Attack Range
# ══════════════════════════════════════════════════════════════

set -e

echo "═══════════════════════════════════════════════════════"
echo "  ⚔️  Kali Attacker VM Setup"
echo "═══════════════════════════════════════════════════════"

# 1. Update system
echo "[1/3] Updating system..."
sudo apt-get update -y

# 2. Install required tools
echo "[2/3] Installing attack tools..."
sudo apt-get install -y \
    curl \
    jq \
    python3-pip \
    awscli

# 3. Configure AWS CLI for LocalStack
echo "[3/3] Configuring AWS CLI..."
mkdir -p ~/.aws

# Default profile (for initial recon)
cat > ~/.aws/credentials << 'EOF'
[default]
aws_access_key_id = test
aws_secret_access_key = test

[stolen]
# These will be filled in during the attack after stealing from IMDS
aws_access_key_id = PLACEHOLDER
aws_secret_access_key = PLACEHOLDER
aws_session_token = PLACEHOLDER
EOF

cat > ~/.aws/config << 'EOF'
[default]
region = us-east-1
output = json

[profile stolen]
region = us-east-1
output = json
EOF

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ Kali VM Ready!"
echo ""
echo "  Tools installed: curl, jq, awscli"
echo "  AWS endpoint: http://192.168.100.20:4566"
echo "  Target API:   http://192.168.100.20:8080"
echo ""
echo "  Run the attack: ./attack_chain.sh"
echo "═══════════════════════════════════════════════════════"
