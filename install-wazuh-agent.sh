#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  Wazuh Agent Installation — Cloud Target VM (192.168.100.20)
#  Connects to Wazuh Manager on SOC VM (192.168.100.10)
# ══════════════════════════════════════════════════════════════

set -e

WAZUH_MANAGER="192.168.100.10"
WAZUH_VERSION="4.8.0"

echo "═══════════════════════════════════════════════════════"
echo "  Installing Wazuh Agent ${WAZUH_VERSION}"
echo "  Manager: ${WAZUH_MANAGER}"
echo "═══════════════════════════════════════════════════════"

# 1. Import Wazuh GPG key
echo "[1/5] Importing Wazuh GPG key..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg

# 2. Add Wazuh repository
echo "[2/5] Adding Wazuh repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# 3. Install Wazuh agent
echo "[3/5] Installing Wazuh agent..."
sudo apt-get update
sudo WAZUH_MANAGER="${WAZUH_MANAGER}" apt-get install -y wazuh-agent

# 4. Create the CloudTrail log directory
echo "[4/5] Creating CloudTrail log directory..."
sudo mkdir -p /var/log/cloudtrail
sudo touch /var/log/cloudtrail/cloudtrail.log
sudo chmod 755 /var/log/cloudtrail
sudo chmod 644 /var/log/cloudtrail/cloudtrail.log

# 5. Configure Wazuh agent to monitor CloudTrail logs
echo "[5/5] Configuring Wazuh agent..."

# Add CloudTrail log monitoring to ossec.conf
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null << 'OSSEC_EOF'

<!-- ═════════════════════════════════════════════════════ -->
<!--  CloudTrail Log Monitoring — Phase 2 Configuration  -->
<!-- ═════════════════════════════════════════════════════ -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/cloudtrail/cloudtrail.log</location>
    <label key="log_type">cloudtrail</label>
  </localfile>
</ossec_config>
OSSEC_EOF

# 6. Start and enable the agent
echo "Starting Wazuh agent..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ Wazuh Agent installed and running!"
echo "  Agent → Manager: ${WAZUH_MANAGER}:1514"
echo "  Monitoring: /var/log/cloudtrail/cloudtrail.log"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Verify with: sudo systemctl status wazuh-agent"
echo "Check logs:  sudo tail -f /var/ossec/logs/ossec.log"
