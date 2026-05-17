#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  Reset Between Attack Runs — Run on Cloud Target VM
#  Clears old logs so the next attack run has clean data
# ══════════════════════════════════════════════════════════════

echo "🔄 Resetting for next attack run..."

# 1. Clear the CloudTrail log file (keeps Wazuh agent monitoring it)
echo "[1/3] Clearing CloudTrail logs..."
sudo truncate -s 0 /var/log/cloudtrail/cloudtrail.log

# 2. Clear forwarder's internal tracking (restart it)
echo "[2/3] Restarting forwarder..."
cd ~/cloud-target && docker compose restart cloudtrail-forwarder

# 3. Clear API container logs (so forwarder doesn't re-read old events)
echo "[3/3] Clearing API container logs..."
sudo truncate -s 0 $(docker inspect --format='{{.LogPath}}' securebank_api)

echo ""
echo "✅ Ready for next attack run!"
echo "   → Go to Kali and run: ./attack_chain.sh"
echo "   → Or run benchmark:   ./detection_delay.sh"
