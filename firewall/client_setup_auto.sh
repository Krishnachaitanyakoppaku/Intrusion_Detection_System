#!/bin/bash
# client_setup_auto.sh
# Usage: sudo bash client_setup_auto.sh
#        OR: chmod +x client_setup_auto.sh && sudo ./client_setup_auto.sh
# Configures client to forward syslog to firewall host.
# Debian/Ubuntu tested.
#
# NOTE: If you get "command not found", use: sudo bash client_setup_auto.sh
#       The script must be run from the firewall/ directory or with full path.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo bash client_setup_auto.sh"
  exit 1
fi

echo ""
echo "=========================================="
echo "  Client Syslog Forwarding Setup"
echo "=========================================="
echo ""

# Prompt for host IP address
echo "Enter the firewall host IP address (the machine running host_setup_auto.sh):"
echo "Example: 192.168.50.1 or 172.20.164.192"
read -p "Host IP: " HOST_IP

# Validate IP address format (basic validation)
if [[ ! $HOST_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "Error: Invalid IP address format: $HOST_IP"
  exit 1
fi

echo ""
echo "[+] Firewall host IP: $HOST_IP"
echo "[+] Configuring client to forward syslog to $HOST_IP:514"
echo ""

# Install rsyslog if not present
echo "[+] Installing rsyslog if missing..."
apt update -y >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt install -y rsyslog >/dev/null 2>&1 || true

# Backup original rsyslog config
if [ ! -f /etc/rsyslog.conf.orig ]; then
  echo "[+] Backing up /etc/rsyslog.conf..."
  cp /etc/rsyslog.conf /etc/rsyslog.conf.orig
fi

# Configure rsyslog to forward all logs to host
echo "[+] Configuring rsyslog to forward logs to $HOST_IP:514..."
cat > /etc/rsyslog.d/10-forward-to-host.conf <<EOF
# Forward all syslog messages to firewall host
*.* @@${HOST_IP}:514
EOF

# Also configure UDP forwarding (fallback)
echo "[+] Adding UDP forwarding (fallback)..."
cat >> /etc/rsyslog.d/10-forward-to-host.conf <<EOF

# UDP forwarding (fallback if TCP fails)
*.* @${HOST_IP}:514
EOF

# Ensure rsyslog is enabled and restart
echo "[+] Restarting rsyslog service..."
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog

# Test connectivity to host
echo "[+] Testing connectivity to $HOST_IP:514..."
if timeout 3 bash -c "echo > /dev/tcp/$HOST_IP/514" 2>/dev/null; then
  echo "  ✅ TCP port 514 is reachable"
else
  echo "  ⚠️  Warning: Cannot reach $HOST_IP:514 (TCP)"
  echo "     Make sure the firewall host is running and port 514 is open"
fi

# Test with UDP (nc/netcat if available)
if command -v nc >/dev/null 2>&1; then
  if timeout 2 nc -u -z "$HOST_IP" 514 2>/dev/null; then
    echo "  ✅ UDP port 514 is reachable"
  else
    echo "  ⚠️  Warning: Cannot reach $HOST_IP:514 (UDP)"
  fi
fi

# Send a test log message
echo "[+] Sending test log message to host..."
logger -t CLIENT_SETUP "Client syslog forwarding configured - $(hostname) -> $HOST_IP:514"
echo "  ✅ Test message sent"

# Display configuration summary
echo ""
echo "=========================================="
echo "  Client Setup Complete"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Host IP:         $HOST_IP"
echo "  Port:            514 (TCP and UDP)"
echo "  Log forwarding:  All syslog messages"
echo ""
echo "Forwarding rules saved to:"
echo "  /etc/rsyslog.d/10-forward-to-host.conf"
echo ""
echo "To verify logs are being forwarded:"
echo "  1. Check firewall host logs: tail -f firewall/logs/firewall.log"
echo "  2. Send test message: logger 'Test message from client'"
echo ""
echo "To disable forwarding, remove or rename:"
echo "  sudo mv /etc/rsyslog.d/10-forward-to-host.conf /etc/rsyslog.d/10-forward-to-host.conf.disabled"
echo "  sudo systemctl restart rsyslog"
echo ""


