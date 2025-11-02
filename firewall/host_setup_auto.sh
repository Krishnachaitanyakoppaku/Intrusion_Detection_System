#!/bin/bash
# host_setup_auto.sh
# Usage: sudo bash host_setup_auto.sh
#        OR: chmod +x host_setup_auto.sh && sudo ./host_setup_auto.sh
# Auto-detects internet interface and picks a client interface (non-loopback, non-inet-if).
# Debian/Ubuntu tested.
#
# NOTE: If you get "command not found", use: sudo bash host_setup_auto.sh
#       The script must be run from the firewall/ directory or with full path.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo bash host_setup_auto.sh"
  exit 1
fi

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIREWALL_DIR="$SCRIPT_DIR"
LOG_DIR="$FIREWALL_DIR/logs"
LOG_FILE="$LOG_DIR/firewall.log"

# Create firewall directory structure
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 660 "$LOG_FILE" || true

# Determine user who invoked sudo (for ownership if possible)
RUN_USER="${SUDO_USER:-root}"
if [ "$RUN_USER" != "root" ] && id "$RUN_USER" &>/dev/null; then
  chown "$RUN_USER":"$RUN_USER" "$LOG_FILE" 2>/dev/null || true
  chown -R "$RUN_USER":"$RUN_USER" "$LOG_DIR" 2>/dev/null || true
fi

echo "[+] Firewall setup starting..."
echo "[+] Logs will be stored in: $LOG_FILE"

# Detect if running in WSL
IS_WSL=false
WINDOWS_HOST_IP=""
if grep -qi microsoft /proc/version 2>/dev/null || grep -qi wsl /proc/version 2>/dev/null; then
  IS_WSL=true
  echo "[+] WSL environment detected"
  
  # Get Windows host IP (usually the default gateway in WSL)
  WINDOWS_HOST_IP=$(ip route show | grep -i 'default via' | awk '{print $3}' | head -n1 || true)
  
  if [ -n "$WINDOWS_HOST_IP" ]; then
    echo "  -> Detected Windows host IP: $WINDOWS_HOST_IP"
    echo "  -> Use this IP for client connections"
  else
    echo "  ! Could not detect Windows host IP automatically"
    echo "  -> You may need to configure port forwarding manually"
  fi
fi

echo "[+] Installing packages if missing..."
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y ufw rsyslog iptables-persistent net-tools

echo "[+] Auto-detecting internet interface (route to 8.8.8.8)..."
INET_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1 || true)
if [ -z "$INET_IF" ]; then
  echo "  ! Could not detect internet interface automatically. Falling back to 'wlan0'."
  INET_IF="wlan0"
else
  echo "  -> Detected internet interface: $INET_IF"
fi

echo "[+] Selecting a client-facing interface..."
# Check if hotspot/AP mode is active (common interface names for AP mode)
AP_INTERFACES=""
if command -v nmcli &> /dev/null; then
  # Check for NetworkManager hotspot/AP connections
  AP_INTERFACES=$(nmcli connection show --active | grep -iE 'hotspot|ap|wifi.*ap' | awk '{print $4}' | head -n1 || true)
fi

# Also check for common AP interface patterns
AP_PATTERNS="ap0|wlan.*ap|hotspot"

# List candidate interfaces
# Priority: 1) Explicit AP interface, 2) Separate physical interface, 3) Same interface in AP mode
CLIENT_IF=""

# Method 1: Check if NetworkManager found an AP interface
if [ -n "$AP_INTERFACES" ]; then
  CLIENT_IF="$AP_INTERFACES"
  echo "  -> Detected hotspot/AP interface via NetworkManager: $CLIENT_IF"
else
  # Method 2: Look for interfaces matching AP patterns
  AP_CANDIDATES=$(ip -o link show | awk -F': ' '{print $2}' \
    | grep -iE "$AP_PATTERNS" \
    | head -n1 || true)
  
  if [ -n "$AP_CANDIDATES" ]; then
    CLIENT_IF="$AP_CANDIDATES"
    echo "  -> Detected hotspot interface: $CLIENT_IF"
  else
    # Method 3: Look for separate physical interface (original logic)
    CLIENT_IF=$(ip -o link show | awk -F': ' '{print $2}' \
      | grep -v '^lo$' \
      | grep -vE '^(docker|veth|br-|virbr|tun|tap)' \
      | grep -v "^${INET_IF}$" \
      | head -n1 || true)
    
    if [ -n "$CLIENT_IF" ]; then
      echo "  -> Found separate interface: $CLIENT_IF"
    fi
  fi
fi

# Method 4: If still no separate interface, use same interface for both (hotspot scenario)
if [ -z "$CLIENT_IF" ]; then
  echo "  ! No separate client interface found."
  echo "  -> Detected WiFi hotspot scenario (same interface for internet and clients)."
  echo "  -> Using same interface ($INET_IF) for both internet and client network."
  echo "  -> WARNING: This setup routes client traffic through the same WiFi interface."
  CLIENT_IF="$INET_IF"
  USE_SAME_INTERFACE=true
else
  USE_SAME_INTERFACE=false
fi

echo "[+] Configuring rsyslog to listen on TCP/UDP 514..."
if [ "$IS_WSL" = "true" ]; then
  # In WSL, bind to all interfaces so Windows can forward to it
  cat >/etc/rsyslog.d/10-network.conf <<EOF
module(load="imudp")
input(type="imudp" port="514" address="0.0.0.0")

module(load="imtcp")
input(type="imtcp" port="514" address="0.0.0.0")
EOF
  echo "  -> Configured to listen on all interfaces (0.0.0.0) for WSL"
  echo "  -> Windows port forwarding required - see instructions below"
else
  # Normal Linux - listen on all interfaces
  cat >/etc/rsyslog.d/10-network.conf <<'EOF'
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")
EOF
fi

echo "[+] Routing incoming remote logs to: $LOG_FILE"
cat >/etc/rsyslog.d/50-remote-firewall.conf <<EOF
# All remote (non-local) logs appended to firewall log file
template(name="FirewallLogFmt" type="string" string="%HOSTNAME% %TIMESTAMP% %syslogtag%%msg%\n")
if (\$fromhost-ip != '127.0.0.1') then {
  action(type="omfile" file="$LOG_FILE" template="FirewallLogFmt")
  stop
}
EOF

echo "[+] Restarting rsyslog..."
systemctl restart rsyslog

echo "[+] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p >/dev/null 2>&1 || true

echo "[+] Backing up /etc/ufw/before.rules (if not already)..."
if [ ! -f /etc/ufw/before.rules.orig ]; then
  cp /etc/ufw/before.rules /etc/ufw/before.rules.orig || true
fi

echo "[+] Adding NAT MASQUERADE for internet interface ($INET_IF) to /etc/ufw/before.rules (if missing)..."
if ! grep -q "POSTROUTING -o $INET_IF -j MASQUERADE" /etc/ufw/before.rules; then
  awk -v iface="$INET_IF" '
  BEGIN { inserted = 0 }
  /^\*filter/ {
    if (!inserted) {
      print "*nat"
      print ":POSTROUTING ACCEPT [0:0]"
      print "-A POSTROUTING -o " iface " -j MASQUERADE"
      print "COMMIT\n"
      inserted = 1
    }
  }
  { print }
  ' /etc/ufw/before.rules > /etc/ufw/before.rules.new
  mv /etc/ufw/before.rules.new /etc/ufw/before.rules
  echo "  -> NAT block inserted."
else
  echo "  -> NAT MASQUERADE already present."
fi

echo "[+] Ensuring UFW default forward policy is ACCEPT..."
if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
  sed -i 's|^DEFAULT_FORWARD_POLICY=.*|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
else
  echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
fi

# ensure ip_forward in ufw sysctl config
if ! grep -q '^net/ipv4/ip_forward' /etc/ufw/sysctl.conf; then
  echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
fi

echo "[+] Configuring UFW rules (default deny incoming, allow outgoing) and enable..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 514/tcp
ufw allow 514/udp
ufw --force enable
ufw logging on

echo "[+] Adding runtime iptables MASQUERADE (so active immediately)..."
iptables -t nat -C POSTROUTING -o "$INET_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -o "$INET_IF" -j MASQUERADE

echo "[+] Saving iptables rules persistently..."
netfilter-persistent save >/dev/null 2>&1 || true

# Give clients a subnet and static IP on client interface (only if link up)
if [ "$USE_SAME_INTERFACE" = "true" ]; then
  echo "[+] WiFi hotspot mode detected - clients connect via same interface ($CLIENT_IF)"
  echo "  -> The hotspot provides its own IP range (usually 192.168.x.x)"
  echo "  -> No need to assign 192.168.50.1/24 manually"
  echo "  -> Clients will route through this host automatically via hotspot gateway"
else
  echo "[+] Assigning 192.168.50.1/24 to client-facing interface ($CLIENT_IF) if it has no IPv4..."
  if ! ip -4 addr show dev "$CLIENT_IF" | grep -q "192.168.50.1"; then
    ip addr add 192.168.50.1/24 dev "$CLIENT_IF" || true
  fi
fi

# Save configuration info to firewall directory
CONFIG_FILE="$FIREWALL_DIR/firewall_config.txt"
cat > "$CONFIG_FILE" <<EOF
Firewall Configuration
======================
Setup Date: $(date)
Internet Interface: $INET_IF
Client Interface: $CLIENT_IF
Client Network: 192.168.50.1/24
Log File: $LOG_FILE
EOF

chmod 644 "$CONFIG_FILE" || true
if [ "$RUN_USER" != "root" ] && id "$RUN_USER" &>/dev/null; then
  chown "$RUN_USER":"$RUN_USER" "$CONFIG_FILE" 2>/dev/null || true
fi

# Determine hotspot gateway IP if using same interface
HOTSPOT_GATEWAY=""
if [ "$USE_SAME_INTERFACE" = "true" ]; then
  # Try to detect hotspot gateway IP (usually the host's IP on the hotspot network)
  HOTSPOT_GATEWAY=$(ip -4 addr show dev "$CLIENT_IF" | grep -oP 'inet \K[\d.]+' | head -n1 || true)
  if [ -z "$HOTSPOT_GATEWAY" ]; then
    HOTSPOT_GATEWAY="<hotspot-gateway-ip>"
  fi
fi

echo ""
echo "=== Host setup complete ==="
echo "Internet interface: $INET_IF"
if [ "$USE_SAME_INTERFACE" = "true" ]; then
  echo "Client interface:   $CLIENT_IF (WiFi Hotspot - same interface)"
  echo "Hotspot gateway:    $HOTSPOT_GATEWAY (clients use this as default gateway)"
else
  echo "Client interface:   $CLIENT_IF (assigned 192.168.50.1/24)"
fi
echo "Logs stored in:     $LOG_FILE"
echo "Configuration:      $CONFIG_FILE"
echo ""
echo "Next steps for clients:"
if [ "$USE_SAME_INTERFACE" = "true" ]; then
  echo " - Clients should already be connected to your WiFi hotspot."
  echo " - Find this host's IP address (gateway IP shown in hotspot settings)."
  echo " - On each client, run: sudo bash firewall/client_setup_auto.sh"
  echo " - When prompted, enter this host's IP: $HOTSPOT_GATEWAY"
  echo " - Or find IP manually: ip addr show dev $CLIENT_IF"
else
  echo " - Connect clients to the host's client network (via ethernet or host AP)."
  echo " - On clients set default gateway to 192.168.50.1 (or use DHCP if you set it)."
  echo " - On each client, run: sudo bash firewall/client_setup_auto.sh"
  echo " - When prompted, enter this host's IP: 192.168.50.1"
fi
echo ""
echo "To test firewall event detection:"
echo "  1. Generate test logs: python firewall/test_parser.py"
echo "  2. Build parser (if not built): cd firewall && make"
echo "  3. Check web interface: http://localhost:8080"

