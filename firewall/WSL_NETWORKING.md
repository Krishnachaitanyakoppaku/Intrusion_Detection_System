# WSL Networking Setup Guide

## Problem

When running the IDS in WSL (Windows Subsystem for Linux):
- WSL has its own virtual network with a private IP (e.g., 172.x.x.x)
- This IP changes between WSL sessions
- Other computers on your network can't reach WSL IP directly
- Logs show WSL IP addresses instead of Windows host IP

## Solution

The system now automatically detects WSL and maps IP addresses:

1. **Scapy Capture** - Maps WSL IPs to Windows IP in logs
2. **Host Setup** - Configures rsyslog to listen on all interfaces
3. **Windows Port Forwarding** - Required for external access

## Quick Setup

### Step 1: Run Host Setup (in WSL)

```bash
cd firewall
sudo bash host_setup_auto.sh
```

The script will:
- Detect WSL environment
- Get Windows host IP address
- Configure rsyslog to listen on 0.0.0.0:514

### Step 2: Configure Windows Port Forwarding

**Option A: Use PowerShell Script (Recommended)**

In Windows PowerShell (as Administrator):

```powershell
cd C:\Users\saina\OneDrive\Desktop\CD\Project\Intrusion_Detection_System\firewall
.\wsl_network_setup.ps1
```

**Option B: Manual Setup**

In Windows PowerShell (as Administrator):

```powershell
# Get WSL IP
wsl hostname -I

# Get Windows IP (from WiFi/Ethernet adapter)
ipconfig | findstr IPv4

# Forward port 514 from Windows to WSL
netsh interface portproxy add v4tov4 listenport=514 listenaddress=0.0.0.0 connectport=514 connectaddress=<WSL_IP>

# Allow firewall rule
netsh advfirewall firewall add rule name="WSL Syslog" dir=in action=allow protocol=TCP localport=514
netsh advfirewall firewall add rule name="WSL Syslog UDP" dir=in action=allow protocol=UDP localport=514
```

### Step 3: Verify

**Check port forwarding:**
```powershell
netsh interface portproxy show all
```

**Test from client:**
```bash
# On client machine
logger -n <WINDOWS_IP> -P 514 "Test message"
```

**Check WSL logs:**
```bash
# In WSL
tail -f firewall/logs/firewall.log
```

## How It Works

### IP Address Mapping

The system automatically maps IP addresses:

1. **Packet Capture (scapy_capture.py)**
   - Detects WSL environment
   - Gets Windows host IP from default gateway
   - Maps WSL IP → Windows IP in logs
   - Logs show Windows IP addresses

2. **Firewall Logs (rsyslog)**
   - Receives logs from clients
   - Shows source IPs as seen by Windows host
   - All logs stored in `firewall/logs/firewall.log`

### Network Flow

```
Client (192.168.x.x)
    |
    | sends to Windows IP:514
    |
Windows Host (e.g., 192.168.1.100)
    |
    | port forwarded to
    |
WSL (172.x.x.x:514)
    |
    | processes and maps IPs
    |
Logs (show Windows IP: 192.168.1.100)
```

## Troubleshooting

### WSL IP keeps changing

**Solution:** Configure WSL to use static IP (optional):

```bash
# In WSL, edit /etc/wsl.conf (create if doesn't exist)
cat > /etc/wsl.conf <<EOF
[network]
generateHosts = false
generateResolvConf = false
EOF

# Restart WSL: wsl --shutdown (in Windows PowerShell)
```

### Can't ping WSL from another computer

**This is normal!** WSL IP is not directly accessible. Use Windows IP instead.

### Port forwarding not working

1. Check Windows Firewall allows port 514
2. Verify portproxy rule exists: `netsh interface portproxy show all`
3. Ensure rsyslog is listening: `sudo netstat -tuln | grep 514`
4. Test locally: `logger -n localhost -P 514 "test"`

### Logs still show WSL IP

1. Restart the IDS engine after running host setup
2. Clear old logs: `> logs/all_packets.log`
3. Verify WSL detection: Check startup messages for "[WSL] Detected"

## Notes

- Windows IP is detected automatically from default gateway
- IP mapping happens automatically in packet logs
- Client configuration uses Windows IP (not WSL IP)
- Port forwarding persists until WSL restarts (then re-run setup script)

