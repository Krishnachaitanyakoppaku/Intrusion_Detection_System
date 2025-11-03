# Quick Test Guide

## Quick Start Testing (3 Steps)

### 1. Run Component Test
```bash
# Linux/WSL
./test_components.sh

# Windows
test_components.bat
```

### 2. Test Packet Capture
```bash
# Start capturing (in one terminal)
python3 scapy_capture.py

# Generate some traffic (browse web, ping, etc.)
# Then check the log:
cat logs/all_packets.log
```

### 3. Test Complete Workflow

**Step A: Capture packets for 30 seconds**
```bash
# Terminal 1
python3 scapy_capture.py
# Wait 30 seconds, then press Ctrl+C
```

**Step B: Build and run analyzer**
```bash
# Build
make packet_analyzer

# Run analyzer
./bin/packet_analyzer
```

**Step C: Check results**
```bash
# See captured packets
cat logs/all_packets.log

# See generated alerts
cat logs/alerts.log
```

## What to Expect

### Successful Packet Capture
You should see entries like:
```
2025-11-03 10:00:00 | 192.168.1.100:80 -> 192.168.1.200:443 | TCP | Size: 150B
```

### Successful Analysis
The analyzer will:
1. Load rules from `rules/local.rules`
2. Parse packets from `logs/all_packets.log`
3. Match packets against rules
4. Generate alerts in `logs/alerts.log`

### Successful Alerts
You should see alerts like:
```
[2025-11-03 10:00:00] ALERT: Incoming HTTP Traffic | 192.168.1.100:80 -> 192.168.1.200:443 | Protocol: TCP | Priority: 5
```

## Troubleshooting

- **No packets captured?** Make sure you have network traffic. Try browsing the web while capturing.
- **Build fails?** Install dependencies: `sudo apt-get install build-essential bison flex`
- **Python errors?** Install scapy: `pip install scapy`

## Next Steps

Once testing works:
1. Integrate with your existing workflow
2. Customize rules in `rules/local.rules`
3. Extend functionality as needed

