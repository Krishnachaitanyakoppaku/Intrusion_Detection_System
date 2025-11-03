# Testing the IDS Components

This document explains how to test each component of the IDS system.

## Prerequisites

1. **Python Dependencies:**
   ```bash
   pip install scapy
   ```

2. **Build Tools (for C components):**
   ```bash
   # On Linux/WSL
   sudo apt-get install build-essential bison flex libpcap-dev
   
   # On Windows, use WSL or MinGW
   ```

## Step-by-Step Testing

### Step 1: Run Component Tests

**On Linux/WSL:**
```bash
chmod +x test_components.sh
./test_components.sh
```

**On Windows:**
```cmd
test_components.bat
```

This will verify:
- All required files exist
- Python dependencies are installed
- Scripts have valid syntax
- Build tools are available
- Log files are properly set up

### Step 2: Test Scapy Packet Capture

**Terminal 1 - Start packet capture:**
```bash
# On Linux/WSL (requires sudo for raw sockets)
sudo python3 scapy_capture.py eth0

# Or on Windows/WSL
python scapy_capture.py

# To capture on all interfaces (default)
python3 scapy_capture.py
```

**Terminal 2 - Generate test traffic:**
```bash
# Ping (ICMP)
ping google.com

# HTTP request (TCP port 80)
curl http://example.com

# Or use any web browser to visit websites
```

**Check the output:**
```bash
# View captured packets
cat logs/all_packets.log
tail -f logs/all_packets.log  # Live view
```

Expected format:
```
2025-11-03 10:00:00 | 192.168.1.100:80 -> 192.168.1.200:443 | TCP | Size: 150B
```

### Step 3: Build Packet Analyzer

```bash
# Build the packet analyzer
make packet_analyzer

# Or build everything
make clean
make
```

Expected output:
- `bin/packet_analyzer` executable should be created
- No compilation errors

### Step 4: Test Packet Log Parser

The parser uses compiler design techniques (Lex/Yacc) to parse packet logs.

**Test with sample data:**
```bash
# Create a test packet log
cat > logs/test_packets.log << EOF
2025-11-03 10:00:00 | 192.168.1.100:80 -> 192.168.1.200:443 | TCP | Size: 150B
2025-11-03 10:00:01 | 192.168.1.101:53 -> 192.168.1.200:53 | UDP | Size: 75B
2025-11-03 10:00:02 | Unknown packet | Size: 42B
EOF

# The parser will be tested when running the analyzer
```

### Step 5: Test Rule Matching

**Run the packet analyzer:**
```bash
# Analyze packets from all_packets.log
./bin/packet_analyzer logs/all_packets.log rules/local.rules

# Or use defaults (logs/all_packets.log and rules/local.rules)
./bin/packet_analyzer
```

**What it does:**
1. Loads rules from `rules/local.rules`
2. Reads packets from `logs/all_packets.log`
3. Parses each packet using the lexer/parser
4. Matches packets against rules
5. Writes alerts to `logs/alerts.log`

**Check alerts:**
```bash
# View generated alerts
cat logs/alerts.log
tail -f logs/alerts.log  # Live view
```

Expected format:
```
[2025-11-03 10:00:00] ALERT: Incoming HTTP Traffic | 192.168.1.100:80 -> 192.168.1.200:443 | Protocol: TCP | Priority: 5
```

### Step 6: Complete Workflow Test

**Terminal 1 - Capture packets:**
```bash
sudo python3 scapy_capture.py eth0
```

**Terminal 2 - Generate suspicious traffic:**
```bash
# This should trigger an alert based on rules/local.rules
curl "http://localhost/?param=../../etc/passwd"
```

**Terminal 3 - Analyze packets:**
```bash
# Run analyzer (in another terminal or after stopping capture)
./bin/packet_analyzer
```

**Check results:**
```bash
# View all captured packets
cat logs/all_packets.log

# View generated alerts
cat logs/alerts.log
```

## Testing Individual Components

### Test Scapy Capture Only
```bash
python3 scapy_capture.py eth0 &
# Generate traffic
# Check logs/all_packets.log
```

### Test Parser Only
The parser is tested automatically when you run the analyzer, but you can test manually by calling `parse_log_line()` from a test program.

### Test Rule Matcher Only
Create a test program that:
1. Creates a sample rule
2. Creates a sample parsed packet
3. Calls `packet_matches_rule()`
4. Verifies the result

## Troubleshooting

### Issue: "Permission denied" for packet capture
**Solution:** Run with sudo (Linux) or as Administrator (Windows)

### Issue: "Scapy not found"
**Solution:** 
```bash
pip install scapy
# Or
pip3 install scapy
```

### Issue: "bison/flex not found"
**Solution:**
```bash
sudo apt-get install bison flex
```

### Issue: "No packets captured"
**Solution:**
- Check network interface name: `ipconfig` (Windows) or `ifconfig` (Linux)
- Try different interface: `python3 scapy_capture.py wlan0`
- Check firewall settings

### Issue: "No alerts generated"
**Solution:**
- Verify packets are in `logs/all_packets.log`
- Check that rules match your traffic patterns
- Verify rule syntax in `rules/local.rules`

## Expected Results

After complete testing, you should have:

1. ✅ `logs/all_packets.log` - Contains captured network packets
2. ✅ `logs/alerts.log` - Contains security alerts when rules match
3. ✅ `bin/packet_analyzer` - Executable that processes packets
4. ✅ All components building without errors

## Next Steps

Once testing is complete, you can:
1. Integrate these components into your existing workflow
2. Modify rules in `rules/local.rules` for your needs
3. Extend the parser for additional packet fields
4. Add more sophisticated rule matching logic

