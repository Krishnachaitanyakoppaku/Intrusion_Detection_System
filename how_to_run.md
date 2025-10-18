# IDS DSL Engine - How to Run Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Configuration](#advanced-configuration)
5. [Monitoring Network Traffic](#monitoring-network-traffic)
6. [Rule Management](#rule-management)
7. [Log Analysis](#log-analysis)
8. [Remote Monitoring](#remote-monitoring)
9. [Troubleshooting](#troubleshooting)
10. [Examples and Use Cases](#examples-and-use-cases)

## Prerequisites

### System Requirements
- Linux-based operating system (Ubuntu, CentOS, Debian, etc.)
- Root privileges (for packet capture)
- Network interface with traffic
- At least 1GB RAM and 100MB disk space

### Required Software
- GCC compiler
- Bison (parser generator)
- Flex (lexical analyzer)
- libpcap (packet capture library)

## Installation

### Step 1: Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential bison flex libpcap-dev
```

#### CentOS/RHEL/Fedora:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install bison flex libpcap-devel
```

#### macOS (with Homebrew):
```bash
brew install bison flex libpcap
```

### Step 2: Build the Project
```bash
cd /path/to/ids-dsl-project
make clean
make
```

### Step 3: Verify Installation
```bash
# Check if binary was created
ls -la bin/ids_engine

# Test help message
./bin/ids_engine --help
```

## Basic Usage

### Step 1: Check Available Network Interfaces
```bash
# List all network interfaces
ip link show

# Or use ifconfig
ifconfig -a
```

### Step 2: Run with Default Settings
```bash
# Run with default rules and interface
sudo ./bin/ids_engine
```

### Step 3: Run with Custom Configuration
```bash
# Specify custom rules file and interface
sudo ./bin/ids_engine -r rules/local.rules -i eth0

# Disable promiscuous mode
sudo ./bin/ids_engine --no-promiscuous

# Custom timeout and log file
sudo ./bin/ids_engine -t 500 -l logs/custom_alerts.log
```

### Step 4: Stop the Engine
```bash
# Press Ctrl+C to stop gracefully
# The engine will clean up and exit
```

## Advanced Configuration

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-r, --rules FILE` | Rules file to load | `-r myrules.rules` |
| `-i, --interface IFACE` | Network interface | `-i wlan0` |
| `-l, --log FILE` | Log file for alerts | `-l /var/log/ids.log` |
| `-p, --no-promiscuous` | Disable promiscuous mode | `--no-promiscuous` |
| `-t, --timeout MS` | Timeout in milliseconds | `-t 1000` |
| `-h, --help` | Show help message | `--help` |
| `-v, --version` | Show version info | `--version` |

### Example Configurations

#### Monitor Wireless Interface
```bash
sudo ./bin/ids_engine -i wlan0 -r rules/wireless.rules
```

#### Monitor Loopback Interface (for testing)
```bash
sudo ./bin/ids_engine -i lo -r rules/test.rules
```

#### High-Performance Monitoring
```bash
sudo ./bin/ids_engine -i eth0 -t 100 -l /var/log/ids_alerts.log
```

## Monitoring Network Traffic

### Step 1: Generate Test Traffic
```bash
# Generate ICMP traffic
ping -c 10 8.8.8.8

# Generate HTTP traffic
curl -s http://httpbin.org/get

# Generate SSH traffic
ssh -o ConnectTimeout=1 localhost
```

### Step 2: Monitor Specific Traffic Types
```bash
# Monitor HTTP traffic on port 80
sudo ./bin/ids_engine -i eth0 -r rules/http.rules

# Monitor SSH traffic on port 22
sudo ./bin/ids_engine -i eth0 -r rules/ssh.rules
```

### Step 3: Real-time Monitoring
```bash
# Monitor all traffic with real-time alerts
sudo ./bin/ids_engine -i eth0 -r rules/local.rules

# In another terminal, watch the log file
tail -f logs/alerts.log
```

## Rule Management

### Understanding Rule Syntax
```
action protocol source_ip source_port direction dest_ip dest_port (options)
```

### Rule Components

#### Actions
- `alert`: Generate an alert when rule matches
- `log`: Log the event without alert
- `pass`: Ignore the traffic

#### Protocols
- `tcp`: Transmission Control Protocol
- `udp`: User Datagram Protocol
- `icmp`: Internet Control Message Protocol
- `ip`: Any IP protocol

#### IP Addresses
- `any`: Match any IP address
- `192.168.1.1`: Specific IP address
- `192.168.1.0/24`: Network range

#### Ports
- `any`: Match any port
- `80`: HTTP port
- `22`: SSH port
- `443`: HTTPS port

#### Directions
- `->`: Unidirectional (source to destination)
- `<>`: Bidirectional (both directions)

#### Options
- `msg`: Alert message
- `content`: Content to match in packet
- `priority`: Alert priority (1-5)
- `sid`: Rule ID
- `rev`: Rule revision
- `classtype`: Classification type
- `reference`: External reference

### Creating Custom Rules

#### Step 1: Create a New Rules File
```bash
# Create custom rules file
nano rules/custom.rules
```

#### Step 2: Add Rules
```bash
# Example: Detect SQL injection
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1"; priority:1)

# Example: Detect XSS attacks
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)

# Example: Detect port scans
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)
```

#### Step 3: Test the Rules
```bash
# Test with custom rules
sudo ./bin/ids_engine -r rules/custom.rules -i eth0
```

### Rule Categories

#### Network Security Rules
```bash
# Detect port scans
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)

# Detect ICMP floods
alert icmp any any -> any any (msg:"ICMP Flood"; priority:4)

# Detect suspicious connections
alert tcp any any -> any 22 (msg:"SSH Connection"; priority:5)
```

#### Web Application Security Rules
```bash
# SQL injection detection
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"UNION SELECT"; priority:1)

# XSS detection
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"javascript:"; priority:2)

# Directory traversal
alert tcp any any -> any 80 (msg:"Directory Traversal"; content:"../"; priority:2)
```

#### System Security Rules
```bash
# Detect brute force attacks
alert tcp any any -> any 22 (msg:"SSH Brute Force"; priority:3)
alert tcp any any -> any 23 (msg:"Telnet Brute Force"; priority:3)

# Detect malicious file uploads
alert tcp any any -> any 80 (msg:"Malicious Upload"; content:".exe"; priority:2)
alert tcp any any -> any 80 (msg:"Malicious Upload"; content:".php"; priority:2)
```

## Log Analysis

### Understanding Alert Format
```
[timestamp] ALERT: Rule message
  Source: IP:port -> Destination: IP:port
  Protocol: protocol_number, Severity: priority_level
  ---
```

### Log File Locations
- **Default**: `logs/alerts.log`
- **Custom**: Specify with `-l` option
- **System**: `/var/log/ids_alerts.log`

### Analyzing Logs

#### Step 1: View Recent Alerts
```bash
# View last 50 alerts
tail -n 50 logs/alerts.log

# View alerts in real-time
tail -f logs/alerts.log
```

#### Step 2: Filter Alerts by Type
```bash
# Filter SQL injection alerts
grep "SQL Injection" logs/alerts.log

# Filter high-priority alerts
grep "priority:1" logs/alerts.log

# Filter alerts from specific IP
grep "192.168.1.100" logs/alerts.log
```

#### Step 3: Generate Reports
```bash
# Count alerts by type
grep -c "SQL Injection" logs/alerts.log
grep -c "XSS Attack" logs/alerts.log
grep -c "Port Scan" logs/alerts.log

# Generate summary report
echo "=== IDS Alert Summary ==="
echo "Total alerts: $(wc -l < logs/alerts.log)"
echo "SQL Injection: $(grep -c "SQL Injection" logs/alerts.log)"
echo "XSS Attacks: $(grep -c "XSS Attack" logs/alerts.log)"
echo "Port Scans: $(grep -c "Port Scan" logs/alerts.log)"
```

### Log Rotation
```bash
# Set up log rotation
sudo nano /etc/logrotate.d/ids-engine

# Add the following content:
/var/log/ids_alerts.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

## Remote Monitoring

### Monitoring Other Computers

#### Step 1: Set Up Centralized Logging
```bash
# On the IDS server, create a shared log directory
sudo mkdir -p /var/log/ids/remote
sudo chmod 755 /var/log/ids/remote
```

#### Step 2: Configure Remote Monitoring
```bash
# Run IDS on the monitoring server
sudo ./bin/ids_engine -i eth0 -l /var/log/ids/remote/alerts.log
```

#### Step 3: Monitor Multiple Interfaces
```bash
# Monitor multiple network interfaces
sudo ./bin/ids_engine -i eth0 -l /var/log/ids/eth0_alerts.log &
sudo ./bin/ids_engine -i wlan0 -l /var/log/ids/wlan0_alerts.log &
sudo ./bin/ids_engine -i lo -l /var/log/ids/loopback_alerts.log &
```

### Network-Wide Monitoring

#### Step 1: Deploy IDS on Multiple Machines
```bash
# Copy the IDS engine to multiple machines
scp bin/ids_engine user@remote-server:/usr/local/bin/
scp rules/local.rules user@remote-server:/etc/ids/rules/
```

#### Step 2: Centralized Log Collection
```bash
# Set up centralized logging
sudo ./bin/ids_engine -i eth0 -l /var/log/ids/centralized_alerts.log

# Collect logs from remote machines
rsync -av user@remote-server:/var/log/ids/ /var/log/ids/remote/
```

#### Step 3: Distributed Monitoring
```bash
# Run IDS on each network segment
# Segment 1: 192.168.1.0/24
sudo ./bin/ids_engine -i eth0 -l /var/log/ids/segment1.log

# Segment 2: 192.168.2.0/24
sudo ./bin/ids_engine -i eth1 -l /var/log/ids/segment2.log

# Segment 3: 192.168.3.0/24
sudo ./bin/ids_engine -i eth2 -l /var/log/ids/segment3.log
```

### Real-time Monitoring Dashboard

#### Step 1: Create Monitoring Script
```bash
#!/bin/bash
# monitor_ids.sh

echo "=== IDS Monitoring Dashboard ==="
echo "Timestamp: $(date)"
echo ""

# Check if IDS is running
if pgrep -f "ids_engine" > /dev/null; then
    echo "✅ IDS Engine: Running"
else
    echo "❌ IDS Engine: Not running"
fi

# Show recent alerts
echo ""
echo "=== Recent Alerts ==="
tail -n 10 /var/log/ids_alerts.log

# Show alert statistics
echo ""
echo "=== Alert Statistics ==="
echo "Total alerts today: $(grep $(date +%Y-%m-%d) /var/log/ids_alerts.log | wc -l)"
echo "High priority alerts: $(grep "priority:1" /var/log/ids_alerts.log | wc -l)"
echo "Medium priority alerts: $(grep "priority:2" /var/log/ids_alerts.log | wc -l)"
echo "Low priority alerts: $(grep "priority:3" /var/log/ids_alerts.log | wc -l)"
```

#### Step 2: Set Up Automated Monitoring
```bash
# Add to crontab for regular monitoring
crontab -e

# Add the following line to run every 5 minutes
*/5 * * * * /path/to/monitor_ids.sh >> /var/log/ids_monitoring.log
```

## Troubleshooting

### Common Issues

#### Issue 1: Permission Denied
```bash
# Problem: Cannot capture packets
# Solution: Run with sudo
sudo ./bin/ids_engine -i eth0
```

#### Issue 2: Interface Not Found
```bash
# Problem: Interface doesn't exist
# Solution: Check available interfaces
ip link show
ifconfig -a

# Use correct interface name
sudo ./bin/ids_engine -i wlan0
```

#### Issue 3: No Rules Loaded
```bash
# Problem: No rules found
# Solution: Check rules file syntax
cat rules/local.rules

# Test with simple rule
echo "alert ip any any -> any any (msg:\"Test Rule\"; priority:5)" > test.rules
sudo ./bin/ids_engine -r test.rules -i lo
```

#### Issue 4: No Alerts Generated
```bash
# Problem: No alerts despite traffic
# Solution: Check if traffic is being captured
sudo tcpdump -i eth0 -c 10

# Test with loopback interface
sudo ./bin/ids_engine -i lo -r rules/local.rules
ping -c 5 127.0.0.1
```

### Debug Mode

#### Step 1: Enable Debug Output
```bash
# Build with debug flags
make debug

# Run with verbose output
sudo ./bin/ids_engine -i eth0 -r rules/local.rules
```

#### Step 2: Check System Logs
```bash
# Check system logs for errors
sudo journalctl -u ids-engine
sudo dmesg | grep -i error
```

#### Step 3: Test Individual Components
```bash
# Test parser only
make test

# Test with sample data
sudo ./bin/ids_engine -i lo -r rules/local.rules
```

## Examples and Use Cases

### Use Case 1: Web Server Protection
```bash
# Monitor web server traffic
sudo ./bin/ids_engine -i eth0 -r rules/web_security.rules

# Rules for web security
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)
alert tcp any any -> any 80 (msg:"Directory Traversal"; content:"../"; priority:2)
```

### Use Case 2: Network Perimeter Monitoring
```bash
# Monitor network perimeter
sudo ./bin/ids_engine -i eth0 -r rules/perimeter.rules

# Rules for perimeter security
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)
alert icmp any any -> any any (msg:"ICMP Flood"; priority:4)
alert tcp any any -> any 22 (msg:"SSH Brute Force"; priority:3)
```

### Use Case 3: Internal Network Monitoring
```bash
# Monitor internal network
sudo ./bin/ids_engine -i eth1 -r rules/internal.rules

# Rules for internal security
alert tcp any any -> any 80 (msg:"Internal HTTP"; priority:5)
alert tcp any any -> any 443 (msg:"Internal HTTPS"; priority:5)
alert tcp any any -> any 22 (msg:"Internal SSH"; priority:5)
```

### Use Case 4: Development Environment
```bash
# Monitor development environment
sudo ./bin/ids_engine -i lo -r rules/dev.rules

# Rules for development security
alert tcp any any -> any 3000 (msg:"Node.js App"; priority:5)
alert tcp any any -> any 8080 (msg:"Java App"; priority:5)
alert tcp any any -> any 5000 (msg:"Python App"; priority:5)
```

### Use Case 5: Home Network Security
```bash
# Monitor home network
sudo ./bin/ids_engine -i wlan0 -r rules/home.rules

# Rules for home security
alert tcp any any -> any 80 (msg:"Web Traffic"; priority:5)
alert tcp any any -> any 443 (msg:"Secure Web Traffic"; priority:5)
alert tcp any any -> any 22 (msg:"SSH Traffic"; priority:5)
```

## Best Practices

### Rule Management
1. **Organize rules by category** (web, network, system)
2. **Use descriptive rule names** and messages
3. **Set appropriate priority levels** (1=critical, 5=info)
4. **Test rules before deployment**
5. **Regular rule updates** and maintenance

### Log Management
1. **Implement log rotation** to prevent disk space issues
2. **Monitor log file sizes** regularly
3. **Archive old logs** for historical analysis
4. **Set up log analysis** and reporting
5. **Backup important logs** regularly

### Performance Optimization
1. **Use specific rules** instead of broad patterns
2. **Optimize rule order** (most common rules first)
3. **Monitor system resources** (CPU, memory, disk)
4. **Use appropriate timeouts** for packet capture
5. **Consider rule compilation** for better performance

### Security Considerations
1. **Run with minimal privileges** when possible
2. **Secure log files** with proper permissions
3. **Encrypt sensitive logs** if necessary
4. **Monitor for rule tampering**
5. **Regular security updates** and patches

## Conclusion

The IDS DSL Engine provides a powerful and flexible platform for network intrusion detection. By following this guide, you can:

- **Deploy the system** on single or multiple machines
- **Create custom rules** for specific security needs
- **Monitor network traffic** in real-time
- **Analyze security logs** and generate reports
- **Scale the system** for enterprise environments

The system is designed to be educational, research-friendly, and production-ready, making it suitable for various use cases from home networks to enterprise environments.
