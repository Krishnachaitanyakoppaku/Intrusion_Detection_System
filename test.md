# 🛡️ Intrusion Detection System (IDS) - Complete Testing Guide

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [System Requirements](#system-requirements)
3. [Installation & Setup](#installation--setup)
4. [Starting the System](#starting-the-system)
5. [Web Interface Guide](#web-interface-guide)
6. [Testing Scenarios](#testing-scenarios)
7. [Network Testing](#network-testing)
8. [Alert Generation](#alert-generation)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Features](#advanced-features)

---

## 🎯 Project Overview

This Intrusion Detection System (IDS) is a comprehensive security monitoring solution that:

- **Detects 98+ types of security threats** including SQL injection, XSS, port scans, malware uploads
- **Monitors network traffic** in real-time across multiple protocols
- **Provides web-based interface** for rule management and alert monitoring
- **Supports AI-powered rule conversion** using Gemini AI
- **Includes firewall monitoring** for system-level security events
- **Offers real-time alerting** with detailed threat information

### Key Components:
- **Backend**: Python web server with REST API
- **Frontend**: Modern web interface with real-time updates
- **Engine**: Custom IDS engine for traffic analysis
- **Rules**: Comprehensive security rule set (98 rules)
- **Monitoring**: Firewall and system process monitoring

---

## 💻 System Requirements

### Minimum Requirements:
- **OS**: Windows 10/11 with WSL2 or Linux
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Ethernet or WiFi connection
- **Browser**: Chrome, Firefox, Edge (latest versions)

### Required Software:
- **WSL2** (Windows Subsystem for Linux)
- **Python 3.8+**
- **Git** (for cloning the repository)
- **Network interface** with packet capture capabilities

---

## 🚀 Installation & Setup

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd Intrusion_Detection_System
```

### Step 2: Run the Installation Script
```bash
# Make the script executable
chmod +x install_complete.sh

# Run the installation (requires sudo password)
./install_complete.sh
```

**Note**: The installation script will:
- Install system dependencies (build tools, libraries)
- Install Python packages (requests, psutil, urllib3)
- Build the IDS engine
- Set up necessary directories
- Configure firewall monitoring

### Step 3: Verify Installation
```bash
# Check if all components are installed
ls -la bin/
ls -la rules/
ls -la web_interface/

# Test Python dependencies
python3 -c "import requests, psutil, urllib3; print('Dependencies OK')"
```

---

## 🎮 Starting the System

### Method 1: Start Web Server Only
```bash
python3 web_server_complete.py
```

### Method 2: Start with IDS Engine
1. **Start the web server**:
   ```bash
   python3 web_server_complete.py
   ```

2. **Open web browser** and go to: `http://localhost:8080`

3. **Start the IDS engine**:
   - Select your network interface (e.g., `eth0`, `wlan0`)
   - Click "🚀 Start IDS Engine"
   - Wait for "Engine Status: Running"

### Method 3: Background Process
```bash
# Start in background
nohup python3 web_server_complete.py > ids.log 2>&1 &

# Check if running
ps aux | grep web_server_complete.py
```

---

## 🌐 Web Interface Guide

### Main Dashboard
Access: `http://localhost:8080`

**Key Sections:**
1. **📊 System Status** - Engine status, alerts count
2. **🔧 Rule Management** - Add, edit, delete security rules
3. **📚 Built-in Security Rules Library** - 98 pre-configured rules
4. **🚨 Real-time Alerts** - Live threat detection
5. **🔥 Firewall Monitoring** - System-level security events

### Rule Management Features

#### View All Rules
- **🔄 Refresh Current Rules** - Load active rules
- **📚 Show Sample Rules** - Display all 98 built-in rules
- **🧪 Test API** - Test API connectivity
- **🔍 Show First 5 Rules** - Debug mode for testing

#### Rule Categories
- **Web Application Security** (Critical/High) - SQL injection, XSS, CSRF
- **Network Reconnaissance** (Medium) - Port scans, SYN/FIN scans
- **Denial of Service** (Low) - ICMP floods, ping attacks
- **Malware Detection** (High) - File uploads, executable detection
- **Authentication Attacks** (Medium) - SSH/Telnet brute force
- **Traffic Monitoring** (Info) - General network monitoring
- **Firewall Management** (High) - System admin commands

#### AI-Powered Rule Conversion
- **Input**: Natural language description
- **Output**: Snort-compatible rule syntax
- **Example**: "Detect SQL injection attempts" → `alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)`

---

## 🧪 Testing Scenarios

### 1. Basic Functionality Test

#### Test Web Interface
```bash
# Start the server
python3 web_server_complete.py

# Open browser to http://localhost:8080
# Verify all sections load correctly
```

#### Test Rule Loading
1. Click "📚 Show Sample Rules"
2. Verify 98 rules are displayed
3. Check rule categories and severity levels
4. Verify rule content is complete (not truncated)

#### Test API Endpoints
```bash
# Test rules API
curl http://localhost:8080/api/rules

# Test alerts API
curl http://localhost:8080/api/get_alerts

# Test firewall alerts
curl http://localhost:8080/api/get_firewall_alerts
```

### 2. Network Traffic Testing

#### Generate Test Traffic
```bash
# Generate HTTP traffic
curl http://localhost:8080/

# Generate multiple requests
for i in {1..10}; do curl http://localhost:8080/api/rules; done

# Generate traffic with suspicious patterns
curl "http://localhost:8080/?test=<script>alert('xss')</script>"
curl "http://localhost:8080/?id=1' OR 1=1--"
```

#### Monitor Alerts
1. Start IDS engine with network interface
2. Generate test traffic
3. Check "🚨 Real-time Alerts" section
4. Verify alerts appear within 5-10 seconds

### 3. Security Rule Testing

#### Test SQL Injection Detection
```bash
# These should trigger alerts
curl "http://localhost:8080/?user=admin' OR 1=1--"
curl "http://localhost:8080/?search=test' UNION SELECT * FROM users--"
curl "http://localhost:8080/?cmd=DROP TABLE users"
```

#### Test XSS Detection
```bash
# These should trigger alerts
curl "http://localhost:8080/?name=<script>alert('xss')</script>"
curl "http://localhost:8080/?url=javascript:alert('xss')"
curl "http://localhost:8080/?onload=alert('xss')"
```

#### Test Directory Traversal
```bash
# These should trigger alerts
curl "http://localhost:8080/../../../etc/passwd"
curl "http://localhost:8080/..\\..\\..\\windows\\system32\\config\\sam"
curl "http://localhost:8080/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

---

## 🌍 Network Testing

### Testing from Another Computer

#### Step 1: Find Your Server IP
```bash
# On the server machine
ip addr show
# Look for your network interface IP (e.g., 192.168.1.100)
```

#### Step 2: Configure Firewall (if needed)
```bash
# Allow port 8080 through firewall
sudo ufw allow 8080
# or
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

#### Step 3: Test from Remote Computer
```bash
# From another computer on the same network
curl http://192.168.1.100:8080/api/rules

# Open browser on remote computer
# Go to: http://192.168.1.100:8080
```

#### Step 4: Generate Remote Traffic
```bash
# From remote computer, generate test traffic
curl "http://192.168.1.100:8080/?test=<script>alert('remote xss')</script>"
curl "http://192.168.1.100:8080/?id=1' OR 1=1--"
```

### Network Interface Selection

#### Available Interfaces
```bash
# List network interfaces
ip link show
# or
ifconfig

# Common interfaces:
# - eth0 (Ethernet)
# - wlan0 (WiFi)
# - lo (Loopback - localhost only)
```

#### Testing Different Interfaces
1. **Loopback (lo)**: Test local traffic only
2. **Ethernet (eth0)**: Monitor wired network traffic
3. **WiFi (wlan0)**: Monitor wireless network traffic

---

## 🚨 Alert Generation

### Types of Alerts

#### 1. Web Application Alerts
- **SQL Injection**: `' OR 1=1`, `UNION SELECT`, `DROP TABLE`
- **XSS Attacks**: `<script>`, `javascript:`, `onload=`
- **Directory Traversal**: `../`, `..\\`, `%2e%2e%2f`
- **Command Injection**: `|`, `;`, `&&`, `||`

#### 2. Network Alerts
- **Port Scans**: SYN, FIN, XMAS, NULL scans
- **ICMP Attacks**: Floods, ping of death, smurf
- **Protocol Monitoring**: HTTP, HTTPS, DNS, FTP, SMTP

#### 3. System Alerts
- **Firewall Changes**: `ufw`, `iptables`, `firewall-cmd`
- **Admin Commands**: `chmod 777`, `rm -rf`, `sudo su`
- **File System**: `mkfs`, `format`, `fdisk`

### Alert Severity Levels
- **🔴 Critical (Priority 1)**: Immediate threat, requires action
- **🟠 High (Priority 2)**: Significant security risk
- **🟡 Medium (Priority 3)**: Moderate concern
- **🟢 Low (Priority 4)**: Minor issue
- **🔵 Info (Priority 5)**: Informational only

### Real-time Monitoring
- **Auto-refresh**: Alerts update every 5 seconds
- **Live counter**: Shows total alerts in real-time
- **Detailed view**: Click alerts for more information
- **Timestamp**: Each alert shows detection time

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Server Won't Start
```bash
# Check if port 8080 is in use
sudo netstat -tlnp | grep 8080

# Kill existing process
sudo pkill -f web_server_complete.py

# Check for errors
python3 web_server_complete.py
```

#### 2. Rules Not Loading
```bash
# Check rules file exists
ls -la rules/local.rules

# Test API directly
curl http://localhost:8080/api/rules

# Check browser console (F12) for JavaScript errors
```

#### 3. No Alerts Generated
```bash
# Verify IDS engine is running
# Check network interface selection
# Generate test traffic
# Check firewall rules
```

#### 4. Permission Issues
```bash
# Fix file permissions
chmod +x install_complete.sh
chmod +x bin/simple_ids

# Check Python permissions
python3 -c "import os; print(os.access('.', os.W_OK))"
```

### Debug Commands
```bash
# Check system status
ps aux | grep python
netstat -tlnp | grep 8080

# Test network connectivity
ping localhost
curl -v http://localhost:8080/api/rules

# Check logs
tail -f ids.log
```

---

## 🚀 Advanced Features

### 1. Custom Rule Creation
```bash
# Add custom rule via API
curl -X POST http://localhost:8080/api/add_rule \
  -H "Content-Type: application/json" \
  -d '{"rule": "alert tcp any any -> any 80 (msg:\"Custom Rule\"; content:\"test\"; priority:2)"}'
```

### 2. AI Rule Conversion
1. Go to "🔧 Rule Management" section
2. Enter natural language description
3. Click "🤖 Convert with AI"
4. Review generated rule
5. Add to rule set

### 3. Firewall Monitoring
- **Real-time monitoring** of system commands
- **Admin activity tracking**
- **Suspicious process detection**
- **File system changes**

### 4. Performance Monitoring
- **CPU usage** tracking
- **Memory consumption** monitoring
- **Network interface** statistics
- **Process monitoring**

---

## 📊 Testing Checklist

### ✅ Pre-Testing Setup
- [ ] Server starts without errors
- [ ] Web interface loads at http://localhost:8080
- [ ] All 98 rules display correctly
- [ ] API endpoints respond (200 status)
- [ ] Network interface is selectable

### ✅ Basic Functionality
- [ ] Rules can be added/edited/deleted
- [ ] AI rule conversion works
- [ ] Alerts section loads
- [ ] Firewall monitoring active
- [ ] Real-time updates working

### ✅ Security Testing
- [ ] SQL injection detection works
- [ ] XSS attack detection works
- [ ] Directory traversal detection works
- [ ] Command injection detection works
- [ ] Port scan detection works

### ✅ Network Testing
- [ ] Local traffic monitoring works
- [ ] Remote computer can connect
- [ ] Cross-network traffic detected
- [ ] Different interfaces selectable
- [ ] Alert generation from remote sources

### ✅ Performance Testing
- [ ] System handles multiple requests
- [ ] Memory usage remains stable
- [ ] CPU usage acceptable
- [ ] No memory leaks detected
- [ ] Concurrent users supported

---

## 📞 Support & Resources

### Getting Help
1. **Check logs**: `tail -f ids.log`
2. **Browser console**: Press F12 for JavaScript errors
3. **API testing**: Use curl commands above
4. **Network debugging**: Use `netstat`, `ps`, `ip` commands

### Useful Commands
```bash
# System monitoring
htop
iotop
netstat -tlnp

# Network testing
nmap localhost
tcpdump -i any port 8080

# Process management
ps aux | grep python
kill -9 <PID>
```

### File Locations
- **Web server**: `web_server_complete.py`
- **Rules**: `rules/local.rules`
- **Web interface**: `web_interface/index.html`
- **Engine**: `bin/simple_ids`
- **Logs**: `ids.log` (if running in background)

---

## 🎉 Conclusion

This Intrusion Detection System provides comprehensive security monitoring with:

- **98+ security rules** covering major threat categories
- **Real-time alerting** with detailed threat information
- **Web-based management** interface
- **AI-powered rule generation**
- **Cross-platform compatibility**
- **Network-wide monitoring** capabilities

Follow this guide to set up, test, and deploy your IDS system effectively. The system is designed to be both powerful and user-friendly, making it suitable for both learning and production environments.

**Happy Testing! 🛡️**
