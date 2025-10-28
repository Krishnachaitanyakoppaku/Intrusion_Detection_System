# 🧪 Testing Guide for IDS DSL Engine

## 🚀 Quick Start - Testing from Another Computer

### Step-by-Step Instructions

1. **Start the Web Server** (on IDS server machine):
   ```bash
   cd Intrusion_Detection_System
   python3 web_server_complete.py
   ```

2. **Access Web Interface**:
   - Open browser: `http://YOUR_SERVER_IP:8080`
   - Or locally: `http://localhost:8080`

3. **Add Rules**:
   - Click "🔄 Refresh All Rules"
   - Click "➕ Add to Current Rules" on any SSH or port scan rules
   - Verify rules appear in "Current Active Rules" section

4. **Select Network Interface**:
   - In "Engine Control" section, select your network interface:
     - `eth0` for Ethernet
     - `wlan0` for Wireless
     - **NOT** `lo` (loopback) - this won't see external traffic!
   
5. **Start the Engine**:
   - Click "🚀 Start Engine"
   - Status should turn green "Running"

6. **Find Your Network Interface**:
   On the IDS server, run:
   ```bash
   ip addr show
   # or
   ifconfig
   ```
   Look for the interface with your IP address (e.g., 10.14.84.14)

7. **Test from Another Computer**:
   ```bash
   # Test SSH connection
   telnet 10.14.84.14 22
   
   # Test multiple times to trigger brute force detection
   telnet 10.14.84.14 22
   telnet 10.14.84.14 22
   
   # Or use curl
   curl "http://10.14.84.14:80/?id=1' OR '1'='1"
   ```

8. **Check Alerts**:
   - In web interface, click "🔄 Refresh Alerts"
   - You should see alerts appear!

---

## Table of Contents
1. [Testing Alerts from Another Computer](#testing-alerts-from-another-computer)
2. [Testing Firewall Alerts](#testing-firewall-alerts)
3. [Testing the Web Interface](#testing-the-web-interface)

---

## 🖥️ Testing Alerts from Another Computer

### Prerequisites
- The IDS engine must be running on the server
- You need another computer on the same network (or WSL/multiple terminals if testing locally)

### Method 1: Using curl (HTTP Requests)

**IMPORTANT**: Put URLs in quotes and use proper URL encoding!

#### Test SQL Injection Alert
```bash
# From another computer or terminal
# Use quotes around URL to handle special characters
curl "http://10.14.84.14:80/?id=1%27%20OR%20%271%27%3D%271"
# Or simplified version (URL encodes the quotes):
curl "http://10.14.84.14:80/?id=1' OR '1'='1"
# For testing IDS, use simpler pattern:
curl "http://10.14.84.14:80/?test=UNION%20SELECT"
curl "http://10.14.84.14:80/?user=DROP%20TABLE"
```

#### Test XSS Alert
```bash
# URL encode the angle brackets
curl "http://10.14.84.14:80/?search=%3Cscript%3E"
curl "http://10.14.84.14:80/?name=%3Ciframe%3E"
# Or use simplified (let curl encode automatically):
curl "http://10.14.84.14:80/?search=<script>"
curl "http://10.14.84.14:80/?iframe=<iframe>"
```

#### Test Directory Traversal Alert
```bash
curl "http://10.14.84.14:80/..%2F..%2F..%2Fetc%2Fpasswd"
curl "http://10.14.84.14:80/../../../etc/passwd"
curl "http://10.14.84.14:80/?file=..%5C..%5Cboot.ini"
```

#### Test Command Injection Alert
```bash
# Test pipe character
curl "http://10.14.84.14:80/?cmd=test%7Cwhoami"
curl "http://10.14.84.14:80/?exec=test%3Bnetstat"
```

#### Test Malicious File Upload Detection
```bash
# Note: These might fail if upload endpoint doesn't exist, but will trigger IDS
curl -X POST "http://10.14.84.14:80/upload" -F "filename=shell.exe"
curl "http://10.14.84.14:80/upload?file=test.php"
```

#### **EASIEST TEST - Just Send HTTP Requests:**
```bash
# Simplest test - just send HTTP request to port 80
curl http://10.14.84.14:80/

# Test with common web paths
curl http://10.14.84.14:80/index.html
curl http://10.14.84.14:80/admin
curl http://10.14.84.14:80/login.php?id=123

# Test with GET parameters
curl "http://10.14.84.14:80/?id=1"
curl "http://10.14.84.14:80/?page=about"
```

### Method 2: Using telnet (Port Scanning)

#### Test Port Scan Detection
```bash
# From another computer
telnet SERVER_IP 22
telnet SERVER_IP 80
telnet SERVER_IP 443
```

Or use `nc` (netcat):
```bash
nc SERVER_IP 22
nc SERVER_IP 80
nc SERVER_IP 443
```

### Method 3: Using ping (ICMP Flood Test)

#### Test ICMP Flood Detection
```bash
# From another computer - Send rapid ICMP packets
ping SERVER_IP -n 100

# On Windows PowerShell
1..100 | ForEach-Object { Test-Connection -ComputerName SERVER_IP -Count 1 }
```

### Method 4: Using nmap (Network Scanning)

#### Test Network Scanner Detection
```bash
# From another computer
nmap -sS SERVER_IP
nmap -p 1-1000 SERVER_IP
nmap -sV SERVER_IP
```

### Method 5: Using SSH (Brute Force Testing)

#### Test SSH Brute Force Detection
```bash
# From another computer - Attempt SSH login
ssh SERVER_IP -l root
ssh SERVER_IP -l admin
# Repeat multiple times to trigger brute force detection
```

---

## 🔥 Testing Firewall Alerts

Firewall monitoring detects suspicious system administration commands and firewall changes.

### Test 1: Firewall Changes (Linux)

#### On the IDS Server Machine (in a terminal):
```bash
# Test 1: Disable firewall
sudo ufw disable
sudo ufw reset

# Test 2: Flush iptables
sudo iptables -F
sudo iptables -X

# Test 3: Stop firewall service
sudo systemctl stop firewalld
sudo firewall-cmd --reload
```

### Test 2: System Administration Commands (Linux)

```bash
# Test 1: Dangerous file permissions
sudo chmod 777 /etc/passwd
sudo chmod 666 /etc/shadow

# Test 2: Remove critical directories
sudo rm -rf /tmp/test_directory

# Test 3: Format operations
dd if=/dev/zero of=/tmp/test bs=1M count=10

# Test 4: Network scanning from admin
sudo nmap -sS 192.168.1.0/24
sudo masscan 192.168.1.0/24 -p 80,443,22,21
```

### Test 3: Privilege Escalation Attempts (Linux)

```bash
# Test switching to root
sudo su
su -
sudo -i
```

### Test 4: Firewall Changes (Windows)

#### On Windows Server (PowerShell or CMD as Administrator):
```powershell
# Test 1: Disable Windows Firewall
netsh advfirewall set allprofiles state off

# Test 2: Flush firewall rules
netsh advfirewall firewall delete rule name="AllowAll"
```

### Test 5: System Commands (Windows)

```powershell
# Test dangerous file permissions
icacls C:\Windows\System32\config\sam /grant Everyone:F

# Test format operations
format C: /Q
del /F /S /Q C:\Temp\*.*
```

---

## 🌐 Testing the Web Interface

### Step 1: Start the Web Server

```bash
# Navigate to project directory
cd Intrusion_Detection_System

# Start the web server
python3 web_server_complete.py
```

You should see:
```
IDS DSL Engine - Web Server
Web Interface: http://localhost:8080
Gemini AI Integration: ENABLED
Rule Management: ENABLED
Monitoring: Ready
Press Ctrl+C to stop
```

### Step 2: Access the Web Interface

Open your browser and go to: `http://localhost:8080`

### Step 3: Test Features

#### A. View All Rules Catalog
1. Click "🔄 Refresh All Rules" button
2. You should see all 94 available rules with:
   - Category tags (Web Application Security, Malware Detection, etc.)
   - Description of what each rule detects
   - "➕ Add to Current Rules" button for each rule

#### B. Add Rules to Current Active Rules
1. Scroll through the All Rules Library
2. Click "➕ Add to Current Rules" on any rule
3. The rule should move to the "Current Active Rules" section

#### C. View Current Active Rules
1. Scroll down to "Current Active Rules" section
2. Click "🔄 Refresh Current Rules"
3. You should see all rules you've added with Edit and Delete buttons

#### D. Test AI Rule Creation
1. In the "Gemini AI Rule Creator" section:
   - Type: "Detect SQL injection attempts"
   - Click "🤖 Convert with Gemini AI"
   - Wait for the DSL rule to be generated
   - Click "➕ Add Rule to Engine"
2. Refresh "Current Active Rules" to see your new rule

#### E. Test Engine Control
1. Select a network interface (lo for testing)
2. Click "🚀 Start Engine" to begin monitoring
3. View the status should change to "Running"

#### F. Generate Test Alerts
After starting the engine, trigger alerts using the commands from [Method 1](#method-1-using-curl-http-requests)

#### G. View Live Alerts
1. After triggering alerts, click "🔄 Refresh Alerts"
2. You should see alerts appear in the "Live Security Alerts" section

#### H. Test Firewall Monitoring
1. Click "🔄 Refresh Firewall Alerts"
2. Run firewall tests from the [Firewall Alert Tests](#testing-firewall-alerts)
3. Refresh again to see firewall alerts

---

## 📋 Quick Test Checklist

### Network Alerts
- [ ] SQL Injection alert triggered
- [ ] XSS attack alert triggered
- [ ] Directory traversal alert triggered
- [ ] Port scan alert triggered
- [ ] ICMP flood alert triggered

### Firewall Alerts
- [ ] Firewall disable alert
- [ ] Iptables flush alert
- [ ] Dangerous chmod alert
- [ ] File deletion alert
- [ ] Privilege escalation alert

### Web Interface
- [ ] All Rules catalog loads (94 rules)
- [ ] Current Rules section works
- [ ] Add rules from catalog works
- [ ] Edit/Delete current rules works
- [ ] AI rule creation works
- [ ] Engine start/stop works
- [ ] Alerts display in real-time

---

## 🔍 Troubleshooting

### No Alerts Appearing?

**Step 1: Check if Engine is Running**
- Look at the "Engine Control" section in web interface
- Status should show "Running" in green
- If not running, click "🚀 Start Engine"

**Step 2: Select the Correct Network Interface**
- **CRITICAL**: Don't use 'lo' (loopback) for testing from another computer
- In the web interface, select:
  - `eth0` for wired Ethernet
  - `wlan0` for wireless
  - `lo` only for testing on the same machine
- Click "🚀 Start Engine" again with the correct interface

**Step 3: Check Interface Names**
On the IDS server, run:
```bash
# Linux/Mac
ifconfig
# or
ip addr show

# Find your active network interface
# Common names: eth0, wlan0, enp0s3, etc.
```

**Step 4: Verify Rules Are Active**
- Click "Show Current Rules" in web interface
- Your rules must be in the "Current Active Rules" section
- If empty, go to "All Rules Library" and add rules using "Add to Current Rules"

**Step 5: Check if Traffic is Reaching the Interface**
```bash
# On the IDS server, monitor traffic
sudo tcpdump -i eth0 port 22
# Then from another computer: telnet SERVER_IP 22
# You should see packets in tcpdump output
```

**Step 6: Check Logs**
- On server, check `logs/alerts.log`:
```bash
tail -f logs/alerts.log
```
- Check if IDS engine is actually running:
```bash
ps aux | grep simple_ids
```

**Step 7: Test Locally First**
- Use 'lo' interface and test from the same machine:
```bash
# On server terminal
curl "http://localhost:80/?id=1' OR '1'='1"
ping localhost
telnet localhost 22
```

### Can't See Firewall Alerts?
1. Check `logs/firewall_monitor.log` on the server
2. Ensure you're running commands as root/admin on the server
3. The firewall monitor runs in the background - wait 10 seconds for detection

### Web Interface Not Loading?
1. Check if `python3 web_server_complete.py` is running
2. Verify you're accessing the correct URL
3. Check console for JavaScript errors (F12 in browser)
4. Check server console for Python errors

### API Errors?
1. Restart the web server
2. Check browser console (F12) for fetch errors
3. Check server console for Python tracebacks
4. Verify firewall isn't blocking port 8080

---

## 📊 Expected Behavior

### When Engine is Running:
- Status shows "Running" in green
- Network traffic is being analyzed
- Alerts appear within 1-3 seconds of trigger
- Alerts log to `logs/alerts.log`

### When Firewall Monitor Detects Activity:
- Suspicious commands logged to `logs/firewall_monitor.log`
- Alerts appear in "Firewall & System Monitoring" section
- Detection happens within 10 seconds

### When Adding Rules:
- Rule appears in "Current Active Rules"
- Rule is saved to `rules/local.rules`
- Rule takes effect immediately (if engine is running)

---

## 🎯 Recommended Test Sequence

1. **Start Web Server**: `python3 web_server_complete.py`
2. **Open Browser**: Navigate to `http://localhost:8080`
3. **Add Rules**: Add 3-5 rules from All Rules catalog to Current Rules
4. **Start Engine**: Click "🚀 Start Engine"
5. **Generate Test Traffic**: Use curl/nmap/ping commands
6. **View Alerts**: Refresh alerts and verify detection
7. **Test Firewall**: Run firewall test commands on server
8. **View Firewall Alerts**: Refresh firewall alerts section
9. **Verify Logs**: Check `logs/alerts.log` and `logs/firewall_monitor.log`

---

**Happy Testing! 🚀**

