# 🚀 IDS DSL Engine - Quick Start Guide

## **⚡ Super Quick Start (30 seconds)**

### **Step 1: Install Everything**
```bash
bash install_complete.sh
```

### **Step 2: Start the System**
```bash
python3 web_server_complete.py
```

### **Step 3: Open Web Interface**
Open your browser and go to: `http://localhost:8080`

**That's it!** 🎉

---

## **🎯 What You'll See**

### **🤖 AI-Powered Rule Creator**
- Type: "Detect SQL injection attempts"
- Click: "🤖 Convert with Gemini AI"
- Get: `alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)`

### **📋 Rule Management**
- **View**: All your security rules
- **Edit**: Click "✏️ Edit" to modify any rule
- **Delete**: Click "🗑️ Delete" to remove rules
- **Export**: Download all rules to a file

### **🚨 Live Security Monitoring**
- **Start Engine**: Click "🚀 Start Engine"
- **Live Alerts**: See real-time security notifications
- **Network Traffic**: Monitor different interfaces

---

## **🔥 Key Features**

### **✅ AI Integration**
- **Gemini AI**: Converts natural language to DSL rules
- **Smart Suggestions**: AI-powered recommendations
- **Fallback**: Template-based conversion if AI fails

### **✅ Complete Rule Management**
- **CRUD Operations**: Create, Read, Update, Delete rules
- **Modal Interface**: Easy editing with popup dialogs
- **Export/Import**: Save and load rule sets

### **✅ Real-Time Monitoring**
- **Live Alerts**: Instant security notifications
- **Multiple Interfaces**: lo, eth0, wlan0 support
- **Severity Levels**: Critical, High, Medium, Low, Info

### **✅ Modern Interface**
- **Responsive Design**: Works on all devices
- **Real-Time Updates**: No page refresh needed
- **Professional UI**: Clean, modern design

---

## **🎮 Try These Examples**

### **Natural Language → DSL Rules**

| Natural Language | Generated DSL Rule |
|------------------|-------------------|
| "Detect SQL injection" | `alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)` |
| "Monitor XSS attacks" | `alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)` |
| "Alert on port scans" | `alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)` |
| "Detect SSH brute force" | `alert tcp any any -> any 22 (msg:"SSH Brute Force"; priority:3)` |
| "Block malicious files" | `alert tcp any any -> any 80 (msg:"Malicious File"; content:".exe"; priority:2)` |

---

## **🛠️ System Requirements**

### **Minimum Requirements:**
- **OS**: Linux, Windows WSL, or macOS
- **RAM**: 512MB
- **Disk**: 100MB free space
- **Network**: Internet connection for AI API

### **Recommended:**
- **OS**: Ubuntu 20.04+ or Windows 10+ with WSL
- **RAM**: 2GB+
- **Disk**: 1GB free space
- **Network**: Stable internet connection

---

## **🔧 Installation Options**

### **Option 1: Automatic (Recommended)**
```bash
# One command installs everything
bash install_complete.sh
```

### **Option 2: Manual**
```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential bison flex libpcap-dev python3 python3-pip python3-requests

# Build project
make clean && make

# Start server
python3 web_server_complete.py
```

---

## **🎯 Usage Scenarios**

### **🏠 Home Network Security**
1. Start monitoring your WiFi interface
2. Create rules for common threats
3. Get alerts for suspicious activities
4. Protect your family's devices

### **🏢 Office Network Monitoring**
1. Monitor multiple network segments
2. Create custom rules for your business
3. Track security events in real-time
4. Generate security reports

### **🎓 Learning Cybersecurity**
1. Experiment with different rule types
2. Understand network security concepts
3. Practice with real packet analysis
4. Learn about intrusion detection

### **🔬 Research & Development**
1. Test new security rules
2. Analyze network traffic patterns
3. Develop custom detection methods
4. Study attack techniques

---

## **🚨 Common Issues & Solutions**

### **❌ "Permission Denied"**
```bash
# Solution: Use sudo
sudo python3 web_server_complete.py
```

### **❌ "Port 8080 in use"**
```bash
# Solution: Kill existing process
sudo lsof -ti:8080 | xargs sudo kill -9
```

### **❌ "No alerts showing"**
```bash
# Solution: Generate test traffic
ping -c 5 8.8.8.8
curl -s http://httpbin.org/get
```

### **❌ "Gemini AI not working"**
- Check internet connection
- Verify API key is correct
- Check API quota limits

---

## **📊 What's Running**

### **Processes:**
- **Web Server**: `python3 web_server_complete.py` (Port 8080)
- **IDS Engine**: `./bin/simple_ids` (When started)
- **Background Tasks**: Alert processing, rule management

### **Files Created:**
- **Rules**: `rules/local.rules`
- **Logs**: `logs/alerts.log`
- **Build**: `bin/simple_ids`

---

## **🎉 Success Indicators**

### **✅ System Running:**
- Web interface loads at `http://localhost:8080`
- "Gemini AI Integration: ENABLED" message
- Rule management interface visible

### **✅ AI Working:**
- Natural language converts to DSL rules
- Gemini API responds successfully
- Rules are generated correctly

### **✅ Monitoring Active:**
- Engine status shows "Running"
- Live alerts appear in real-time
- Network traffic is being analyzed

---

## **🚀 Next Steps**

### **Immediate:**
1. ✅ Create your first AI rule
2. ✅ Start monitoring
3. ✅ View live alerts
4. ✅ Manage your rules

### **Advanced:**
1. 🔄 Customize rule templates
2. 🔄 Set up automated monitoring
3. 🔄 Integrate with other security tools
4. 🔄 Develop custom detection rules

---

## **💡 Pro Tips**

### **For Best Results:**
1. **Start with loopback interface (lo)** for testing
2. **Use specific rule descriptions** for better AI conversion
3. **Monitor logs regularly** for system health
4. **Export rules frequently** as backup

### **Performance Optimization:**
1. **Limit rule complexity** for faster processing
2. **Use appropriate priority levels** for alerts
3. **Monitor system resources** (CPU, memory)
4. **Regular cleanup** of old logs

---

## **🎯 Perfect For:**

### **👨‍🎓 Students**
- Learn network security concepts
- Practice with real-world tools
- Understand intrusion detection

### **👨‍💻 Developers**
- Integrate security monitoring
- Build custom security rules
- Develop AI-powered tools

### **🏢 Organizations**
- Monitor network security
- Detect threats in real-time
- Train security teams

### **🏠 Home Users**
- Protect home networks
- Monitor internet traffic
- Learn about cybersecurity

---

**🛡️ Your AI-Powered Security System is Ready!**

Start protecting your network with intelligent, real-time intrusion detection.