# 🛡️ IDS DSL Engine - AI-Powered Network Intrusion Detection System

## 🚀 **Quick Start**

### **One Command Setup:**
```bash
bash install_complete.sh
```

### **Start the System:**

**For Demo (Recommended):**
```bash
# Windows
start_demo.bat

# Linux/Mac
chmod +x start_demo.sh
./start_demo.sh
```

**Manual Start:**
```bash
# Linux/Mac (requires sudo for packet capture)
sudo python3 web_server_complete.py

# Windows
python web_server_complete.py
```

**⚠️ Note:** Use sudo on Linux/Mac for full packet capture functionality!

### **Access Web Interface:**
Open your browser and go to: `http://localhost:8080`

## ✨ **Features**

### 🤖 **AI-Powered Rule Creation**
- **Gemini AI Integration**: Convert natural language to DSL rules
- **Smart Suggestions**: AI-powered rule recommendations
- **Example Templates**: Pre-built rule examples

### 📋 **Complete Rule Management**
- **View Rules**: See all current security rules
- **Edit Rules**: Modify existing rules with modal interface
- **Delete Rules**: Remove unwanted rules with confirmation
- **Add Rules**: Create new rules using AI or manually
- **Export Rules**: Download rules to text file

### 🚨 **Real-Time Monitoring**
- **Live Alerts**: Real-time security notifications
- **Firewall Monitoring**: Detect firewall rule changes and system administration
- **Process Monitoring**: Track suspicious system processes and commands
- **Network Interface Selection**: Monitor different network interfaces
- **Alert Severity Levels**: Critical, High, Medium, Low, Info
- **Historical Logs**: View past security events

### 🌐 **Modern Web Interface**
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-Time Updates**: Live data without page refresh
- **Intuitive Controls**: Easy-to-use interface
- **Professional UI**: Modern, clean design

## 🔧 **System Requirements**

### **Operating System:**
- Linux (Ubuntu, Debian, CentOS, etc.)
- Windows with WSL (Windows Subsystem for Linux)
- macOS with Homebrew

### **Dependencies:**
- GCC compiler
- Python 3.8+
- libpcap (packet capture library)
- curl (for API requests)
- make, bison, flex (build tools)
- psutil (for process monitoring)

### **Network Requirements:**
- Root/sudo privileges for packet capture
- Network interface access
- Internet connection for Gemini AI API

## 📦 **Installation**

### **Automatic Installation:**
```bash
# Download and run the complete installation script
bash install_complete.sh
```

### **Manual Installation:**
```bash
# Install system dependencies
sudo apt update
sudo apt install -y build-essential bison flex libpcap-dev python3 python3-pip curl

# Install Python packages
pip3 install psutil scapy requests

# Build the project (optional, for C engine)
make clean
make

# Start the web server
sudo python3 web_server_complete.py
```

## 🎯 **Usage Guide**

### **1. Creating AI Rules**
1. Open the web interface at `http://localhost:8080`
2. In the "Gemini AI Rule Creator" section:
   - Type your rule in natural language (e.g., "Detect SQL injection attempts")
   - Click "🤖 Convert with Gemini AI"
   - Review the generated DSL rule
   - Click "➕ Add Rule to Engine"

### **2. Managing Rules**
1. Click "🔄 Refresh Rules" to see all current rules
2. **Edit Rule**: Click "✏️ Edit" on any rule to modify it
3. **Delete Rule**: Click "🗑️ Delete" to remove a rule
4. **Export Rules**: Click "📤 Export Rules" to download all rules

### **3. Starting Monitoring**
1. Select your network interface (lo for testing, eth0/wlan0 for real monitoring)
2. Click "🚀 Start Engine" to begin monitoring
3. View live alerts in the "Live Security Alerts" section
4. Click "🔄 Refresh Alerts" to update the alert list

### **4. Example Rules**
Try these natural language examples:
- "Detect SQL injection attempts"
- "Monitor for XSS attacks"
- "Alert on port scanning activities"
- "Detect brute force attacks on SSH"
- "Block malicious file uploads"
- "Monitor directory traversal attempts"

## 🔧 **Configuration**

### **Gemini AI API Key**
The system comes pre-configured with a Gemini API key. To use your own:
1. Get a Gemini API key from Google AI Studio
2. Edit `web_server_complete.py`
3. Replace the `GEMINI_API_KEY` variable with your key

### **Network Interfaces**
- **lo (Loopback)**: Safe for testing, no real network traffic
- **eth0**: Ethernet interface for wired networks
- **wlan0**: Wireless interface for WiFi networks

### **Rules File**
Rules are stored in `rules/local.rules`. You can:
- Edit the file directly
- Use the web interface
- Import/export rules

## 📊 **System Architecture**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │────│  Python Server   │────│   Gemini AI     │
│   (Port 8080)   │    │  (API Endpoints) │    │   (Rule Conv.)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Rule Manager  │    │   IDS Engine     │    │   Alert System  │
│   (CRUD Ops)    │    │   (Packet Cap.)  │    │   (Live Logs)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚨 **Security Features**

### **Threat Detection:**
- SQL Injection attacks
- Cross-Site Scripting (XSS)
- Port scanning activities
- Brute force attacks
- Malicious file uploads
- Directory traversal attempts
- Command injection
- ICMP floods
- Firewall rule tampering
- System administration abuse
- Process-based attacks
- Privilege escalation attempts

### **Alert Levels:**
- **Critical (Priority 1)**: Immediate attention required
- **High (Priority 2)**: Important security events
- **Medium (Priority 3)**: Suspicious activities
- **Low (Priority 4)**: Minor security events
- **Info (Priority 5)**: General information

## 🔍 **Troubleshooting**

### **Common Issues:**

#### **"Permission Denied" Error**
```bash
# Solution: Run with sudo privileges
sudo python3 web_server_complete.py
```

#### **"Port 8080 in use" Error**
```bash
# Solution: Kill existing process
sudo lsof -ti:8080 | xargs sudo kill -9
```

#### **"Gemini API Error"**
- Check your internet connection
- Verify API key is correct
- Check API quota limits

#### **"No Alerts Generated"**
- Ensure the engine is running
- Check if network interface is correct
- Generate test traffic (ping, curl, etc.)

### **Debug Mode:**
```bash
# Run with verbose output
python3 web_server_complete.py --debug
```

## 📁 **File Structure**

```
Intrusion_Detection_System/
├── web_server_complete.py      # Main web server with AI integration
├── web_interface/
│   └── index.html              # Enhanced web interface
├── bin/
│   └── simple_ids             # Compiled IDS engine
├── rules/
│   └── local.rules            # Security rules file (80+ rules)
├── logs/
│   ├── alerts.log             # Alert logs
│   └── firewall_monitor.log  # Firewall monitoring logs
├── src/                       # Source code
├── include/                   # Header files
├── build/                     # Build artifacts
├── install_complete.sh        # Installation script
├── simple_ids.c               # Simple IDS engine source
├── requirements.txt           # Python dependencies
├── start_ids_system.bat       # Windows startup script
├── test_firewall_monitoring.py # Firewall monitoring test
└── README.md                  # This file
```

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 **Acknowledgments**

- Google Gemini AI for natural language processing
- libpcap for packet capture functionality
- The open-source community for various libraries and tools

## 📞 **Support**

For issues and questions:
1. Check the troubleshooting section above
2. Review the logs in the `logs/` directory
3. Open an issue on the project repository

---

**🛡️ IDS DSL Engine - Protecting Networks with AI-Powered Intelligence**
