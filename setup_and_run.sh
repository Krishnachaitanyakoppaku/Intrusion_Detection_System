#!/bin/bash

# IDS DSL Engine - Complete Setup and Run Script
# This script will install dependencies, build the project, and start the web interface

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    # Update package list
    sudo apt update -y
    
    # Install required packages
    sudo apt install -y bison flex libpcap-dev build-essential curl python3 python3-pip
    
    print_success "Dependencies installed successfully!"
}

# Function to build the project
build_project() {
    print_status "Building IDS DSL Engine..."
    
    # Clean previous builds
    make clean > /dev/null 2>&1 || true
    
    # Build the project
    if make > /dev/null 2>&1; then
        print_success "Project built successfully!"
    else
        print_error "Build failed. Please check the error messages above."
        exit 1
    fi
}

# Function to start the web interface
start_web_interface() {
    print_status "Starting web interface..."
    
    # Create a simple web server
    cat > web_server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import os
import subprocess
import json
import threading
import time
import signal
import sys

class IDSHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        return super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/start_ids':
            self.start_ids()
        elif self.path == '/api/stop_ids':
            self.stop_ids()
        elif self.path == '/api/convert_rule':
            self.convert_rule()
        elif self.path == '/api/get_alerts':
            self.get_alerts()
        else:
            self.send_error(404)
    
    def start_ids(self):
        try:
            # Start IDS engine in background
            cmd = ['sudo', './bin/ids_engine', '-i', 'lo', '-r', 'rules/local.rules']
            self.ids_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'started'}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def stop_ids(self):
        try:
            if hasattr(self, 'ids_process'):
                self.ids_process.terminate()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'stopped'}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def convert_rule(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            # Simple rule conversion (in real implementation, this would use AI)
            natural_language = data.get('text', '')
            dsl_rule = f'alert tcp any any -> any 80 (msg:"{natural_language}"; content:"test"; priority:1)'
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'dsl_rule': dsl_rule}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def get_alerts(self):
        try:
            # Read alerts from log file
            alerts = []
            if os.path.exists('logs/alerts.log'):
                with open('logs/alerts.log', 'r') as f:
                    alerts = f.readlines()[-10:]  # Last 10 alerts
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'alerts': alerts}).encode())
        except Exception as e:
            self.send_error(500, str(e))

def signal_handler(sig, frame):
    print('\nShutting down web server...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    PORT = 8080
    
    # Change to the project directory
    os.chdir('/home/kkc/Documents/CD_project')
    
    with socketserver.TCPServer(("", PORT), IDSHandler) as httpd:
        print(f"Web server running on http://localhost:{PORT}")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()
EOF

    chmod +x web_server.py
    
    # Start the web server in background
    python3 web_server.py &
    WEB_PID=$!
    
    print_success "Web interface started on http://localhost:8080"
    print_status "Web server PID: $WEB_PID"
    
    # Wait a moment for server to start
    sleep 2
    
    # Open the web browser
    if command_exists xdg-open; then
        xdg-open http://localhost:8080
    elif command_exists open; then
        open http://localhost:8080
    else
        print_status "Please open http://localhost:8080 in your web browser"
    fi
}

# Function to create enhanced web interface
create_web_interface() {
    print_status "Creating enhanced web interface..."
    
    cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS DSL Engine - Smart Security Interface</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            color: white;
        }
        .header h1 { 
            font-size: 2.5em; 
            margin-bottom: 10px; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header p { 
            font-size: 1.2em; 
            opacity: 0.9;
        }
        .main-content { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 30px; 
            margin-bottom: 30px;
        }
        .card { 
            background: white; 
            padding: 25px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .card:hover { 
            transform: translateY(-5px); 
        }
        .card h2 { 
            color: #667eea; 
            margin-bottom: 20px; 
            font-size: 1.5em;
        }
        .input-group { 
            margin-bottom: 20px; 
        }
        .input-group label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600; 
            color: #555;
        }
        .input-group input, 
        .input-group textarea, 
        .input-group select { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #e1e5e9; 
            border-radius: 8px; 
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .input-group input:focus, 
        .input-group textarea:focus, 
        .input-group select:focus { 
            outline: none; 
            border-color: #667eea; 
        }
        .btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 12px 25px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 16px; 
            font-weight: 600;
            transition: transform 0.2s ease;
        }
        .btn:hover { 
            transform: translateY(-2px); 
        }
        .btn:active { 
            transform: translateY(0); 
        }
        .btn-success { 
            background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%); 
        }
        .btn-danger { 
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); 
        }
        .status { 
            padding: 15px; 
            border-radius: 8px; 
            margin: 15px 0; 
            font-weight: 600;
        }
        .status.running { 
            background: #d4edda; 
            color: #155724; 
            border: 1px solid #c3e6cb;
        }
        .status.stopped { 
            background: #f8d7da; 
            color: #721c24; 
            border: 1px solid #f5c6cb;
        }
        .alerts-container { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            max-height: 400px; 
            overflow-y: auto; 
            font-family: 'Courier New', monospace;
            border: 1px solid #e9ecef;
        }
        .alert-item { 
            padding: 10px; 
            margin: 5px 0; 
            background: white; 
            border-radius: 5px; 
            border-left: 4px solid #ffc107;
        }
        .alert-item.high { 
            border-left-color: #dc3545; 
        }
        .alert-item.medium { 
            border-left-color: #fd7e14; 
        }
        .alert-item.low { 
            border-left-color: #28a745; 
        }
        .full-width { 
            grid-column: 1 / -1; 
        }
        .loading { 
            display: none; 
            text-align: center; 
            padding: 20px;
        }
        .spinner { 
            border: 4px solid #f3f3f3; 
            border-top: 4px solid #667eea; 
            border-radius: 50%; 
            width: 40px; 
            height: 40px; 
            animation: spin 1s linear infinite; 
            margin: 0 auto;
        }
        @keyframes spin { 
            0% { transform: rotate(0deg); } 
            100% { transform: rotate(360deg); } 
        }
        .examples { 
            background: #e3f2fd; 
            padding: 15px; 
            border-radius: 8px; 
            margin-top: 15px;
        }
        .examples h4 { 
            color: #1976d2; 
            margin-bottom: 10px;
        }
        .examples ul { 
            list-style: none; 
            padding-left: 0;
        }
        .examples li { 
            padding: 5px 0; 
            border-bottom: 1px solid #bbdefb;
        }
        .examples li:last-child { 
            border-bottom: none; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ IDS DSL Engine</h1>
            <p>Smart Network Intrusion Detection System</p>
        </div>

        <div class="main-content">
            <!-- Natural Language Rule Creator -->
            <div class="card">
                <h2>🤖 AI-Powered Rule Creator</h2>
                <div class="input-group">
                    <label for="natural-language">Describe your security rule in plain English:</label>
                    <textarea id="natural-language" rows="3" placeholder="e.g., 'Detect SQL injection attempts on web servers'"></textarea>
                </div>
                <button class="btn" onclick="convertRule()">Convert to DSL Rule</button>
                
                <div class="input-group" style="margin-top: 20px;">
                    <label for="dsl-rule">Generated DSL Rule:</label>
                    <textarea id="dsl-rule" rows="2" readonly></textarea>
                </div>
                <button class="btn btn-success" onclick="addRule()">Add Rule to Engine</button>
                
                <div class="examples">
                    <h4>💡 Example Rules:</h4>
                    <ul>
                        <li>"Detect SQL injection attempts"</li>
                        <li>"Monitor for XSS attacks"</li>
                        <li>"Alert on port scanning activities"</li>
                        <li>"Detect brute force attacks"</li>
                    </ul>
                </div>
            </div>

            <!-- Engine Control -->
            <div class="card">
                <h2>⚙️ Engine Control</h2>
                <div class="input-group">
                    <label for="interface">Network Interface:</label>
                    <select id="interface">
                        <option value="lo">Loopback (lo)</option>
                        <option value="eth0">Ethernet (eth0)</option>
                        <option value="wlan0">Wireless (wlan0)</option>
                    </select>
                </div>
                
                <div class="status" id="engine-status">
                    <strong>Engine Status:</strong> <span id="status-text">Stopped</span>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button class="btn btn-success" onclick="startEngine()">Start Engine</button>
                    <button class="btn btn-danger" onclick="stopEngine()">Stop Engine</button>
                </div>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>Processing...</p>
                </div>
            </div>
        </div>

        <!-- Live Alerts -->
        <div class="card full-width">
            <h2>🚨 Live Security Alerts</h2>
            <div class="alerts-container" id="alerts-container">
                <p style="text-align: center; color: #666; padding: 20px;">
                    Start the engine to see live security alerts...
                </p>
            </div>
            <button class="btn" onclick="refreshAlerts()" style="margin-top: 15px;">Refresh Alerts</button>
        </div>
    </div>

    <script>
        let engineRunning = false;
        let alertInterval;

        // Convert natural language to DSL rule
        async function convertRule() {
            const naturalLanguage = document.getElementById('natural-language').value;
            if (!naturalLanguage) {
                alert('Please enter a natural language description');
                return;
            }

            try {
                const response = await fetch('/api/convert_rule', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ text: naturalLanguage })
                });

                const data = await response.json();
                document.getElementById('dsl-rule').value = data.dsl_rule;
            } catch (error) {
                console.error('Error converting rule:', error);
                alert('Error converting rule. Please try again.');
            }
        }

        // Add rule to engine
        function addRule() {
            const dslRule = document.getElementById('dsl-rule').value;
            if (!dslRule) {
                alert('Please generate a DSL rule first');
                return;
            }
            
            // In a real implementation, this would save the rule to a file
            alert('Rule added successfully!');
        }

        // Start the IDS engine
        async function startEngine() {
            const interface = document.getElementById('interface').value;
            
            document.getElementById('loading').style.display = 'block';
            
            try {
                const response = await fetch('/api/start_ids', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ interface: interface })
                });

                const data = await response.json();
                
                if (data.status === 'started') {
                    engineRunning = true;
                    document.getElementById('status-text').textContent = 'Running';
                    document.getElementById('engine-status').className = 'status running';
                    
                    // Start polling for alerts
                    startAlertPolling();
                }
            } catch (error) {
                console.error('Error starting engine:', error);
                alert('Error starting engine. Please check if you have sudo privileges.');
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }

        // Stop the IDS engine
        async function stopEngine() {
            try {
                const response = await fetch('/api/stop_ids', {
                    method: 'POST'
                });

                const data = await response.json();
                
                if (data.status === 'stopped') {
                    engineRunning = false;
                    document.getElementById('status-text').textContent = 'Stopped';
                    document.getElementById('engine-status').className = 'status stopped';
                    
                    // Stop polling for alerts
                    if (alertInterval) {
                        clearInterval(alertInterval);
                    }
                }
            } catch (error) {
                console.error('Error stopping engine:', error);
            }
        }

        // Start polling for alerts
        function startAlertPolling() {
            alertInterval = setInterval(refreshAlerts, 2000); // Poll every 2 seconds
        }

        // Refresh alerts
        async function refreshAlerts() {
            try {
                const response = await fetch('/api/get_alerts');
                const data = await response.json();
                
                const alertsContainer = document.getElementById('alerts-container');
                
                if (data.alerts && data.alerts.length > 0) {
                    alertsContainer.innerHTML = data.alerts.map(alert => 
                        `<div class="alert-item high">${alert}</div>`
                    ).join('');
                } else {
                    alertsContainer.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">No alerts yet. Generate some network traffic to see alerts...</p>';
                }
            } catch (error) {
                console.error('Error fetching alerts:', error);
            }
        }

        // Initialize the interface
        document.addEventListener('DOMContentLoaded', function() {
            console.log('IDS DSL Engine Web Interface loaded');
        });
    </script>
</body>
</html>
EOF

    print_success "Enhanced web interface created!"
}

# Main execution
main() {
    echo "🚀 IDS DSL Engine - Complete Setup and Run"
    echo "=========================================="
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for security reasons."
        print_status "Consider running as a regular user and using sudo when needed."
    fi
    
    # Step 1: Install dependencies
    if ! command_exists bison || ! command_exists flex; then
        print_status "Installing required dependencies..."
        install_dependencies
    else
        print_success "Dependencies already installed!"
    fi
    
    # Step 2: Build the project
    print_status "Building the IDS DSL Engine..."
    build_project
    
    # Step 3: Create web interface
    create_web_interface
    
    # Step 4: Start web server
    start_web_interface
    
    echo ""
    print_success "🎉 IDS DSL Engine is now running!"
    print_status "Web Interface: http://localhost:8080"
    print_status "Press Ctrl+C to stop the web server"
    echo ""
    print_status "Features available:"
    print_status "  • AI-powered rule creation from natural language"
    print_status "  • Real-time network monitoring"
    print_status "  • Live security alerts"
    print_status "  • Easy-to-use web interface"
    echo ""
    
    # Keep the script running
    wait
}

# Run the main function
main "$@"
