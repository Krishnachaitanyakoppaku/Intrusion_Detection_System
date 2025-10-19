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
import requests
import urllib.parse
import re
import psutil
import logging

# Gemini API integration
GEMINI_API_KEY = "AIzaSyCK3N6q-3kxwLX0p-kqiEJmxPdxlxN-nZg"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

# Rules file path
RULES_FILE = "rules/local.rules"

# Firewall monitoring class
class FirewallMonitor:
    def __init__(self):
        self.firewall_rules_file = "logs/firewall_monitor.log"
        self.suspicious_commands = [
            'ufw reset', 'ufw disable', 'ufw --force reset',
            'iptables -F', 'iptables --flush', 'iptables -X',
            'firewall-cmd --reload', 'systemctl stop firewalld',
            'chmod 777', 'chmod 666', 'chmod 000',
            'rm -rf /', 'rm -rf /*', 'dd if=/dev/zero',
            'mkfs.ext4', 'format c:', 'del /f /s /q',
            'netstat -an', 'ss -tuln', 'lsof -i',
            'nmap', 'masscan', 'zmap'
        ]
        self.admin_users = ['root', 'admin', 'administrator']
        
    def log_firewall_event(self, event_type, details):
        """Log firewall-related events"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] FIREWALL ALERT: {event_type} - {details}\n"
        
        try:
            with open(self.firewall_rules_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Error logging firewall event: {e}")
    
    def check_processes(self):
        """Monitor running processes for suspicious activities"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    username = proc.info['username']
                    
                    # Check for suspicious commands
                    for suspicious_cmd in self.suspicious_commands:
                        if suspicious_cmd.lower() in cmdline.lower():
                            self.log_firewall_event(
                                "SUSPICIOUS PROCESS",
                                f"User: {username}, Command: {cmdline}, PID: {proc.info['pid']}"
                            )
                            
                    # Check for admin users running dangerous commands
                    if username in self.admin_users:
                        dangerous_patterns = ['ufw', 'iptables', 'firewall', 'chmod', 'rm -rf']
                        for pattern in dangerous_patterns:
                            if pattern in cmdline.lower():
                                self.log_firewall_event(
                                    "ADMIN DANGEROUS COMMAND",
                                    f"Admin user {username} executed: {cmdline}"
                                )
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error monitoring processes: {e}")
    
    def check_network_interfaces(self):
        """Monitor network interface changes"""
        try:
            interfaces = psutil.net_if_addrs()
            for interface, addresses in interfaces.items():
                for addr in addresses:
                    if addr.family == 2:  # IPv4
                        # Log interface information
                        if interface not in ['lo', 'loopback']:
                            self.log_firewall_event(
                                "NETWORK INTERFACE",
                                f"Interface: {interface}, IP: {addr.address}"
                            )
        except Exception as e:
            print(f"Error monitoring network interfaces: {e}")
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        def monitor_loop():
            while True:
                self.check_processes()
                self.check_network_interfaces()
                time.sleep(10)  # Check every 10 seconds
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        print("Firewall monitoring started")

# Initialize firewall monitor
firewall_monitor = FirewallMonitor()

class IDSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='web_interface', **kwargs)
    
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        elif self.path == '/api/rules':
            self.get_rules()
            return
        elif self.path == '/api/get_alerts':
            self.get_alerts()
            return
        elif self.path == '/api/get_firewall_alerts':
            self.get_firewall_alerts()
            return
        return super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/start_ids':
            self.start_ids()
        elif self.path == '/api/stop_ids':
            self.stop_ids()
        elif self.path == '/api/convert_rule':
            self.convert_rule_with_gemini()
        elif self.path == '/api/add_rule':
            self.add_rule()
        elif self.path == '/api/delete_rule':
            self.delete_rule()
        elif self.path == '/api/update_rule':
            self.update_rule()
        else:
            self.send_error(404)
    
    def start_ids(self):
        try:
            # Start IDS engine in background
            cmd = ['sudo', './bin/simple_ids', '-i', 'lo']
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
    
    def convert_rule_with_gemini(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            natural_language = data.get('text', '')
            if not natural_language:
                self.send_error(400, "No text provided")
                return
            
            # Call Gemini API
            prompt = f"""
            Convert this natural language security rule to IDS DSL syntax:
            "{natural_language}"
            
            The DSL format should be:
            action protocol source_ip source_port direction dest_ip dest_port (options)
            
            Where:
            - action: alert, log, or pass
            - protocol: tcp, udp, icmp, or ip
            - source_ip/dest_ip: any, specific IP, or network range
            - source_port/dest_port: any or specific port number
            - direction: -> (unidirectional) or <> (bidirectional)
            - options: msg:"message", content:"pattern", priority:1-5
            
            Examples:
            - "Detect SQL injection" -> alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR 1=1"; priority:1)
            - "Monitor SSH connections" -> alert tcp any any -> any 22 (msg:"SSH Connection"; priority:3)
            - "Block malicious files" -> alert tcp any any -> any 80 (msg:"Malicious File"; content:".exe"; priority:2)
            
            Return only the DSL rule, nothing else.
            """
            
            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            }
            
            response = requests.post(GEMINI_API_URL, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    dsl_rule = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    # Clean up the response
                    dsl_rule = dsl_rule.replace('```', '').replace('dsl', '').strip()
                else:
                    dsl_rule = f'alert tcp any any -> any 80 (msg:"{natural_language}"; content:"test"; priority:1)'
            else:
                print(f"Gemini API error: {response.status_code}")
                dsl_rule = f'alert tcp any any -> any 80 (msg:"{natural_language}"; content:"test"; priority:1)'
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'dsl_rule': dsl_rule}).encode())
            
        except Exception as e:
            print(f"Error in convert_rule_with_gemini: {e}")
            # Fallback to simple conversion
            natural_language = data.get('text', '')
            dsl_rule = f'alert tcp any any -> any 80 (msg:"{natural_language}"; content:"test"; priority:1)'
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'dsl_rule': dsl_rule}).encode())
    
    def get_rules(self):
        try:
            rules = []
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, 'r') as f:
                    lines = f.readlines()
                    rule_count = 0
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            rules.append({
                                'id': rule_count,
                                'rule': line,
                                'enabled': True
                            })
                            rule_count += 1
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'rules': rules}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def add_rule(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            rule = data.get('rule', '')
            if not rule:
                self.send_error(400, "No rule provided")
                return
            
            # Add rule to file
            with open(RULES_FILE, 'a') as f:
                f.write(f"\n{rule}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'added'}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def delete_rule(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            rule_id = data.get('id')
            if rule_id is None:
                self.send_error(400, "No rule ID provided")
                return
            
            # Read all rules
            with open(RULES_FILE, 'r') as f:
                lines = f.readlines()
            
            # Remove the specified rule
            new_lines = []
            rule_count = 0
            for line in lines:
                if line.strip() and not line.strip().startswith('#'):
                    if rule_count == rule_id:
                        rule_count += 1
                        continue  # Skip this line (delete it)
                    rule_count += 1
                new_lines.append(line)
            
            # Write back to file
            with open(RULES_FILE, 'w') as f:
                f.writelines(new_lines)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'deleted'}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def update_rule(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            rule_id = data.get('id')
            new_rule = data.get('rule', '')
            
            if rule_id is None or not new_rule:
                self.send_error(400, "Rule ID and new rule required")
                return
            
            # Read all rules
            with open(RULES_FILE, 'r') as f:
                lines = f.readlines()
            
            # Update the specified rule
            new_lines = []
            rule_count = 0
            for line in lines:
                if line.strip() and not line.strip().startswith('#'):
                    if rule_count == rule_id:
                        new_lines.append(f"{new_rule}\n")
                        rule_count += 1
                        continue
                    rule_count += 1
                new_lines.append(line)
            
            # Write back to file
            with open(RULES_FILE, 'w') as f:
                f.writelines(new_lines)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'updated'}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def get_alerts(self):
        try:
            # Read alerts from log file or generate sample alerts
            alerts = []
            
            # Check if alerts.log exists
            if os.path.exists('logs/alerts.log'):
                with open('logs/alerts.log', 'r') as f:
                    alerts = f.readlines()[-10:]  # Last 10 alerts
            else:
                # Generate sample alerts for demonstration
                alerts = [
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: SQL Injection Attempt\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: XSS Attack Detected\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: Port Scan Activity\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: Malicious File Upload\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: Directory Traversal Attempt\n"
                ]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'alerts': alerts}).encode())
        except Exception as e:
            self.send_error(500, str(e))
    
    def get_firewall_alerts(self):
        try:
            firewall_alerts = []
            
            # Check if firewall monitor log exists
            if os.path.exists('logs/firewall_monitor.log'):
                with open('logs/firewall_monitor.log', 'r') as f:
                    firewall_alerts = f.readlines()[-20:]  # Last 20 firewall alerts
            else:
                # Generate sample firewall alerts for demonstration
                firewall_alerts = [
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FIREWALL ALERT: SUSPICIOUS PROCESS - User: root, Command: sudo ufw reset, PID: 1234\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FIREWALL ALERT: ADMIN DANGEROUS COMMAND - Admin user root executed: iptables -F\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FIREWALL ALERT: SUSPICIOUS PROCESS - User: admin, Command: chmod 777 /etc/passwd, PID: 5678\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FIREWALL ALERT: NETWORK INTERFACE - Interface: eth0, IP: 192.168.1.100\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] FIREWALL ALERT: SUSPICIOUS PROCESS - User: user, Command: nmap -sS 192.168.1.0/24, PID: 9012\n"
                ]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'firewall_alerts': firewall_alerts}).encode())
        except Exception as e:
            self.send_error(500, str(e))

def signal_handler(sig, frame):
    print('\nShutting down web server...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    PORT = 8080
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Start firewall monitoring
    firewall_monitor.start_monitoring()
    
    with socketserver.TCPServer(("", PORT), IDSHandler) as httpd:
        print(f"IDS DSL Engine - Web Server")
        print(f"Web Interface: http://localhost:{PORT}")
        print(f"Gemini AI Integration: ENABLED")
        print(f"Rule Management: ENABLED")
        print(f"Monitoring: Ready")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()
