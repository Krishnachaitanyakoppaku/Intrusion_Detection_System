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

# Gemini API integration
GEMINI_API_KEY = "AIzaSyCK3N6q-3kxwLX0p-kqiEJmxPdxlxN-nZg"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

# Rules file path
RULES_FILE = "rules/local.rules"

class IDSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='web_interface', **kwargs)
    
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        elif self.path == '/api/rules':
            self.get_rules()
            return
        return super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/start_ids':
            self.start_ids()
        elif self.path == '/api/stop_ids':
            self.stop_ids()
        elif self.path == '/api/convert_rule':
            self.convert_rule_with_gemini()
        elif self.path == '/api/get_alerts':
            self.get_alerts()
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
                    for i, line in enumerate(lines):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            rules.append({
                                'id': i,
                                'rule': line,
                                'enabled': True
                            })
            
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
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 ALERT: SQL Injection Attempt\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 ALERT: XSS Attack Detected\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 ALERT: Port Scan Activity\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 ALERT: Malicious File Upload\n",
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 🚨 ALERT: Directory Traversal Attempt\n"
                ]
            
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
    os.chdir('/mnt/c/Users/Charan/Documents/sem-5/cd project/Intrusion_Detection_System')
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    with socketserver.TCPServer(("", PORT), IDSHandler) as httpd:
        print(f"🛡️ IDS DSL Engine - Web Server")
        print(f"🌐 Web Interface: http://localhost:{PORT}")
        print(f"🤖 Gemini AI Integration: ENABLED")
        print(f"📋 Rule Management: ENABLED")
        print(f"📡 Monitoring: Ready")
        print("Press Ctrl+C to stop")
        httpd.serve_forever()
