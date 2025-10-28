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
    
    def send_json_response(self, data, status=200):
        """Send JSON response with proper headers"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        # Parse path and query string
        parsed_path = self.path.split('?')[0]
        print(f"GET request: original={self.path}, parsed={parsed_path}")
        
        # Store original path
        original_path = self.path
        self.path = parsed_path
        
        try:
            if parsed_path == '/':
                self.path = '/index.html'
                return super().do_GET()
            elif parsed_path == '/api/rules':
                print("Handling /api/rules request (current/user rules)")
                self.get_user_rules()
                return
            elif parsed_path == '/api/active_rules':
                print("Handling /api/active_rules request (all non-comment rules)")
                self.get_active_rules()
                return
            elif parsed_path == '/api/all_rules':
                print("Handling /api/all_rules request")
                self.get_all_rules()
                return
            elif parsed_path == '/api/get_alerts':
                print("Handling /api/get_alerts request")
                self.get_alerts()
                return
            elif parsed_path == '/api/alerts/stream':
                print("Handling /api/alerts/stream (SSE)")
                self.stream_alerts()
                return
            elif parsed_path == '/api/capture_status':
                print("Handling /api/capture_status request")
                self.capture_status()
                return
            elif parsed_path == '/api/get_firewall_alerts':
                print("Handling /api/get_firewall_alerts request (disabled)")
                self.get_firewall_alerts()
                return
            else:
                # Restore original path for file serving
                self.path = original_path
                return super().do_GET()
        except BrokenPipeError:
            # Client disconnected, ignore
            pass
        except Exception as e:
            print(f"Error in do_GET for path {parsed_path}: {e}")
            import traceback
            traceback.print_exc()
            # Don't send error if we've already started sending a response
            if not self.wfile.closed:
                try:
                    self.send_error(404, f"Path not found: {parsed_path}")
                except:
                    pass
    
    def do_POST(self):
        # Parse path and query string
        parsed_path = self.path.split('?')[0]
        
        if parsed_path == '/api/start_ids':
            self.start_ids()
        elif parsed_path == '/api/stop_ids':
            self.stop_ids()
        elif parsed_path == '/api/convert_rule':
            self.convert_rule_with_gemini()
        elif parsed_path == '/api/add_rule':
            self.add_rule()
        elif parsed_path == '/api/delete_rule':
            self.delete_rule()
        elif parsed_path == '/api/update_rule':
            self.update_rule()
        else:
            self.send_error(404)
    
    def start_ids(self):
        try:
            # Get interface from request
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            interface = data.get('interface', 'any')
            print(f"\n{'='*50}")
            print(f"🚀 Starting IDS engine on interface: {interface}")
            print(f"{'='*50}")
            
            current_dir = os.getcwd()
            
            # Refresh logs on every start
            try:
                os.makedirs('logs', exist_ok=True)
                open('logs/alerts.log', 'w', encoding='utf-8').close()
                open('logs/all_packets.log', 'w', encoding='utf-8').close()
                print("[OK] Logs refreshed: logs/alerts.log, logs/all_packets.log")
            except Exception as e:
                print(f"[WARN] Could not refresh logs: {e}")
            
            # Create minimal active rules for testing from another machine
            try:
                os.makedirs('rules', exist_ok=True)
                with open('rules/active.rules', 'w', encoding='utf-8') as rf:
                    rf.write(
                        "# Active test rules (limited to three)\n"
                        "alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; priority:5)\n"
                        "alert udp any any -> any 53 (msg:\"DNS Query\"; priority:5)\n"
                        "alert icmp any any -> any any (msg:\"ICMP Flood Attack\"; priority:4)\n"
                    )
                print("[OK] Wrote rules/active.rules with 3 test rules")
            except Exception as e:
                print(f"[WARN] Could not write active rules: {e}")
            
            # Try Scapy first (cross-platform, easier to use)
            if os.path.exists('./scapy_capture.py'):
                print(f"✅ Using Scapy-based packet capture")
                if sys.platform == 'win32':
                    cmd = [sys.executable, './scapy_capture.py', interface]
                else:
                    cmd = ['sudo', sys.executable, './scapy_capture.py', interface]
                print(f"Command: {' '.join(cmd)}")
            # Fallback to C engine
            elif os.path.exists('./bin/ids_engine'):
                print(f"✅ Using C-based ids_engine")
                if sys.platform == 'win32':
                    wsl_path = current_dir.replace('\\', '/').replace('C:', '/mnt/c')
                    cmd_str = f'cd {wsl_path} && ./bin/ids_engine -i {interface} -r rules/active.rules'
                    cmd = ['wsl', 'bash', '-c', cmd_str]
                else:
                    cmd = ['./bin/ids_engine', '-i', interface, '-r', 'rules/active.rules']
            else:
                print(f"⚠️  No capture engine found! Please build the project.")
                self.send_error(500, "No capture engine available")
                return
            
            print(f"Starting capture engine...")
            
            # Start IDS engine and log its output
            self.ids_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                shell=False
            )
            
            # Function to read and print process output
            def read_output():
                try:
                    for line in iter(self.ids_process.stdout.readline, ''):
                        if line:
                            print(f"[IDS Engine] {line.rstrip()}")
                    self.ids_process.stdout.close()
                except Exception as e:
                    print(f"Error reading IDS output: {e}")
            
            # Start thread to read output
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
            print(f"✅ IDS engine started with PID: {self.ids_process.pid}")
            print(f"✅ Monitoring output in background thread")
            print(f"{'='*50}\n")
            
            self.send_json_response({'status': 'started', 'interface': interface, 'pid': self.ids_process.pid})
        except Exception as e:
            print(f"\n❌ Error starting IDS: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, str(e))
    
    def stop_ids(self):
        try:
            if hasattr(self, 'ids_process'):
                self.ids_process.terminate()
            
            # Remove active rules file so defaults resume next time
            try:
                active_path = 'rules/active.rules'
                if os.path.exists(active_path):
                    os.remove(active_path)
                    print("[OK] Removed rules/active.rules")
            except Exception as e:
                print(f"[WARN] Could not remove active rules: {e}")
            
            self.send_json_response({'status': 'stopped'})
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
            
            self.send_json_response({'dsl_rule': dsl_rule})
            
        except Exception as e:
            print(f"Error in convert_rule_with_gemini: {e}")
            # Fallback to simple conversion
            natural_language = data.get('text', '')
            dsl_rule = f'alert tcp any any -> any 80 (msg:"{natural_language}"; content:"test"; priority:1)'
            
            self.send_json_response({'dsl_rule': dsl_rule})
    
    def get_user_rules(self):
        try:
            print(f"get_rules called, RULES_FILE={RULES_FILE}, exists={os.path.exists(RULES_FILE)}")
            rules = []
            user_rules = []
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, 'r') as f:
                    lines = f.readlines()
                    rule_count = 0
                    user_rule_count = 0
                    in_user_section = False
                    
                    for line in lines:
                        line_stripped = line.strip()
                        
                        # Check if we've entered the user-added rules section
                        if 'USER-ADDED RULES' in line_stripped:
                            in_user_section = True
                            print("Found USER-ADDED RULES marker")
                            continue
                        
                        # Skip comments and empty lines
                        if line_stripped.startswith('#') or not line_stripped:
                            continue
                        
                        if in_user_section:
                            # This is a user-added rule
                            user_rules.append({
                                'id': user_rule_count,
                                'rule': line_stripped,
                                'enabled': True,
                                'file_index': rule_count
                            })
                            user_rule_count += 1
                        
                        rule_count += 1
                        
            else:
                print(f"WARNING: Rules file {RULES_FILE} does not exist!")
            
            # Debug logging
            print(f"Loaded {len(rules)} total rules, {len(user_rules)} user rules from {RULES_FILE}")
            
            # Return only user-added rules
            self.send_json_response({'rules': user_rules})
        except Exception as e:
            print(f"Error loading rules: {e}")
            import traceback
            traceback.print_exc()
            # Send proper JSON error response
            self.send_json_response({'error': str(e), 'rules': []}, status=500)
    
    def get_active_rules(self):
        try:
            print(f"[get_active_rules] Reading from {RULES_FILE}")
            active = []
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    rule_id = 0
                    for line_num, line in enumerate(f, 1):
                        s = line.strip()
                        if not s or s.startswith('#'):
                            continue
                        active.append({
                            'id': rule_id,
                            'rule': s,
                            'description': self._extract_rule_description(s),
                            'category': self._extract_rule_category(s)
                        })
                        rule_id += 1
                        print(f"[get_active_rules] Added rule #{rule_id}: {s[:50]}...")
            print(f"[get_active_rules] Returning {len(active)} active rules")
            self.send_json_response({'rules': active})
        except Exception as e:
            print(f"[get_active_rules] ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.send_json_response({'error': str(e), 'rules': []}, status=500)
    
    def get_all_rules(self):
        """Get all rules (system + user) with descriptions"""
        try:
            print(f"get_all_rules called, RULES_FILE={RULES_FILE}")
            all_rules = []
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, 'r') as f:
                    lines = f.readlines()
                    rule_count = 0
                    for line in lines:
                        line_stripped = line.strip()
                        
                        # Skip comments (but not rule descriptions in comments)
                        if line_stripped.startswith('#'):
                            continue
                        
                        # Only non-empty lines
                        if line_stripped:
                            all_rules.append({
                                'id': rule_count,
                                'rule': line_stripped,
                                'description': self._extract_rule_description(line_stripped),
                                'category': self._extract_rule_category(line_stripped),
                                'enabled': False  # Need to check if in user section
                            })
                            rule_count += 1
            
            print(f"Loaded {len(all_rules)} total rules from {RULES_FILE}")
            self.send_json_response({'rules': all_rules})
        except Exception as e:
            print(f"Error loading all rules: {e}")
            import traceback
            traceback.print_exc()
            self.send_json_response({'error': str(e), 'rules': []}, status=500)
    
    def _extract_rule_description(self, rule_text):
        """Extract description from rule message"""
        try:
            # Extract message from rule
            if 'msg:' in rule_text:
                start = rule_text.find('msg:"') + 5
                end = rule_text.find('"', start)
                if end > start:
                    return rule_text[start:end]
            return "Security rule"
        except:
            return "Security rule"
    
    def _extract_rule_category(self, rule_text):
        """Extract category from rule"""
        rule_lower = rule_text.lower()
        if 'sql' in rule_lower:
            return 'Web Application Security'
        elif 'xss' in rule_lower or 'iframe' in rule_lower or 'script' in rule_lower:
            return 'Web Application Security'
        elif 'directory' in rule_lower or 'traversal' in rule_lower or '../' in rule_lower:
            return 'Web Application Security'
        elif 'command' in rule_lower or 'pipe' in rule_lower:
            return 'Web Application Security'
        elif 'malicious' in rule_lower or '.exe' in rule_lower or '.php' in rule_lower:
            return 'Malware Detection'
        elif 'port' in rule_lower or 'scan' in rule_lower:
            return 'Network Reconnaissance'
        elif 'icmp' in rule_lower:
            return 'Denial of Service'
        elif 'ssh' in rule_lower or 'brute' in rule_lower or 'force' in rule_lower:
            return 'Authentication Attacks'
        elif 'firewall' in rule_lower or 'iptables' in rule_lower:
            return 'Firewall Monitoring'
        elif 'log' in rule_lower:
            return 'Traffic Monitoring'
        else:
            return 'General Security'
    
    def add_rule(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            rule = data.get('rule', '')
            if not rule:
                self.send_error(400, "No rule provided")
                return
            
            # Add rule to file in the user-added section
            with open(RULES_FILE, 'r') as f:
                content = f.read()
            
            # Append to the end of the file (user section)
            with open(RULES_FILE, 'a') as f:
                f.write(f"\n{rule}")
            
            print(f"Added new rule: {rule}")
            
            self.send_json_response({'status': 'added', 'rule': rule})
        except Exception as e:
            print(f"Error adding rule: {e}")
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
            
            # Read all rules to find user rules
            with open(RULES_FILE, 'r') as f:
                lines = f.readlines()
            
            # Find and delete only user-added rules (after marker)
            new_lines = []
            in_user_section = False
            user_rule_count = 0
            
            for line in lines:
                line_stripped = line.strip()
                
                # Check for user section marker
                if 'USER-ADDED RULES' in line_stripped:
                    in_user_section = True
                    new_lines.append(line)
                    continue
                
                # Skip comments
                if line_stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                # If this is a user rule and it's the one to delete
                if in_user_section and line_stripped and not line_stripped.startswith('#'):
                    if user_rule_count == rule_id:
                        print(f"Deleting user rule #{rule_id}: {line_stripped}")
                        user_rule_count += 1
                        continue  # Skip this line
                    user_rule_count += 1
                
                new_lines.append(line)
            
            # Write back to file
            with open(RULES_FILE, 'w') as f:
                f.writelines(new_lines)
            
            print(f"Successfully deleted user rule #{rule_id}")
            
            self.send_json_response({'status': 'deleted'})
        except Exception as e:
            print(f"Error deleting rule: {e}")
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
            
            # Update only user-added rules (after marker)
            new_lines = []
            in_user_section = False
            user_rule_count = 0
            
            for line in lines:
                line_stripped = line.strip()
                
                # Check for user section marker
                if 'USER-ADDED RULES' in line_stripped:
                    in_user_section = True
                    new_lines.append(line)
                    continue
                
                # Skip comments
                if line_stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                # If this is a user rule and it's the one to update
                if in_user_section and line_stripped and not line_stripped.startswith('#'):
                    if user_rule_count == rule_id:
                        print(f"Updating user rule #{rule_id} to: {new_rule}")
                        new_lines.append(f"{new_rule}\n")
                        user_rule_count += 1
                        continue
                    user_rule_count += 1
                
                new_lines.append(line)
            
            # Write back to file
            with open(RULES_FILE, 'w') as f:
                f.writelines(new_lines)
            
            print(f"Successfully updated user rule #{rule_id}")
            
            self.send_json_response({'status': 'updated'})
        except Exception as e:
            print(f"Error updating rule: {e}")
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
            
            self.send_json_response({'alerts': alerts})
        except Exception as e:
            self.send_error(500, str(e))
    
    def stream_alerts(self):
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            log_path = 'logs/alerts.log'
            # Ensure log file exists
            os.makedirs('logs', exist_ok=True)
            open(log_path, 'a').close()
            
            with open(log_path, 'r') as f:
                # Start at end of file for new alerts
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    data = line.strip().replace('\r', '')
                    msg = f"data: {data}\n\n"
                    try:
                        self.wfile.write(msg.encode('utf-8'))
                        self.wfile.flush()
                    except BrokenPipeError:
                        break
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except:
                pass
    
    def capture_status(self):
        try:
            path = 'logs/alerts.log'
            os.makedirs('logs', exist_ok=True)
            if not os.path.exists(path):
                open(path, 'a').close()
            stat = os.stat(path)
            size = stat.st_size
            mtime = stat.st_mtime
            now = time.time()
            recency_s = now - mtime
            status = 'capturing' if recency_s <= 5 else 'idle'
            self.send_json_response({
                'alerts_log_exists': True,
                'alerts_log_size_bytes': size,
                'alerts_log_mtime_epoch': mtime,
                'seconds_since_last_write': recency_s,
                'status': status
            })
        except Exception as e:
            self.send_json_response({'error': str(e), 'status': 'unknown'}, status=500)
    
    def get_firewall_alerts(self):
        try:
            # Temporarily disabled; return empty list
            self.send_json_response({'firewall_alerts': []})
        except Exception as e:
            self.send_error(500, str(e))

def signal_handler(sig, frame):
    print('\nShutting down web server...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def find_free_port(start_port=8080, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            # Try to bind to the port
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(('', port))
            test_socket.close()
            return port
        except OSError:
            continue
    return None

if __name__ == '__main__':
    import socket
    
    PORT = 8080
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Start firewall monitoring (disabled for now)
    # firewall_monitor.start_monitoring()
    
    # Try to find an available port
    used_port = PORT
    try:
        httpd = socketserver.TCPServer(("", PORT), IDSHandler)
    except OSError as e:
        if e.winerror == 10048 or "Address already in use" in str(e):
            print(f"\n⚠️  Port {PORT} is already in use!")
            print("🔍 Looking for an available port...")
            used_port = find_free_port(start_port=8081)
            if used_port:
                print(f"✅ Found available port: {used_port}")
                httpd = socketserver.TCPServer(("", used_port), IDSHandler)
            else:
                print("❌ Could not find an available port. Please close other applications using ports 8080-8090")
                sys.exit(1)
        else:
            raise
    
    try:
        print(f"\n{'='*60}")
        print(f"IDS DSL Engine - Web Server")
        print(f"{'='*60}")
        print(f"Web Interface: http://localhost:{used_port}")
        print(f"Gemini AI Integration: ENABLED")
        print(f"Rule Management: ENABLED")
        print(f"Monitoring: Ready")
        print(f"{'='*60}")
        print("Press Ctrl+C to stop\n")
        
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down web server...")
        sys.exit(0)
