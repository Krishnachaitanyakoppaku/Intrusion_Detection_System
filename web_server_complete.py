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

# Import firewall parser (C-based Lex/Yacc parser)
try:
    # Try to import the C-based parser wrapper
    firewall_parser_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall')
    sys.path.insert(0, firewall_parser_path)
    from firewall_parser_python import FirewallEventParser
    FIREWALL_PARSER_AVAILABLE = True
    print(" Firewall parser (Lex/Yacc) loaded successfully")
except ImportError as e:
    print(f"  Warning: Firewall parser not available: {e}")
    print("  To build the parser:")
    print("    1. On Linux/WSL: cd firewall && make")
    print("    2. Or: bash firewall/build_parser.sh")
    print("    3. Make sure flex and bison are installed")
    FIREWALL_PARSER_AVAILABLE = False
    FirewallEventParser = None

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
    
    def _get_rules_file(self):
        try:
            active_path = 'rules/active.rules'
            if os.path.exists(active_path):
                return active_path
        except Exception:
            pass
        return RULES_FILE
    
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
                print("Handling /api/get_firewall_alerts request")
                self.get_firewall_alerts()
                return
            elif parsed_path == '/api/firewall_events':
                print("Handling /api/firewall_events request")
                self.get_firewall_events()
                return
            elif parsed_path == '/api/firewall_events/stream':
                print("Handling /api/firewall_events/stream (SSE)")
                self.stream_firewall_events()
                return
            elif parsed_path == '/api/host-ip':
                print("Handling /api/host-ip request (GET)")
                self.get_host_ip()
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
        elif parsed_path == '/api/host-ip':
            self.set_host_ip()
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
            print(f" Starting IDS engine on interface: {interface}")
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
            
            # Try Scapy first (cross-platform, easier to use)
            if os.path.exists('./scapy_capture.py'):
                print(f" Using Scapy-based packet capture")
                if sys.platform == 'win32':
                    cmd = [sys.executable, './scapy_capture.py', interface]
                else:
                    # Check if already running with sudo
                    if os.geteuid() == 0:
                        cmd = [sys.executable, './scapy_capture.py', interface]
                    else:
                        print("⚠️  Please run with sudo to enable packet capture:")
                        print("   sudo python3 web_server_complete.py")
                        print("\nStarting web server anyway (monitoring disabled)...")
                        self.send_json_response({'status': 'started', 'warning': 'Run with sudo for packet capture'})
                        return
                print(f"Command: {' '.join(cmd)}")
            # Fallback to C engine
            elif os.path.exists('./bin/ids_engine'):
                print(f" Using C-based ids_engine")
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
            
            print(f" IDS engine started with PID: {self.ids_process.pid}")
            print(f" Monitoring output in background thread")
            print(f"{'='*50}\n")
            
            self.send_json_response({'status': 'started', 'interface': interface, 'pid': self.ids_process.pid})
        except Exception as e:
            print(f"\n   Error starting IDS: {e}")
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
            
            # Call Gemini API with improved prompt
            prompt = f"""Convert this natural language security rule to IDS DSL syntax:
"{natural_language}"

CRITICAL REQUIREMENTS - You MUST follow this EXACT format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]"; priority:[1-5]);

MANDATORY SYNTAX RULES:
1. MUST end with semicolon (;)
2. Options MUST be inside parentheses: (msg:"..."; priority:...)
3. For ICMP rules: ALWAYS use "any any" for BOTH source and destination ports (ICMP doesn't use ports, but parser requires port fields)
4. For TCP/UDP rules: Use actual port numbers (e.g., 80, 443, 22) or "any"
5. Direction MUST be "->" (not "<>")
6. Protocol must be: tcp, udp, icmp, or ip (lowercase)
7. Use double quotes for msg content: msg:"Your message here"
8. Priority is a number 1-5 (1=highest, 5=lowest)

EXAMPLES (copy this exact format):

For ICMP Ping:
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3);

For HTTP (port 80):
alert tcp any any -> any 80 (msg:"Incoming HTTP Request to Host"; priority:5);

For SSH (port 22):
alert tcp any any -> any 22 (msg:"Incoming SSH Connection Attempt"; priority:3);

For DNS (port 53 UDP):
alert udp any any -> any 53 (msg:"Incoming DNS Query to Host"; priority:5);

For HTTPS (port 443):
alert tcp any any -> any 443 (msg:"Incoming HTTPS Request to Host"; priority:5);

IMPORTANT: If the request mentions "ICMP", "ping", or "icmp", you MUST use:
alert icmp any any -> any any (msg:"..."; priority:...);

Return ONLY the complete rule in the exact format above. No explanations, no markdown, just the rule text ending with semicolon."""
            
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
                    # Clean up the response - remove markdown code blocks
                    dsl_rule = dsl_rule.replace('```', '').replace('```dsl', '').replace('```plaintext', '').replace('dsl', '').strip()
                    
                    # Validate and fix the rule if needed
                    dsl_rule = self._validate_and_fix_rule(dsl_rule, natural_language)
                else:
                    dsl_rule = self._create_fallback_rule(natural_language)
            else:
                print(f"Gemini API error: {response.status_code}")
                dsl_rule = self._create_fallback_rule(natural_language)
            
            # Check if this rule or similar rule exists in local.rules
            rule_check_result = self._check_rule_in_local_rules(dsl_rule, natural_language)
            
            # If exact match or similar rule with same protocol+port found, use the rule from local.rules instead
            if rule_check_result['exact_match']:
                dsl_rule = rule_check_result['exact_match']['rule']
                print(f"[Gemini] Using existing rule from local.rules (line {rule_check_result['exact_match']['line_number']})")
            
            # Return rule with check results
            response_data = {
                'dsl_rule': dsl_rule,
                'exists_in_local': rule_check_result['exists'],
                'exact_match': rule_check_result['exact_match'],
                'similar_rules': rule_check_result['similar_rules'],
                'suggestions': rule_check_result['suggestions'],
                'test_instruction': rule_check_result.get('test_instruction')
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            print(f"Error in convert_rule_with_gemini: {e}")
            import traceback
            traceback.print_exc()
            # Fallback to smart conversion based on input
            natural_language = data.get('text', '')
            dsl_rule = self._create_fallback_rule(natural_language)
            
            # Check if rule exists in local.rules
            rule_check_result = self._check_rule_in_local_rules(dsl_rule, natural_language)
            
            # If exact match or similar rule with same protocol+port found, use the rule from local.rules instead
            if rule_check_result['exact_match']:
                dsl_rule = rule_check_result['exact_match']['rule']
                print(f"[Gemini] Using existing rule from local.rules (line {rule_check_result['exact_match']['line_number']})")
            
            response_data = {
                'dsl_rule': dsl_rule,
                'exists_in_local': rule_check_result['exists'],
                'exact_match': rule_check_result['exact_match'],
                'similar_rules': rule_check_result['similar_rules'],
                'suggestions': rule_check_result['suggestions'],
                'test_instruction': rule_check_result.get('test_instruction')
            }
            
            self.send_json_response(response_data)
    
    def _validate_and_fix_rule(self, rule, natural_language=""):
        """Validate and auto-fix rule syntax"""
        import re
        
        # Remove any leading/trailing whitespace
        rule = rule.strip()
        
        # Remove markdown code blocks if present
        rule = re.sub(r'```[a-z]*\n?', '', rule)
        rule = rule.strip()
        
        # Check if it's already valid format
        valid_pattern = r'^alert\s+(tcp|udp|icmp|ip)\s+'
        if not re.match(valid_pattern, rule, re.IGNORECASE):
            # Try to create a proper rule
            return self._create_fallback_rule(natural_language)
        
        # Fix ICMP rules - ensure ports are "any any"
        if 'icmp' in rule.lower():
            # Pattern: alert icmp [anything] -> [anything]
            rule = re.sub(r'alert\s+icmp\s+(\S+)\s+(\S+)\s*->\s*(\S+)\s+(\S+)', 
                        r'alert icmp any any -> \3 any', rule, flags=re.IGNORECASE)
            rule = re.sub(r'alert\s+icmp\s+(\S+)\s*->\s*(\S+)', 
                        r'alert icmp any any -> \2 any', rule, flags=re.IGNORECASE)
        
        # Ensure semicolon at end
        if not rule.endswith(';'):
            rule = rule.rstrip() + ';'
        
        # Ensure parentheses around options
        if '(' not in rule or ')' not in rule:
            # Try to add basic options if missing
            if '(msg:' not in rule.lower():
                rule = rule.replace(';', ' (msg:"' + natural_language + '"; priority:3);')
        
        return rule
    
    def _create_fallback_rule(self, natural_language):
        """Create a fallback rule based on natural language input"""
        natural_lower = natural_language.lower()
        
        # Detect ICMP/ping
        if 'icmp' in natural_lower or 'ping' in natural_lower:
            return f'alert icmp any any -> any any (msg:"{natural_language}"; priority:3);'
        
        # Detect SSH
        if 'ssh' in natural_lower:
            return f'alert tcp any any -> any 22 (msg:"{natural_language}"; priority:3);'
        
        # Detect HTTP
        if 'http' in natural_lower and 'https' not in natural_lower:
            return f'alert tcp any any -> any 80 (msg:"{natural_language}"; priority:5);'
        
        # Detect HTTPS
        if 'https' in natural_lower:
            return f'alert tcp any any -> any 443 (msg:"{natural_language}"; priority:5);'
        
        # Detect DNS
        if 'dns' in natural_lower:
            return f'alert udp any any -> any 53 (msg:"{natural_language}"; priority:5);'
        
        # Default to HTTP
        return f'alert tcp any any -> any 80 (msg:"{natural_language}"; priority:3);'
    
    def _check_rule_in_local_rules(self, generated_rule, natural_language):
        """Check if generated rule exists in local.rules or find similar rules"""
        import re
        
        result = {
            'exists': False,
            'exact_match': None,
            'similar_rules': [],
            'suggestions': [],
            'test_instruction': None
        }
        
        try:
            rules_path = 'rules/local.rules'
            if not os.path.exists(rules_path):
                result['suggestions'].append("Rules file not found. The generated rule can be added as a new rule.")
                return result
            
            # Parse the generated rule to extract key components
            generated_protocol = None
            generated_port = None
            generated_msg = None
            
            # Extract protocol
            protocol_match = re.search(r'alert\s+(tcp|udp|icmp|ip)\s+', generated_rule, re.IGNORECASE)
            if protocol_match:
                generated_protocol = protocol_match.group(1).lower()
            
            # Extract destination port
            port_match = re.search(r'->\s+\S+\s+(\d+|any)', generated_rule, re.IGNORECASE)
            if port_match:
                generated_port = port_match.group(1)
            
            # Extract message
            msg_match = re.search(r'msg:"([^"]+)"', generated_rule)
            if msg_match:
                generated_msg = msg_match.group(1).lower()
            
            # Extract keywords from natural language
            natural_lower = natural_language.lower()
            keywords = set(re.findall(r'\b\w+\b', natural_lower))
            
            # Load and compare with local.rules
            with open(rules_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                rule_count = 0
                prev_comment = None
                
                for line in lines:
                    line_stripped = line.strip()
                    
                    # Check if this is a test instruction comment
                    if line_stripped.startswith('#') and 'test:' in line_stripped.lower():
                        prev_comment = line_stripped
                        continue
                    
                    # Skip other comments and empty lines
                    if line_stripped.startswith('#') or not line_stripped:
                        if not line_stripped:  # Empty line resets comment
                            prev_comment = None
                        continue
                    
                    # Check for exact match (normalized comparison - ignore semicolons and whitespace)
                    rule_normalized = re.sub(r'\s+', ' ', line_stripped).strip().rstrip(';').rstrip()
                    generated_normalized = re.sub(r'\s+', ' ', generated_rule).strip().rstrip(';').rstrip()
                    
                    if rule_normalized.lower() == generated_normalized.lower():
                        result['exists'] = True
                        result['exact_match'] = {
                            'rule': line_stripped.rstrip(';') + ';' if not line_stripped.rstrip().endswith(';') else line_stripped,
                            'line_number': rule_count + 1
                        }
                        result['test_instruction'] = prev_comment if prev_comment else None
                        result['suggestions'].append(f" Exact match found in local.rules (line {rule_count + 1}). You can add this existing rule to active.rules.")
                        return result
                    
                    # Extract existing rule components first (needed for semantic matching)
                    existing_protocol = None
                    existing_port = None
                    existing_msg = None
                    
                    proto_match = re.search(r'alert\s+(tcp|udp|icmp|ip)\s+', line_stripped, re.IGNORECASE)
                    if proto_match:
                        existing_protocol = proto_match.group(1).lower()
                    
                    port_match = re.search(r'->\s+\S+\s+(\d+|any)', line_stripped, re.IGNORECASE)
                    if port_match:
                        existing_port = port_match.group(1)
                    
                    msg_match = re.search(r'msg:"([^"]+)"', line_stripped)
                    if msg_match:
                        existing_msg = msg_match.group(1).lower()
                    
                    # Check for semantic match: same protocol, port, and similar message meaning
                    # Normalize message text for comparison (remove "Incoming", "Request to Host", etc.)
                    rule_msg_normalized = existing_msg.lower() if existing_msg else ""
                    generated_msg_normalized = generated_msg.lower() if generated_msg else ""
                    
                    # Remove common prefixes/suffixes for better matching
                    prefixes_to_remove = ["incoming ", "incoming", "detect ", "detect", "detecting ", "detecting"]
                    for prefix in prefixes_to_remove:
                        if rule_msg_normalized.startswith(prefix):
                            rule_msg_normalized = rule_msg_normalized[len(prefix):].strip()
                        if generated_msg_normalized.startswith(prefix):
                            generated_msg_normalized = generated_msg_normalized[len(prefix):].strip()
                    
                    suffixes_to_remove = [" to host", " to host.", " detected", " detected.", " request", " request.", 
                                          " connection attempt", " connection", " query", " query to host"]
                    for suffix in suffixes_to_remove:
                        if rule_msg_normalized.endswith(suffix):
                            rule_msg_normalized = rule_msg_normalized[:-len(suffix)].strip()
                        if generated_msg_normalized.endswith(suffix):
                            generated_msg_normalized = generated_msg_normalized[:-len(suffix)].strip()
                    
                    # Extract core keywords (protocol names and key terms)
                    rule_keywords = set(re.findall(r'\b\w+\b', rule_msg_normalized))
                    generated_keywords = set(re.findall(r'\b\w+\b', generated_msg_normalized))
                    
                    # Check if protocol, port match
                    protocol_match = generated_protocol and existing_protocol and generated_protocol == existing_protocol
                    port_match = generated_port and existing_port and generated_port == existing_port
                    msg_similar = False
                    
                    if protocol_match and port_match:
                        # If protocol and port match, check message similarity
                        # Core keywords that indicate same purpose
                        core_keywords = {'http', 'https', 'ssh', 'dns', 'icmp', 'ping', 'traffic', 'connection', 
                                        'query', 'attack', 'request', 'brute', 'force', 'icmp', 'udp', 'tcp'}
                        
                        # Check keyword overlap
                        if rule_keywords and generated_keywords:
                            overlap = rule_keywords.intersection(generated_keywords)
                            # Match if core protocol keywords overlap OR if messages are very similar
                            if overlap.intersection(core_keywords):
                                msg_similar = True
                            elif len(overlap) >= 2:  # At least 2 words match
                                msg_similar = True
                        
                        # Special case: if protocol+port match and no conflicting keywords, assume match
                        # (e.g., "HTTPS Traffic" matches "Incoming HTTPS Request to Host")
                        if not msg_similar:
                            # Check if both messages contain the protocol name
                            protocol_in_rule_msg = generated_protocol in rule_msg_normalized or generated_protocol in existing_msg.lower()
                            protocol_in_gen_msg = generated_protocol in generated_msg_normalized or generated_protocol in generated_msg.lower()
                            if protocol_in_rule_msg and protocol_in_gen_msg:
                                msg_similar = True
                    
                    # If protocol, port, and message are similar, treat as match
                    if protocol_match and port_match and msg_similar:
                        result['exists'] = True
                        result['exact_match'] = {
                            'rule': line_stripped.rstrip(';') + ';' if not line_stripped.rstrip().endswith(';') else line_stripped,
                            'line_number': rule_count + 1
                        }
                        result['test_instruction'] = prev_comment if prev_comment else None
                        result['suggestions'].append(f" Matching rule found in local.rules (line {rule_count + 1}): Same protocol ({existing_protocol}), port ({existing_port}), and similar purpose.")
                        # Don't return yet - continue to find exact text match if exists
                    
                    # Extract existing rule components (only if not already matched)
                    if not result['exact_match']:
                        proto_match = re.search(r'alert\s+(tcp|udp|icmp|ip)\s+', line_stripped, re.IGNORECASE)
                        if proto_match:
                            existing_protocol = proto_match.group(1).lower()
                        
                        port_match = re.search(r'->\s+\S+\s+(\d+|any)', line_stripped, re.IGNORECASE)
                        if port_match:
                            existing_port = port_match.group(1)
                        
                        msg_match = re.search(r'msg:"([^"]+)"', line_stripped)
                        if msg_match:
                            existing_msg = msg_match.group(1).lower()
                        
                        # Check similarity - STRICT: Must match protocol AND port
                        is_similar = False
                        if generated_protocol and existing_protocol and generated_protocol == existing_protocol:
                            if generated_port and existing_port and generated_port == existing_port:
                                # Protocol AND port match - this is a relevant similar rule
                                is_similar = True
                        
                        # Only add if both protocol and port match
                        if is_similar:
                            result['similar_rules'].append({
                                'rule': line_stripped,
                                'line_number': rule_count + 1,
                                'protocol': existing_protocol,
                                'port': existing_port,
                                'test_instruction': prev_comment if prev_comment else None
                            })
                    
                    rule_count += 1
                    prev_comment = None  # Reset after processing rule
            
            # Generate suggestions based on results
            if result['exact_match']:
                result['suggestions'].append(f" This rule already exists in local.rules (line {result['exact_match']['line_number']}). You can add it directly to active.rules.")
            elif result['similar_rules']:
                # Found rules with same protocol and port - use the first one from local.rules
                best_match = result['similar_rules'][0]
                result['suggestions'].append(f" Found matching rule in local.rules (same protocol {best_match['protocol']} and port {best_match['port']}):")
                result['suggestions'].append(f"  • Line {best_match['line_number']}: {best_match['rule']}")
                result['suggestions'].append("💡 This existing rule will be used instead of the generated one.")
                # Set this as the rule to use
                if 'exact_match' not in result or not result['exact_match']:
                    result['exists'] = True
                    result['exact_match'] = {
                        'rule': best_match['rule'],
                        'line_number': best_match['line_number']
                    }
                    # Get test instruction for the matched rule (need to find it in similar_rules)
                    if 'test_instruction' in best_match:
                        result['test_instruction'] = best_match.get('test_instruction')
            else:
                result['suggestions'].append("  No matching rule found in local.rules (same protocol and port).")
                result['suggestions'].append("💡 This rule doesn't exist yet. You can:")
                result['suggestions'].append("   1. Add it as a new rule (if it's valid)")
                result['suggestions'].append("   2. Refine your prompt to match an existing rule")
                result['suggestions'].append("   3. Check 'All Rules Library' to see available rules")
                
        except Exception as e:
            print(f"Error checking rule in local.rules: {e}")
            import traceback
            traceback.print_exc()
            result['suggestions'].append(f"⚠️ Error checking rules file: {str(e)}")
        
        return result
    
    def get_user_rules(self):
        try:
            # Use same logic as get_active_rules - read from active.rules if it exists
            rules_path = self._get_rules_file()
            print(f"get_user_rules called, reading from {rules_path}")
            user_rules = []
            
            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    rule_count = 0
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
                        
                        # If in user section, only add those. Otherwise add all non-comment rules
                        if in_user_section:
                            # This is a user-added rule
                            user_rules.append({
                                'id': rule_count,
                                'rule': line_stripped,
                                'enabled': True,
                                'file_index': rule_count
                            })
                        else:
                            # No user section marker, so add all rules
                            user_rules.append({
                                'id': rule_count,
                                'rule': line_stripped,
                                'enabled': True,
                                'file_index': rule_count
                            })
                        
                        rule_count += 1
            else:
                print(f"WARNING: Rules file {rules_path} does not exist!")
            
            # Debug logging
            print(f"Loaded {len(user_rules)} rules from {rules_path}")
            
            # Return all rules from the file
            self.send_json_response({'rules': user_rules})
        except Exception as e:
            print(f"Error loading rules: {e}")
            import traceback
            traceback.print_exc()
            # Send proper JSON error response
            self.send_json_response({'error': str(e), 'rules': []}, status=500)
    
    def get_active_rules(self):
        try:
            rules_path = self._get_rules_file()
            print(f"[get_active_rules] Reading from {rules_path}")
            active = []
            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    rule_id = 0
                    prev_comment = None
                    
                    for i, line in enumerate(lines):
                        s = line.strip()
                        if not s:
                            prev_comment = None  # Reset on empty lines
                            continue
                        if s.startswith('#'):
                            # Check if it contains "Test:" - this is a test instruction
                            if 'test:' in s.lower():
                                prev_comment = s
                            continue
                        active.append({
                            'id': rule_id,
                            'rule': s,
                            'description': self._extract_rule_description(s),
                            'category': self._extract_rule_category(s),
                            'test_instruction': prev_comment if prev_comment else None
                        })
                        rule_id += 1
                        print(f"[get_active_rules] Added rule #{rule_id}: {s[:50]}...")
                        prev_comment = None  # Reset after using it
            print(f"[get_active_rules] Returning {len(active)} active rules")
            self.send_json_response({'rules': active})
        except Exception as e:
            print(f"[get_active_rules] ERROR: {e}")
            import traceback
            traceback.print_exc()
            self.send_json_response({'error': str(e), 'rules': []}, status=500)
    
    def get_all_rules(self):
        """Get all rules (system + user) with descriptions and test instructions"""
        try:
            rules_path = self._get_rules_file()
            print(f"get_all_rules called, rules_path={rules_path}")
            all_rules = []
            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    rule_count = 0
                    prev_comment = None
                    
                    for i, line in enumerate(lines):
                        line_stripped = line.strip()
                        
                        # Check if this is a comment line with test instructions
                        if line_stripped.startswith('#'):
                            # Check if it contains "Test:" - this is a test instruction
                            if 'test:' in line_stripped.lower():
                                prev_comment = line_stripped
                            continue
                        
                        # Only non-empty lines (actual rules)
                        if line_stripped:
                            all_rules.append({
                                'id': rule_count,
                                'rule': line_stripped,
                                'description': self._extract_rule_description(line_stripped),
                                'category': self._extract_rule_category(line_stripped),
                                'test_instruction': prev_comment if prev_comment else None,
                                'enabled': False
                            })
                            rule_count += 1
                            prev_comment = None  # Reset after using it
            
            print(f"Loaded {len(all_rules)} total rules from {rules_path}")
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
            test_instruction = data.get('test_instruction', None)
            
            if not rule:
                self.send_error(400, "No rule provided")
                return
            
            # Use the active rules file
            rules_path = self._get_rules_file()
            
            # Append to the end of the file with test instruction if available
            with open(rules_path, 'a', encoding='utf-8') as f:
                if test_instruction:
                    # Ensure test instruction has # prefix if it doesn't
                    if not test_instruction.strip().startswith('#'):
                        test_instruction = '# ' + test_instruction.strip()
                    f.write(f"\n{test_instruction}")
                f.write(f"\n{rule}")
            
            print(f"Added new rule to {rules_path}: {rule}")
            if test_instruction:
                print(f"  With test instruction: {test_instruction}")
            
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
            
            # Use the active rules file
            rules_path = self._get_rules_file()
            
            # Read all rules
            with open(rules_path, 'r') as f:
                lines = f.readlines()
            
            # Find and delete the rule by ID
            new_lines = []
            rule_count = 0
            
            for line in lines:
                line_stripped = line.strip()
                
                # Skip comments
                if line_stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                # If this is the rule to delete
                if line_stripped:  # Non-empty line
                    if rule_count == rule_id:
                        print(f"Deleting rule #{rule_id}: {line_stripped}")
                        rule_count += 1
                        continue  # Skip this line
                    rule_count += 1
                
                new_lines.append(line)
            
            # Write back to file
            with open(rules_path, 'w') as f:
                f.writelines(new_lines)
            
            print(f"Successfully deleted rule #{rule_id}")
            
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
            
            # Use the active rules file
            rules_path = self._get_rules_file()
            
            # Read all rules
            with open(rules_path, 'r') as f:
                lines = f.readlines()
            
            # Update the rule by ID
            new_lines = []
            rule_count = 0
            
            for line in lines:
                line_stripped = line.strip()
                
                # Skip comments
                if line_stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                # If this is the rule to update
                if line_stripped:  # Non-empty line
                    if rule_count == rule_id:
                        print(f"Updating rule #{rule_id} to: {new_rule}")
                        new_lines.append(f"{new_rule}\n")
                        rule_count += 1
                        continue
                    rule_count += 1
                
                new_lines.append(line)
            
            # Write back to file
            with open(rules_path, 'w') as f:
                f.writelines(new_lines)
            
            print(f"Successfully updated rule #{rule_id}")
            
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
    
    def get_host_ip(self):
        """Get saved host IP address from config file"""
        try:
            # Use absolute path to avoid failures when server is started
            # from a different working directory (e.g., service/shortcut)
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(base_dir, '.ids_host_ip')
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    ip = f.read().strip()
                    if ip:
                        self.send_json_response({'ip': ip, 'success': True})
                        return
            self.send_json_response({'ip': None, 'success': True})
        except Exception as e:
            print(f"Error reading host IP: {e}")
            self.send_json_response({'ip': None, 'success': False, 'error': str(e)})
    
    def set_host_ip(self):
        """Save host IP address to config file"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            ip = data.get('ip', '').strip()
            if not ip:
                self.send_json_response({'success': False, 'error': 'No IP address provided'})
                return
            
            # Validate IP format
            import re
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if not re.match(ip_pattern, ip):
                self.send_json_response({'success': False, 'error': 'Invalid IP format'})
                return
            
            # Validate octets
            octets = ip.split('.')
            if not all(0 <= int(octet) <= 255 for octet in octets):
                self.send_json_response({'success': False, 'error': 'Invalid IP: octets must be 0-255'})
                return
            
            # Save to config file (absolute path to be robust against CWD)
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(base_dir, '.ids_host_ip')
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(ip)
            
            print(f"[OK] Host IP saved to config file: {ip}")
            self.send_json_response({'success': True, 'ip': ip})
        except Exception as e:
            print(f"Error saving host IP: {e}")
            import traceback
            traceback.print_exc()
            self.send_json_response({'success': False, 'error': str(e)})
    
    def get_firewall_alerts(self):
        try:
            # Use the new firewall parser if available
            if FIREWALL_PARSER_AVAILABLE:
                parser = FirewallEventParser()
                events = parser.get_recent_events(count=100)
                self.send_json_response({'firewall_alerts': events})
            else:
                self.send_json_response({'firewall_alerts': []})
        except Exception as e:
            print(f"Error getting firewall alerts: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500, str(e))
    
    def get_firewall_events(self):
        """Get parsed firewall events"""
        try:
            if not FIREWALL_PARSER_AVAILABLE:
                self.send_json_response({
                    'events': [], 
                    'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}},
                    'error': 'Firewall parser not available. Build it with: cd firewall && make'
                })
                return
            
            try:
                parser = FirewallEventParser()
            except Exception as init_error:
                self.send_json_response({
                    'events': [], 
                    'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}},
                    'error': f'Parser initialization failed: {init_error}. Build library: cd firewall && make'
                })
                return
            
            # Get query parameters
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            count = int(query_params.get('count', [50])[0])
            severity_filter = query_params.get('severity', [None])[0]
            
            if severity_filter == 'critical':
                events = parser.get_critical_events()
            else:
                events = parser.get_recent_events(count=count)
            
            stats = parser.get_stats()
            
            self.send_json_response({
                'events': events,
                'stats': stats,
                'total': len(events)
            })
        except Exception as e:
            print(f"Error getting firewall events: {e}")
            import traceback
            traceback.print_exc()
            self.send_json_response({
                'events': [], 
                'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}},
                'error': str(e)
            }, status=500)
    
    def stream_firewall_events(self):
        """Stream firewall events using Server-Sent Events"""
        try:
            if not FIREWALL_PARSER_AVAILABLE:
                self.send_error(503, "Firewall parser not available")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            parser = FirewallEventParser()
            log_path = parser.log_file
            
            # Ensure log file exists
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            if not os.path.exists(log_path):
                open(log_path, 'a').close()
            
            last_position = 0
            if os.path.exists(log_path):
                last_position = os.path.getsize(log_path)
            
            while True:
                try:
                    if os.path.exists(log_path):
                        current_size = os.path.getsize(log_path)
                        if current_size > last_position:
                            # New data available, read new lines
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                f.seek(last_position)
                                new_lines = f.readlines()
                                last_position = current_size
                                
                                # Parse new lines for firewall events
                                for line in new_lines:
                                    event = parser.parse_log_line(line)
                                    if event:
                                        event_json = json.dumps(event)
                                        msg = f"data: {event_json}\n\n"
                                        try:
                                            self.wfile.write(msg.encode('utf-8'))
                                            self.wfile.flush()
                                        except BrokenPipeError:
                                            return
                    
                    time.sleep(1)  # Check every second
                except BrokenPipeError:
                    break
                except Exception as e:
                    print(f"Error in firewall event stream: {e}")
                    time.sleep(2)
                    
        except Exception as e:
            print(f"Error setting up firewall event stream: {e}")
            try:
                self.send_error(500, str(e))
            except:
                pass

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
                print(f" Found available port: {used_port}")
                httpd = socketserver.TCPServer(("", used_port), IDSHandler)
            else:
                print("  Could not find an available port. Please close other applications using ports 8080-8090")
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
        
        # Show sudo requirement notice
        if sys.platform != 'win32' and os.geteuid() != 0:
            print(f"{'='*60}")
            print("⚠️  NOTE: Packet capture requires sudo privileges")
            print("   You'll be prompted for password when starting engine")
            print("   Or run this script with: sudo python3 web_server_complete.py")
        
        print(f"{'='*60}")
        print("Press Ctrl+C to stop\n")
        
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down web server...")
        sys.exit(0)
