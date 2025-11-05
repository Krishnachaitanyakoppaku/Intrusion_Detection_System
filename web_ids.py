#!/usr/bin/env python3
import http.server
import socketserver
import os
import subprocess
import json
import threading
import time
import sys
import importlib
import re
import pathlib

# Optional Gemini integration (restored)
try:
    import google.generativeai as genai  # type: ignore
except Exception:
    genai = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
ALERTS_LOG = os.path.join(LOGS_DIR, 'alerts.log')
PACKETS_LOG = os.path.join(LOGS_DIR, 'all_packets.log')
ACTIVE_RULES = os.path.join(BASE_DIR, 'rules', 'active.rules')
LOCAL_RULES = os.path.join(BASE_DIR, 'rules', 'local.rules')
FIREWALL_DIR = os.path.join(BASE_DIR, 'firewall')
FIREWALL_LOG = os.path.join(FIREWALL_DIR, 'logs', 'firewall.log')

# Gemini API integration (same as web_server_complete.py)
GEMINI_API_KEY = "AIzaSyApvXNq995-ko9v0KaxWDhDEufVtHNCGHI"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

# Optional: firewall parser integration (Lex/Yacc-based) if built
FIREWALL_PARSER_AVAILABLE = False
FIREWALL_MODULE = None

# Eager import removed to avoid crashes at startup. We'll lazy-load in the endpoint.

def build_firewall_parser():
    """Auto-build firewall parser if not already built"""
    lib_path = os.path.join(BASE_DIR, 'build', 'firewall', 'libfirewall_parser.so')
    if os.path.exists(lib_path):
        return True
    
    print("[INFO] Firewall parser not found. Attempting to build...")
    try:
        if sys.platform == 'win32':
            # Build in WSL
            wsl_path = FIREWALL_DIR.replace('\\', '/').replace('C:', '/mnt/c')
            cmd = ['wsl', 'bash', '-lc', f"cd '{wsl_path}' && make clean && make"]
        else:
            # Build natively
            clean_cmd = ['make', '-C', FIREWALL_DIR, 'clean']
            subprocess.run(clean_cmd, check=False, cwd=BASE_DIR, capture_output=True)
            cmd = ['make', '-C', FIREWALL_DIR]
        
        result = subprocess.run(cmd, check=False, cwd=BASE_DIR, capture_output=True, text=True)
        if result.returncode == 0 and os.path.exists(lib_path):
            print("[OK] Firewall parser built successfully!")
            return True
        else:
            print(f"[WARN] Firewall parser build returned code {result.returncode}")
            if result.stderr:
                print(f"  Build error: {result.stderr[:200]}")
    except Exception as e:
        print(f"[WARN] Could not build firewall parser: {e}")
    
    return False

# Try to import firewall parser, auto-build if needed
try:
    sys.path.insert(0, FIREWALL_DIR)
    import firewall_parser_python as firewall_module  # type: ignore
    FIREWALL_MODULE = firewall_module
    # Try to initialize and test the parser
    try:
        parser = FIREWALL_MODULE.FirewallEventParser()
        # Test if parser works
        _ = parser.get_recent_events(1)
        FIREWALL_PARSER_AVAILABLE = True
        print("[OK] Firewall parser loaded and working!")
    except Exception as e:
        # Parser library might not be built yet, try building
        print(f"[INFO] Firewall parser import failed: {e}")
        if build_firewall_parser():
            # Retry after build
            try:
                # Reload might need module reload, but try fresh initialization
                import importlib
                FIREWALL_MODULE = importlib.import_module('firewall_parser_python')
                parser = FIREWALL_MODULE.FirewallEventParser()
                _ = parser.get_recent_events(1)
                FIREWALL_PARSER_AVAILABLE = True
                print("[OK] Firewall parser loaded after build!")
            except Exception as e2:
                print(f"[WARN] Firewall parser still not working after build: {e2}")
                FIREWALL_PARSER_AVAILABLE = False
        else:
            FIREWALL_PARSER_AVAILABLE = False
except Exception as e:
    # Import failed, try building first
    print(f"[INFO] Could not import firewall parser: {e}")
    if build_firewall_parser():
        # Retry import after build
        try:
            import importlib
            FIREWALL_MODULE = importlib.import_module('firewall_parser_python')
            parser = FIREWALL_MODULE.FirewallEventParser()
            _ = parser.get_recent_events(1)
            FIREWALL_PARSER_AVAILABLE = True
            print("[OK] Firewall parser loaded after build!")
        except Exception as e2:
            print(f"[WARN] Firewall parser still not working: {e2}")
            FIREWALL_PARSER_AVAILABLE = False
    else:
        FIREWALL_PARSER_AVAILABLE = False


def _naive_parse_firewall_log(log_path: str, max_lines: int = 200):
    """Very simple fallback parser for firewall.log when C parser isn't available.
    Detects common firewall-related commands and returns event dicts.
    """
    events = []
    if not os.path.exists(log_path):
        return events
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-max_lines:]
        for line in lines:
            s = line.strip()
            if not s:
                continue
            sev = 'medium'
            etype = 'unknown'
            desc = s
            cmd = ''
            lower = s.lower()
            if 'ufw' in lower and 'reset' in lower:
                etype = 'ufw_reset'; sev = 'high'
            elif 'ufw' in lower and 'disable' in lower:
                etype = 'ufw_disable'; sev = 'high'
            elif 'ufw' in lower and ('allow' in lower or 'deny' in lower or 'enable' in lower):
                etype = 'ufw_rule_change'; sev = 'medium'
            elif 'firewall-cmd' in lower and ('--reload' in lower or ' --add-' in lower or ' --remove-' in lower):
                etype = 'firewall_reload'; sev = 'medium'
            elif 'systemctl' in lower and ('firewalld' in lower) and ('stop' in lower or 'disable' in lower):
                etype = 'firewall_stop'; sev = 'high'
            elif 'iptables' in lower and (' -f' in lower or ' --flush' in lower):
                etype = 'iptables_flush'; sev = 'high'
            elif 'iptables' in lower and (' -d ' in lower or ' -x ' in lower or ' -dport ' in lower or ' -a ' in lower or ' -d ' in lower):
                etype = 'iptables_rule_change'; sev = 'medium'
            elif re.search(r'\bchmod\s+777\b', lower):
                etype = 'chmod_dangerous'; sev = 'critical'

            # Try to extract command after markers like 'executed:', 'COMMAND=', etc.
            m = re.search(r'(COMMAND=|executed:|command:)(.*)$', s, flags=re.IGNORECASE)
            if m:
                cmd = m.group(2).strip()

            # Extract timestamp [YYYY-MM-DD HH:MM:SS]
            ts = ''
            mts = re.search(r'\[(.*?)\]', s)
            if mts:
                ts = mts.group(1)

            # Extract hostname as first token after timestamp bracket
            host = ''
            parts = re.split(r'\]\\s*', s, maxsplit=1)
            if len(parts) == 2:
                rest = parts[1].strip()
                host = rest.split()[0] if rest else ''

            events.append({
                'timestamp': ts,
                'event_type': etype,
                'severity': sev,
                'description': desc,
                'hostname': host,
                'command': cmd,
                'raw_line': s,
            })
    except Exception:
        return []
    return events


class IDSManager:
    """Manages Scapy capture and IDS engine analyzer without touching existing server."""

    def __init__(self):
        self.capture_proc = None
        self.analyzer_thread = None
        self.analyzer_stop = threading.Event()

    def refresh_logs(self):
        os.makedirs(LOGS_DIR, exist_ok=True)
        open(ALERTS_LOG, 'w', encoding='utf-8').close()
        open(PACKETS_LOG, 'w', encoding='utf-8').close()

    def start_capture(self, interface: str | None):
        # Prefer our lightweight capture if present, else fallback to existing
        script = os.path.join(BASE_DIR, 'scapy_capture_ids.py') if os.path.exists(os.path.join(BASE_DIR, 'scapy_capture_ids.py')) else os.path.join(BASE_DIR, 'scapy_capture.py')
        # Prefer explicit interface; if "any" or empty on Windows, omit iface arg to let Scapy choose
        cmd = [sys.executable, script]
        if interface and interface.lower() != 'any':
            cmd.append(interface)
        self.capture_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            bufsize=1,
            cwd=BASE_DIR,
        )

    def stop_capture(self):
        if self.capture_proc and self.capture_proc.poll() is None:
            try:
                self.capture_proc.terminate()
                try:
                    self.capture_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.capture_proc.kill()
            except Exception:
                pass
        self.capture_proc = None

    def _run_analyzer_once(self):
        # Use compiled analyzer if present
        analyzer_path = os.path.join(BASE_DIR, 'bin', 'packet_analyzer')
        if os.path.exists(analyzer_path):
            try:
                if sys.platform == 'win32':
                    # Run analyzer in WSL so the Linux binary executes
                    wsl_path = BASE_DIR.replace('\\', '/').replace('C:', '/mnt/c')
                    cmd = ['wsl', 'bash', '-lc', f"cd '{wsl_path}' && ./bin/packet_analyzer logs/all_packets.log rules/active.rules"]
                    subprocess.run(cmd, check=False)
                else:
                    cmd = [analyzer_path, PACKETS_LOG, ACTIVE_RULES]
                    subprocess.run(cmd, check=False, cwd=BASE_DIR)
            except Exception:
                pass
            finally:
                # As requested: refresh (truncate) the capture log after each analyzer run
                try:
                    open(PACKETS_LOG, 'w', encoding='utf-8').close()
                except Exception:
                    pass

    def _analyzer_loop(self, interval_sec: int = 5):
        # Periodically invoke analyzer to parse captured packets and raise alerts
        while not self.analyzer_stop.is_set():
            self._run_analyzer_once()
            # small sleep to avoid hot loop
            self.analyzer_stop.wait(interval_sec)

    def start_analyzer_loop(self):
        if self.analyzer_thread and self.analyzer_thread.is_alive():
            return
        self.analyzer_stop.clear()
        self.analyzer_thread = threading.Thread(target=self._analyzer_loop, args=(10,), daemon=True)
        self.analyzer_thread.start()

    def stop_analyzer_loop(self):
        self.analyzer_stop.set()
        if self.analyzer_thread and self.analyzer_thread.is_alive():
            self.analyzer_thread.join(timeout=3)
        self.analyzer_thread = None


ids_manager = IDSManager()


class WebIDSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve existing web_interface directory without changing it
        super().__init__(*args, directory='web_interface', **kwargs)

    def _send_json(self, obj, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/api/get_alerts':
            try:
                alerts = []
                if os.path.exists(ALERTS_LOG):
                    with open(ALERTS_LOG, 'r', encoding='utf-8', errors='ignore') as f:
                        alerts = [line.rstrip('\n') for line in f.readlines()[-200:]]
                self._send_json({'alerts': alerts})
            except Exception as e:
                self._send_json({'error': str(e)}, status=500)
            return
        if path == '/api/active_rules':
            try:
                rules_list = []
                if os.path.exists(ACTIVE_RULES):
                    with open(ACTIVE_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                        idx = 0
                        for line in f:
                            s = line.strip()
                            if not s or s.startswith('#'):
                                continue
                            rules_list.append({ 'id': idx, 'rule': s })
                            idx += 1
                self._send_json({'rules': rules_list})
            except Exception as e:
                self._send_json({'error': str(e)}, status=500)
            return
        if path == '/api/host-ip':
            try:
                ip = None
                cfg = os.path.join(BASE_DIR, '.ids_host_ip')
                if os.path.exists(cfg):
                    with open(cfg, 'r', encoding='utf-8', errors='ignore') as f:
                        ip = f.read().strip() or None
                self._send_json({'ip': ip, 'success': True})
            except Exception as e:
                self._send_json({'ip': None, 'success': False, 'error': str(e)}, status=500)
            return
        if path == '/api/firewall_events':
            # Return parsed firewall events if parser is available
            global FIREWALL_PARSER_AVAILABLE
            try:
                # Parse count from query string if present
                count = 100
                try:
                    qs = self.path.split('?')[1]
                    for part in qs.split('&'):
                        if part.startswith('count='):
                            count = int(part.split('=', 1)[1])
                            break
                except Exception:
                    pass

                # Lazy import/load of firewall parser to avoid startup crashes
                global FIREWALL_MODULE
                # Force reload module to pick up rebuilt C library
                if FIREWALL_MODULE:
                    importlib.reload(FIREWALL_MODULE)
                    FIREWALL_MODULE = None
                    FIREWALL_PARSER_AVAILABLE = False
                
                if not FIREWALL_PARSER_AVAILABLE or not FIREWALL_MODULE:
                    sys.path.insert(0, FIREWALL_DIR)
                    try:
                        FIREWALL_MODULE = importlib.import_module('firewall_parser_python')
                        test_parser = FIREWALL_MODULE.FirewallEventParser()
                        _ = test_parser.get_recent_events(1)
                        FIREWALL_PARSER_AVAILABLE = True
                        print("[OK] Firewall parser loaded lazily")
                    except Exception as e:
                        print(f"[INFO] Lazy load failed: {e}")
                        # Try building then retry once
                        if build_firewall_parser():
                            try:
                                FIREWALL_MODULE = importlib.import_module('firewall_parser_python')
                                test_parser = FIREWALL_MODULE.FirewallEventParser()
                                _ = test_parser.get_recent_events(1)
                                FIREWALL_PARSER_AVAILABLE = True
                                print("[OK] Firewall parser built and loaded lazily")
                            except Exception as e2:
                                print(f"[WARN] Firewall parser still unavailable: {e2}")
                                FIREWALL_PARSER_AVAILABLE = False

                if not FIREWALL_PARSER_AVAILABLE:
                    return self._send_json({
                        'events': [],
                        'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}},
                        'error': 'Firewall parser not available. Please build it manually: cd firewall && make'
                    })

                parser = FIREWALL_MODULE.FirewallEventParser()
                
                # Get events and stats via C parser only
                print(f"[DEBUG] Calling parser.get_recent_events(count={count})")
                events = parser.get_recent_events(count=count) or []
                print(f"[DEBUG] Firewall parser returned {len(events)} events")
                if len(events) > 0:
                    print(f"[DEBUG] First event sample: {events[0]}")
                stats = parser.get_stats() if hasattr(parser, 'get_stats') else {'total_events': len(events), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}}
                print(f"[DEBUG] Firewall stats: {stats}")

                # Format events for frontend
                formatted_events = []
                for ev in events:
                    timestamp = ev.get('timestamp', '').strip()
                    if not timestamp:
                        timestamp = 'Unknown'
                    formatted_events.append({
                        'timestamp': timestamp,
                        'event_type': ev.get('event_type', 'unknown'),
                        'severity': ev.get('severity', 'low'),
                        'description': ev.get('description', ''),
                        'hostname': ev.get('host', ev.get('hostname', '')),
                        'host': ev.get('host', ''),
                        'source_ip': ev.get('source_ip', ev.get('ip', '')),
                        'command': ev.get('command', ''),
                        'raw_line': ev.get('raw_line', '')
                    })

                self._send_json({
                    'events': formatted_events,
                    'stats': {
                        'total_events': stats.get('total_events', 0),
                        'critical': stats.get('critical', 0),
                        'high': stats.get('high', 0),
                        'medium': stats.get('medium', 0),
                        'low': stats.get('low', 0),
                        'by_type': stats.get('by_type', {})
                    }
                })
            except Exception as e:
                self._send_json({'events': [], 'stats': {'total_events': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}}, 'error': str(e)}, status=500)
            return
        return super().do_GET()

    def do_POST(self):
        path = self.path.split('?')[0]
        if path == '/api/start_ids':
            try:
                content_length = int(self.headers.get('Content-Length', '0') or '0')
                data = {}
                if content_length:
                    data = json.loads(self.rfile.read(content_length).decode())
                interface = data.get('interface', 'any')

                # Prep logs
                ids_manager.refresh_logs()

                # Start scapy capture
                ids_manager.start_capture(interface)

                # Kick analyzer loop (uses compiled ids engine)
                ids_manager.start_analyzer_loop()

                self._send_json({'status': 'started', 'interface': interface})
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)}, status=500)
            return

        if path == '/api/stop_ids':
            try:
                ids_manager.stop_analyzer_loop()
                ids_manager.stop_capture()
                self._send_json({'status': 'stopped'})
            except Exception as e:
                self._send_json({'status': 'error', 'error': str(e)}, status=500)
            return

        if path == '/api/host-ip':
            try:
                content_length = int(self.headers.get('Content-Length', '0') or '0')
                data = {}
                if content_length:
                    data = json.loads(self.rfile.read(content_length).decode())
                ip = (data.get('ip') or '').strip()
                if not ip:
                    return self._send_json({'success': False, 'error': 'No IP address provided'}, status=400)
                with open(os.path.join(BASE_DIR, '.ids_host_ip'), 'w', encoding='utf-8') as f:
                    f.write(ip)
                self._send_json({'success': True, 'ip': ip})
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)}, status=500)
            return

        if path == '/api/convert_rule' or path == '/api/ai_suggest_rule':
            # Restore Gemini integration: take a natural-language description and return a parser-safe rule
            print(f"[DEBUG] Received {path} request")
            try:
                content_length = int(self.headers.get('Content-Length', '0') or '0')
                data = {}
                if content_length:
                    data = json.loads(self.rfile.read(content_length).decode())
                
                # Handle both 'description' and 'text' field names for compatibility
                description = (data.get('description') or data.get('text') or '').strip()
                print(f"[DEBUG] Description received: {description[:100]}...")
                if not description:
                    return self._send_json({'success': False, 'error': 'Missing description'}, status=400)

                # Ensure API key
                api_key = GEMINI_API_KEY
                if not genai:
                    return self._send_json({'success': False, 'error': 'Gemini is not configured. Install google-generativeai package: pip install google-generativeai'}, status=500)
                if not api_key or api_key.strip() == '':
                    return self._send_json({'success': False, 'error': 'Gemini API key is not configured. Please set GEMINI_API_KEY.'}, status=500)

                try:
                    genai.configure(api_key=api_key)
                    # Try different model names in order of preference
                    model = None
                    model_names = ['models/gemini-pro-latest', 'models/gemini-flash-latest', 'models/gemini-2.0-flash', 'models/gemini-pro']
                    for model_name in model_names:
                        try:
                            model = genai.GenerativeModel(model_name)
                            break
                        except Exception:
                            continue
                    if model is None:
                        raise Exception('Failed to initialize any Gemini model. Tried: ' + ', '.join(model_names))
                except Exception as e:
                    error_msg = str(e)
                    if 'api key' in error_msg.lower() or 'invalid' in error_msg.lower():
                        error_msg = 'Invalid Gemini API key. Please check your API key configuration.'
                    else:
                        error_msg = f'Failed to initialize Gemini: {error_msg}'
                    print(f"[ERROR] Gemini initialization error: {error_msg}")
                    return self._send_json({'success': False, 'error': error_msg}, status=500)

                # Call Gemini API with improved prompt
                prompt = f"""Convert this natural language security rule to IDS DSL syntax:
"{description}"

CRITICAL REQUIREMENTS - You MUST follow this EXACT format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]";priority:[1-5]);

MANDATORY SYNTAX RULES:
1. MUST end with semicolon (;)
2. Options MUST be inside parentheses: (msg:"...";priority:...)
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

                try:
                    # Set timeout for API call
                    resp = model.generate_content(prompt, request_options={'timeout': 30})
                    suggested = (resp.text or '').strip()
                    # Clean up markdown code blocks if present
                    suggested = suggested.replace('```', '').replace('```dsl', '').replace('```plaintext', '').strip()
                    # Remove any leading/trailing whitespace or newlines
                    suggested = suggested.strip()
                    # If empty or just whitespace, provide fallback
                    if not suggested:
                        print("[WARN] Gemini returned empty response")
                        if path == '/api/convert_rule':
                            return self._send_json({
                                'dsl_rule': '',
                                'error': 'Gemini API returned empty response. Please try again.',
                                'exists_in_local': False,
                                'suggestions': []
                            }, status=500)
                        else:
                            return self._send_json({'success': False, 'error': 'Gemini API returned empty response. Please try again.'}, status=500)
                except Exception as e:
                    error_msg = str(e)
                    # Provide more specific error messages
                    if '429' in error_msg or 'quota' in error_msg.lower():
                        error_msg = 'Gemini API quota exceeded. Please try again later.'
                    elif '401' in error_msg or '403' in error_msg or 'api key' in error_msg.lower() or 'invalid' in error_msg.lower():
                        error_msg = 'Invalid Gemini API key. Please check your API key configuration.'
                    elif 'timeout' in error_msg.lower() or 'timed out' in error_msg.lower():
                        error_msg = 'Request timed out. Please check your internet connection and try again.'
                    elif 'connection' in error_msg.lower() or 'network' in error_msg.lower() or 'socket' in error_msg.lower():
                        error_msg = 'Could not connect to Gemini AI. Please check your internet connection and try again.'
                    elif '503' in error_msg or 'service unavailable' in error_msg.lower():
                        error_msg = 'Gemini API service is temporarily unavailable. Please try again later.'
                    else:
                        error_msg = f'Gemini generation failed: {error_msg}'
                    print(f"[ERROR] Gemini API error: {error_msg}")
                    print(f"[ERROR] Full exception: {type(e).__name__}: {e}")
                    
                    # Format error response based on endpoint
                    if path == '/api/convert_rule':
                        return self._send_json({
                            'dsl_rule': '',
                            'error': error_msg,
                            'exists_in_local': False,
                            'suggestions': []
                        }, status=500)
                    else:
                        return self._send_json({'success': False, 'error': error_msg}, status=500)

                # Validate and normalize suggestion
                valid, err = self._validate_rule_syntax(suggested)
                if not valid:
                    # For convert_rule endpoint, return error in frontend format
                    if path == '/api/convert_rule':
                        return self._send_json({
                            'dsl_rule': suggested,
                            'error': f'Invalid rule syntax: {err}',
                            'exists_in_local': False,
                            'suggestions': []
                        }, status=400)
                    else:
                        return self._send_json({'success': False, 'suggested_rule': suggested, 'error': f'Invalid rule syntax: {err}'}, status=400)

                # Try to match against local.rules; prefer existing canonical rule
                matched = self._match_against_local_rules(suggested)
                
                # Format response based on endpoint
                if path == '/api/convert_rule':
                    # Frontend expects: { dsl_rule, exists_in_local, suggestions, test_instruction }
                    # If matched, use the rule from local.rules instead of generated one
                    display_rule = matched if matched else suggested
                    result = {
                        'dsl_rule': display_rule,
                        'exists_in_local': matched is not None,
                        'suggestions': [],
                        'test_instruction': None,
                        'similar_rules': [],
                        'matched_rule': matched,  # Include the matched rule for reference
                        'generated_rule': suggested  # Keep original generated rule for reference
                    }
                    if matched:
                        result['suggestions'] = [
                            f'✓ Found matching rule in local.rules (matched by protocol and port)',
                            f'Using rule from local.rules instead of generated rule.',
                            f'You can edit this rule before adding it to active.rules.'
                        ]
                        result['similar_rules'] = [matched]
                        print(f"[INFO] Matched rule from local.rules: {matched[:80]}...")
                        print(f"[INFO] Replacing generated rule with matched rule from local.rules")
                else:
                    # Backend API format: { success, suggested_rule, matched_rule, added_to_active }
                    result = {
                        'success': True,
                        'suggested_rule': suggested,
                        'matched_rule': matched or None,
                        'added_to_active': False,
                    }
                    # If matched, append to active.rules (idempotent)
                    if matched:
                        added = self._append_to_active_rules_if_missing(matched)
                        result['added_to_active'] = added
                
                print(f"[DEBUG] Gemini API success. Generated rule: {suggested[:100]}...")
                self._send_json(result)
            except Exception as e:
                self._send_json({'success': False, 'error': str(e)}, status=500)
            return

        if path == '/api/add_rule' or path == '/api/activate_rule':
            # Add a rule to active.rules file (used by IDS engine)
            print(f"[DEBUG] Received {path} request")
            try:
                content_length = int(self.headers.get('Content-Length', '0') or '0')
                data = {}
                if content_length:
                    data = json.loads(self.rfile.read(content_length).decode())
                rule = (data.get('rule') or '').strip()
                print(f"[DEBUG] Rule received: {rule[:100]}...")
                
                if not rule:
                    print("[ERROR] Missing rule in request")
                    return self._send_json({'success': False, 'status': 'error', 'error': 'Missing rule'}, status=400)
                
                # Validate rule syntax
                print("[DEBUG] Validating rule syntax...")
                valid, err = self._validate_rule_syntax(rule)
                if not valid:
                    print(f"[ERROR] Invalid rule syntax: {err}")
                    return self._send_json({'success': False, 'status': 'error', 'error': f'Invalid rule syntax: {err}'}, status=400)
                
                print("[DEBUG] Rule syntax is valid. Checking if rule exists...")
                # Add rule to active.rules file
                try:
                    added = self._append_to_active_rules_if_missing(rule)
                    print(f"[DEBUG] Rule added status: {added}")
                except Exception as append_error:
                    print(f"[ERROR] Failed to append rule: {append_error}")
                    import traceback
                    print(f"[ERROR] Traceback: {traceback.format_exc()}")
                    if path == '/api/add_rule':
                        return self._send_json({'status': 'error', 'error': f'Failed to write rule to file: {append_error}'}, status=500)
                    else:
                        return self._send_json({'success': False, 'error': f'Failed to write rule to file: {append_error}'}, status=500)
                
                # Return response based on endpoint
                if path == '/api/add_rule':
                    # Frontend expects: { status: 'added' }
                    if added:
                        print(f"[INFO] Rule added to active.rules: {rule[:80]}...")
                        return self._send_json({'status': 'added', 'message': 'Rule added successfully to active.rules'})
                    else:
                        print(f"[INFO] Rule already exists in active.rules: {rule[:80]}...")
                        return self._send_json({'status': 'exists', 'message': 'Rule already exists in active.rules'})
                else:
                    # Backend API format: { success: True, added: boolean }
                    return self._send_json({'success': True, 'added': added})
            except Exception as e:
                error_msg = str(e)
                print(f"[ERROR] Error adding rule: {error_msg}")
                import traceback
                print(f"[ERROR] Traceback: {traceback.format_exc()}")
                if path == '/api/add_rule':
                    return self._send_json({'status': 'error', 'error': error_msg}, status=500)
                else:
                    return self._send_json({'success': False, 'error': error_msg}, status=500)
            return

        return self.send_error(404)

    # --- Helpers: rule processing ---
    def _normalize_rule(self, s: str) -> str:
        return re.sub(r'\s+', ' ', s.strip())

    def _parse_rule_core(self, rule: str):
        """Extract protocol, dst_port, and options block."""
        # Make semicolon optional to handle rules from local.rules (no semicolon) and generated rules (with semicolon)
        m = re.match(r'^(alert|log|pass)\s+(tcp|udp|icmp|ip)\s+([^\s]+)\s+([^\s]+)\s+(->|<>)\s+([^\s]+)\s+([^\s]+)\s*\((.*)\)\s*;?\s*$', rule, flags=re.IGNORECASE)
        if not m:
            return None
        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, opts = m.groups()
        return {
            'action': action.lower(),
            'protocol': protocol.lower(),
            'src_ip': src_ip,
            'src_port': src_port,
            'direction': direction,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'options_raw': opts.strip(),
        }

    def _validate_rule_syntax(self, rule: str):
        if not rule:
            return False, 'Empty rule'
        core = self._parse_rule_core(rule)
        if not core:
            return False, 'Does not match required grammar'
        protocol = core['protocol']
        # ICMP must use any any for ports
        if protocol == 'icmp':
            if core['src_port'].lower() != 'any' or core['dst_port'].lower() != 'any':
                return False, 'ICMP must use any any for ports'
        # Options: allow only msg, priority, sid, rev for safety
        options = core['options_raw']
        # Split on semicolons, ignore empty
        parts = [p.strip() for p in options.split(';') if p.strip()]
        allowed = {'msg', 'priority', 'sid', 'rev'}
        seen = set()
        for p in parts:
            if ':' not in p:
                return False, f'Invalid option fragment: {p}'
            k, v = p.split(':', 1)
            k = k.strip().lower()
            if k not in allowed:
                return False, f'Unsupported option: {k}'
            seen.add(k)
            if k == 'msg':
                if not re.match(r'^\".*\"$', v.strip()):
                    return False, 'msg must be quoted'
            elif k in ('priority', 'sid', 'rev'):
                if not re.match(r'^\d+$', v.strip()):
                    return False, f'{k} must be integer'
        # Require msg and priority at minimum
        if 'msg' not in seen or 'priority' not in seen:
            return False, 'msg and priority are required'
        return True, ''

    def _load_local_rules(self):
        rules = []
        try:
            if os.path.exists(LOCAL_RULES):
                with open(LOCAL_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith('#'):
                            continue
                        rules.append(s)
        except Exception:
            return []
        return rules

    def _extract_msg_protocol_dst(self, rule: str):
        core = self._parse_rule_core(rule)
        if not core:
            return None, None, None
        msg = None
        for frag in [p.strip() for p in core['options_raw'].split(';') if p.strip()]:
            if frag.lower().startswith('msg:'):
                msg = frag.split(':', 1)[1].strip().strip('"')
                break
        return core['protocol'], core['dst_port'].lower(), msg

    def _match_against_local_rules(self, suggested: str):
        norm_suggested = self._normalize_rule(suggested)
        proto_s, dst_s, msg_s = self._extract_msg_protocol_dst(norm_suggested)
        local_rules = self._load_local_rules()
        # First: exact normalized match
        for r in local_rules:
            if self._normalize_rule(r) == norm_suggested:
                return r
        # Second: match protocol/dst_port and msg substring match
        for r in local_rules:
            proto_r, dst_r, msg_r = self._extract_msg_protocol_dst(r)
            if proto_r == proto_s and (dst_r == dst_s or proto_s == 'icmp'):
                if msg_s and msg_r and msg_s.lower() in msg_r.lower():
                    return r
        # Third: match by protocol/dst_port only
        for r in local_rules:
            proto_r, dst_r, _ = self._extract_msg_protocol_dst(r)
            if proto_r == proto_s and (dst_r == dst_s or proto_s == 'icmp'):
                return r
        return None

    def _append_to_active_rules_if_missing(self, rule: str) -> bool:
        try:
            pathlib.Path(os.path.dirname(ACTIVE_RULES)).mkdir(parents=True, exist_ok=True)
            existing = []
            if os.path.exists(ACTIVE_RULES):
                with open(ACTIVE_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                    existing = [self._normalize_rule(x) for x in f if x.strip() and not x.strip().startswith('#')]
            norm = self._normalize_rule(rule)
            if norm in existing:
                print(f"[INFO] Rule already exists (normalized): {norm[:80]}...")
                return False
            print(f"[INFO] Adding new rule to {ACTIVE_RULES}")
            with open(ACTIVE_RULES, 'a', encoding='utf-8') as f:
                # Ensure newline before adding if file doesn't end with one
                if existing:
                    # Check if last line in file ends with newline
                    with open(ACTIVE_RULES, 'r', encoding='utf-8') as check_file:
                        content = check_file.read()
                        if content and not content.endswith('\n'):
                            f.write('\n')
                f.write(rule.rstrip() + '\n')
            print(f"[INFO] Successfully wrote rule to file")
            return True
        except Exception as e:
            print(f"[ERROR] Exception in _append_to_active_rules_if_missing: {e}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            return False


def run(host='127.0.0.1', port=8080):
    # Try to start server, handle port conflicts
    max_retries = 5
    for attempt in range(max_retries):
        try:
            with socketserver.TCPServer((host, port), WebIDSHandler) as httpd:
                print(f"Web IDS server running at http://{host}:{port}")
                if FIREWALL_PARSER_AVAILABLE:
                    print("✅ Firewall parser: Available")
                else:
                    print("⚠️  Firewall parser: Not available (will auto-build on first request)")
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    pass
                finally:
                    ids_manager.stop_analyzer_loop()
                    ids_manager.stop_capture()
                return
        except OSError as e:
            if e.winerror == 10048 or "Address already in use" in str(e):
                if attempt < max_retries - 1:
                    print(f"⚠️  Port {port} is already in use. Trying to find available port...")
                    port += 1
                    continue
                else:
                    print(f"❌ Error: Port {port} is already in use.")
                    print(f"   Please stop the existing server or use a different port.")
                    print(f"   To find and kill the process using port {port}:")
                    print(f"   netstat -ano | findstr :{port}")
                    print(f"   taskkill /F /PID <PID>")
                    return
            else:
                raise


if __name__ == '__main__':
    run()


