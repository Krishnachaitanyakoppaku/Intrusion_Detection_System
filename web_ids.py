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


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
ALERTS_LOG = os.path.join(LOGS_DIR, 'alerts.log')
PACKETS_LOG = os.path.join(LOGS_DIR, 'all_packets.log')
ACTIVE_RULES = os.path.join(BASE_DIR, 'rules', 'active.rules')
FIREWALL_DIR = os.path.join(BASE_DIR, 'firewall')
FIREWALL_LOG = os.path.join(FIREWALL_DIR, 'logs', 'firewall.log')

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
                events = parser.get_recent_events(count=count) or []
                stats = parser.get_stats() if hasattr(parser, 'get_stats') else {'total_events': len(events), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_type': {}}

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

        return self.send_error(404)


def run(host='127.0.0.1', port=8080):
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


if __name__ == '__main__':
    run()


