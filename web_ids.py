#!/usr/bin/env python3
import http.server
import socketserver
import os
import subprocess
import json
import threading
import time
import sys


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
ALERTS_LOG = os.path.join(LOGS_DIR, 'alerts.log')
PACKETS_LOG = os.path.join(LOGS_DIR, 'all_packets.log')
ACTIVE_RULES = os.path.join(BASE_DIR, 'rules', 'active.rules')


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
            # Minimal stub: return empty events so UI doesn't error
            self._send_json({
                'events': [],
                'stats': {
                    'total_events': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'by_type': {}
                }
            })
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
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            ids_manager.stop_analyzer_loop()
            ids_manager.stop_capture()


if __name__ == '__main__':
    run()


