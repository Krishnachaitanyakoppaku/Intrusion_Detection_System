#!/usr/bin/env python3
"""
Scapy-based Packet Capture Module for IDS
Captures TCP packets using Scapy and integrates with the IDS engine
"""
import sys
import os
import time
import json
import socket
import struct
import subprocess
import re
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Installing...")
    print("Run: pip install scapy")
    sys.exit(1)


def is_wsl():
    """Check if running in WSL"""
    try:
        with open('/proc/version', 'r') as f:
            version = f.read().lower()
            return 'microsoft' in version or 'wsl' in version
    except:
        return False


def get_windows_host_ip():
    """Get Windows host IP address when running in WSL"""
    try:
        # Get default gateway which is usually Windows host in WSL
        result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            return match.group(1)
        
        # Alternative: Get IP from interface connected to default route
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True)
        # Extract the source IP from the route
        match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            src_ip = match.group(1)
            # If it's not a WSL IP (not 172.x.x.x), return it
            if not src_ip.startswith('172.'):
                return src_ip
    except:
        pass
    return None


def get_windows_network_ip():
    """Get Windows network IP (WiFi/Ethernet IP) when in WSL"""
    try:
        # Get all IP addresses
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ips = result.stdout.strip().split()
        
        # Find non-WSL IP (not 172.x.x.x, not 127.x.x.x)
        for ip in ips:
            if not ip.startswith('172.') and not ip.startswith('127.'):
                return ip
        
        # If all are WSL IPs, get Windows host IP from gateway
        return get_windows_host_ip()
    except:
        return None


def get_wsl_ip():
    """Get WSL's own IP address"""
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        wsl_ips = result.stdout.strip().split()
        if wsl_ips:
            return wsl_ips[0]
    except:
        pass
    return None


def map_ip_to_windows(ip_address, windows_network_ip, windows_host_ip, wsl_ip):
    """Map WSL IP to Windows IP if the IP EXACTLY matches WSL IP (not subnet-based)"""
    if not ip_address:
        return ip_address
    
    # Prefer network IP (actual WiFi/Ethernet IP) over host IP (gateway)
    windows_ip = windows_network_ip or windows_host_ip
    if not windows_ip or not wsl_ip:
        return ip_address
    
    # ONLY map if IP EXACTLY matches WSL IP (complete IP address, not subnet)
    # This prevents mapping other computers on the same 172.17.x.x network
    if ip_address == wsl_ip:
        return windows_ip
    
    # Don't do subnet-based mapping - use exact IP matching only
    return ip_address


class PacketCaptureEngine:
    """Advanced packet capture using Scapy"""
    
    def __init__(self, interface="any", rules_file="rules/local.rules", log_file="logs/alerts.log"):
        self.interface = interface
        # Prefer active.rules if present
        preferred_rules = "rules/active.rules"
        if os.path.exists(preferred_rules):
            self.rules_file = preferred_rules
        else:
            self.rules_file = rules_file
        self.log_file = log_file
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        
        # WSL IP mapping
        self.is_wsl = is_wsl()
        self.windows_host_ip = None
        self.windows_network_ip = None
        self.wsl_ip = None
        self.host_ips = set()  # All IPs this host owns (for incoming traffic detection)
        
        if self.is_wsl:
            self.windows_host_ip = get_windows_host_ip()
            self.windows_network_ip = get_windows_network_ip()
            self.wsl_ip = get_wsl_ip()
            
            if self.windows_network_ip or self.windows_host_ip:
                print(f"[WSL] Detected WSL environment")
                if self.windows_network_ip:
                    print(f"   Windows Network IP: {self.windows_network_ip}")
                if self.windows_host_ip:
                    print(f"   Windows Host IP: {self.windows_host_ip}")
                print(f"   WSL IP: {self.wsl_ip}")
                print(f"   IP addresses will be mapped to Windows IP in logs")
            else:
                print(f"[WSL] WSL detected but could not get Windows IP")
                print(f"   Logs will show WSL IP addresses")
        else:
            print(f"[OK] Running on native Linux")
        
        # Collect all host IP addresses FIRST (before loading rules, as rules might need this info)
        self._collect_host_ips()
        
        # Load rules
        self.rules = self._load_rules()
        
        # Stats
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'alerts': 0,
            'start_time': datetime.now().isoformat()
        }
        
        print("[OK] Scapy Packet Capture Engine initialized")
        print(f"   Interface: {interface}")
        print(f"   Rules file: {self.rules_file}")
        print(f"   Alert log: {log_file}")
        print(f"   Packet log: logs/all_packets.log")
        print(f"   Loaded {len(self.rules)} rules")
    
    def _collect_host_ips(self):
        """Collect all IP addresses this host owns (for incoming traffic detection)"""
        try:
            print(f"   [DEBUG] Collecting host IPs...")
            print(f"   [DEBUG] WSL detection: is_wsl={self.is_wsl}, wsl_ip={self.wsl_ip}, windows_host_ip={self.windows_host_ip}, windows_network_ip={self.windows_network_ip}")
            
            # Get all IP addresses from hostname -I (this should include 172.17.1.152)
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ips = result.stdout.strip().split()
                print(f"   [DEBUG] hostname -I returned: {ips}")
                for ip in ips:
                    ip_clean = ip.strip()
                    if ip_clean:
                        self.host_ips.add(ip_clean)
                        print(f"   [DEBUG] Added IP from hostname -I: {ip_clean}")
            
            # In WSL, add ALL relevant IPs (both WSL IP and Windows IPs)
            # External computers ping Windows IP, but packets might show WSL IP as destination
            # So we need BOTH in host_ips to catch incoming traffic
            if self.is_wsl:
                # Add WSL IP first (this is what Scapy sees as destination - e.g., 172.17.1.152)
                if self.wsl_ip:
                    self.host_ips.add(self.wsl_ip)
                    print(f"   [WSL] Added WSL IP for incoming detection: {self.wsl_ip}")
                # Add Windows host IP (external devices ping this)
                if self.windows_host_ip:
                    self.host_ips.add(self.windows_host_ip)
                    print(f"   [WSL] Added Windows Host IP for incoming detection: {self.windows_host_ip}")
                # Add Windows network IP (actual WiFi/Ethernet IP)
                if self.windows_network_ip:
                    self.host_ips.add(self.windows_network_ip)
                    print(f"   [WSL] Added Windows Network IP for incoming detection: {self.windows_network_ip}")
            
            # Also scan all network interfaces for additional IPs (CRITICAL - catches all IPs including 172.17.1.152)
            try:
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    import re
                    # Find all IP addresses (IPv4) - extract complete IP, not subnet
                    ip_pattern = r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                    found_ips = re.findall(ip_pattern, result.stdout)
                    print(f"   [DEBUG] ip addr show found IPs: {found_ips}")
                    for ip in found_ips:
                        # Only add complete, valid IP addresses (exclude link-local and loopback)
                        if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                            self.host_ips.add(ip)
                            print(f"   [DEBUG] Added IP from ip addr show: {ip}")
            except Exception as e:
                print(f"   [DEBUG] Error scanning interfaces: {e}")
                import traceback
                traceback.print_exc()
            
            # Add localhost
            self.host_ips.add('127.0.0.1')
            self.host_ips.add('::1')
            
            # Check if we're in an interactive terminal (for user input)
            import sys
            is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
            
            # Get user input for host IP address if not automatically detected
            # This is useful when automatic detection fails (e.g., WSL IP 172.17.1.152)
            network_ips = [ip for ip in self.host_ips if ip != '127.0.0.1' and ip != '::1']
            if len(network_ips) == 0:
                print(f"\n   [WARNING] No network IP addresses were automatically detected.")
                print(f"   Current host_ips: {sorted(self.host_ips)}")
                print(f"   [INFO] Incoming traffic detection requires at least one network IP address.")
                
                # Try to get IP from environment variable first (for non-interactive use)
                env_host_ip = os.environ.get('IDS_HOST_IP', '').strip()
                if env_host_ip:
                    import re
                    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                    if re.match(ip_pattern, env_host_ip):
                        octets = env_host_ip.split('.')
                        if all(0 <= int(octet) <= 255 for octet in octets):
                            self.host_ips.add(env_host_ip)
                            print(f"   [OK] Added host IP from environment variable IDS_HOST_IP: {env_host_ip}")
                        else:
                            print(f"   [ERROR] Invalid IP in IDS_HOST_IP environment variable: {env_host_ip}")
                    else:
                        print(f"   [ERROR] Invalid IP format in IDS_HOST_IP environment variable: {env_host_ip}")
                elif is_interactive:
                    # Only prompt for input if we're in an interactive terminal
                    print(f"\n   [INPUT REQUIRED] Please enter your host IP address.")
                    print(f"   Example: 172.17.1.152 (for WSL) or your actual network IP")
                    
                    while True:
                        try:
                            user_ip = input(f"   Enter host IP address (or press Enter to skip): ").strip()
                            if not user_ip:
                                print(f"   [SKIP] No IP entered - incoming detection may not work!")
                                print(f"   [TIP] You can set IDS_HOST_IP environment variable instead.")
                                break
                            
                            # Basic IP validation
                            import re
                            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                            if re.match(ip_pattern, user_ip):
                                # Verify each octet is 0-255
                                octets = user_ip.split('.')
                                if all(0 <= int(octet) <= 255 for octet in octets):
                                    self.host_ips.add(user_ip)
                                    print(f"   [OK] Added user-provided IP: {user_ip}")
                                    break
                                else:
                                    print(f"   [ERROR] Invalid IP: octets must be 0-255. Please try again.")
                            else:
                                print(f"   [ERROR] Invalid IP format. Please enter a valid IPv4 address (e.g., 172.17.1.152).")
                        except (KeyboardInterrupt, EOFError):
                            print(f"\n   [SKIP] Input cancelled - skipping manual addition")
                            break
                        except Exception as e:
                            print(f"   [ERROR] Input error: {e}. Please try again.")
                else:
                    # Non-interactive mode - provide instructions
                    print(f"   [SKIP] Non-interactive mode detected - cannot prompt for input.")
                    print(f"   [TIP] To set host IP, use environment variable: export IDS_HOST_IP=172.17.1.152")
                    print(f"   [TIP] Or create a config file: echo '172.17.1.152' > .ids_host_ip")
            
            # Check if we should read from config file
            config_file = '.ids_host_ip'
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        config_ip = f.read().strip()
                    if config_ip:
                        import re
                        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                        if re.match(ip_pattern, config_ip):
                            octets = config_ip.split('.')
                            if all(0 <= int(octet) <= 255 for octet in octets):
                                if config_ip not in self.host_ips:
                                    self.host_ips.add(config_ip)
                                    print(f"   [OK] Added host IP from config file (.ids_host_ip): {config_ip}")
                        else:
                            print(f"   [WARNING] Invalid IP format in .ids_host_ip config file: {config_ip}")
                except Exception as e:
                    print(f"   [WARNING] Could not read .ids_host_ip config file: {e}")
            
            if self.host_ips:
                print(f"   Host IPs for incoming detection ({len(self.host_ips)} total): {', '.join(sorted(self.host_ips))}")
                # Show summary of detected IPs (excluding localhost)
                network_ips = [ip for ip in self.host_ips if ip != '127.0.0.1' and ip != '::1']
                if network_ips:
                    print(f"   [OK] Network IPs detected: {', '.join(sorted(network_ips))}")
                else:
                    print(f"   [WARNING] Only localhost IPs detected - incoming detection may not work for external traffic!")
            else:
                print(f"   [WARNING] No host IPs collected! Incoming traffic detection will fail.")
        except Exception as e:
            print(f"   Warning: Could not collect host IPs: {e}")
            import traceback
            traceback.print_exc()
    
    def _load_rules(self):
        """Load IDS rules from file"""
        rules = []
        if not os.path.exists(self.rules_file):
            print(f"[WARNING] Rules file not found: {self.rules_file}")
            return rules
        
        with open(self.rules_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse rule into components
                rule_parts = self._parse_rule(line)
                if rule_parts:
                    rules.append(rule_parts)
        
        return rules
    
    def _parse_rule(self, rule_line):
        """Parse a rule line into components"""
        try:
            parts = rule_line.split()
            if len(parts) < 6:
                return None
            
            action = parts[0]  # alert, log
            protocol = parts[1]  # tcp, udp, icmp, ip
            src_ip = parts[2]
            src_port = parts[3]
            direction = parts[4]  # ->
            dst_ip = parts[5]
            dst_port = parts[6]
            
            # Extract options
            msg = ""
            content = ""
            priority = 5
            
            # Parse options like (msg:"..."; content:"..."; priority:1)
            if len(rule_line) > 50:
                opts_part = rule_line.split('(', 1)[1].rsplit(')', 1)[0]
                
                if 'msg:"' in opts_part:
                    start = opts_part.find('msg:"') + 5
                    end = opts_part.find('"', start)
                    msg = opts_part[start:end]
                
                if 'content:"' in opts_part:
                    start = opts_part.find('content:"') + 9
                    end = opts_part.find('"', start)
                    content = opts_part[start:end]
                
                if 'priority:' in opts_part:
                    start = opts_part.find('priority:') + 9
                    priority = int(opts_part[start:start+1])
            
            return {
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'msg': msg,
                'content': content,
                'priority': priority,
                'original': rule_line
            }
        except Exception as e:
            print(f"Error parsing rule: {e}")
            return None
    
    def _matches_rule(self, packet, rule):
        """Check if packet matches a rule"""
        try:
            # Check protocol
            if rule['protocol'] == 'ip':
                if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                    return False
            elif rule['protocol'] == 'tcp':
                if not packet.haslayer(TCP):
                    return False
            elif rule['protocol'] == 'udp':
                if not packet.haslayer(UDP):
                    return False
            elif rule['protocol'] == 'icmp':
                if not packet.haslayer(ICMP):
                    return False
            else:
                return False
            
            # Check IP match (require IP layer for TCP/UDP/ICMP rules)
            if rule['protocol'] in ['tcp', 'udp', 'icmp']:
                # TCP/UDP/ICMP rules require IP layer (IPv4 or IPv6)
                if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                    return False
            
            # Extract IP packet (IPv4 or IPv6)
            ip_packet = None
            is_ipv6 = False
            if packet.haslayer(IP):
                ip_packet = packet[IP]
            elif packet.haslayer(IPv6):
                ip_packet = packet[IPv6]
                is_ipv6 = True
            
            # All rules need IP layer for matching
            if not ip_packet:
                return False
            
            # Check source IP
            if rule['src_ip'] != 'any':
                if str(ip_packet.src) != rule['src_ip']:
                    return False
            
            # Check destination IP
            if rule['dst_ip'] != 'any':
                if str(ip_packet.dst) != rule['dst_ip']:
                    return False
            
            # Check ports for TCP/UDP
            if packet.haslayer(TCP):
                tcp_packet = packet[TCP]
                if rule['dst_port'] != 'any' and rule['dst_port'] != '0':
                    if tcp_packet.dport != int(rule['dst_port']):
                        return False
                if rule['src_port'] != 'any' and rule['src_port'] != '0':
                    if tcp_packet.sport != int(rule['src_port']):
                        return False
            
            if packet.haslayer(UDP):
                udp_packet = packet[UDP]
                if rule['dst_port'] != 'any' and rule['dst_port'] != '0':
                    if udp_packet.dport != int(rule['dst_port']):
                        return False
                if rule['src_port'] != 'any' and rule['src_port'] != '0':
                    if udp_packet.sport != int(rule['src_port']):
                        return False
            
            # Check content match if specified
            if rule['content']:
                raw_data = bytes(packet)
                if rule['content'].encode() not in raw_data:
                    return False
            
            # Note: Incoming traffic check is now done in _process_packet to have access to full packet context
            # All checks passed - rule matches
            return True
            
        except Exception as e:
            print(f"Error matching rule: {e}")
            return False
    
    def _log_packet(self, packet):
        """Log all captured packets to file"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Extract basic packet info
            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "Unknown"
            size = len(packet)
            
            if packet.haslayer(IP):
                ip_packet = packet[IP]
                src_ip = str(ip_packet.src)
                dst_ip = str(ip_packet.dst)
                
                # Map WSL IPs to Windows IPs if in WSL
                if self.is_wsl and (self.windows_network_ip or self.windows_host_ip) and self.wsl_ip:
                    src_ip = map_ip_to_windows(src_ip, self.windows_network_ip or '', self.windows_host_ip or '', self.wsl_ip)
                    dst_ip = map_ip_to_windows(dst_ip, self.windows_network_ip or '', self.windows_host_ip or '', self.wsl_ip)
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    packet_info = f"{timestamp} | {src_ip}:{ip_packet.sport} -> {dst_ip}:{ip_packet.dport} | {protocol} | Size: {size}B"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    packet_info = f"{timestamp} | {src_ip}:{ip_packet.sport} -> {dst_ip}:{ip_packet.dport} | {protocol} | Size: {size}B"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    packet_info = f"{timestamp} | {src_ip} -> {dst_ip} | {protocol} | Size: {size}B"
                else:
                    packet_info = f"{timestamp} | {src_ip} -> {dst_ip} | IP | Size: {size}B"
            else:
                packet_info = f"{timestamp} | Unknown packet | Size: {size}B"
            
            # Log to all_packets.log
            try:
                with open('logs/all_packets.log', 'a', encoding='utf-8') as f:
                    f.write(packet_info + '\n')
            except Exception as e:
                print(f"Error logging packet: {e}")
        
        except Exception as e:
            print(f"Error in _log_packet: {e}")
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        self.packet_count += 1
        self.stats['total_packets'] += 1
        
        # Determine if this packet is incoming (for rules with "incoming" in message)
        is_incoming = False
        if packet.haslayer(IP):
            dst_ip = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            dst_ip = str(packet[IPv6].dst)
        else:
            dst_ip = None
        
        # Check if destination IP is one of host IPs (EXACT match)
        if dst_ip and hasattr(self, 'host_ips') and len(self.host_ips) > 0:
            if dst_ip in self.host_ips:
                is_incoming = True
        
        # Log ALL packets to all_packets.log (for C engine processing)
        # Note: C engine will check incoming detection when matching rules
        self._log_packet(packet)
        
        # Update protocol stats
        if packet.haslayer(TCP):
            self.stats['tcp_packets'] += 1
        elif packet.haslayer(UDP):
            self.stats['udp_packets'] += 1
        elif packet.haslayer(ICMP):
            self.stats['icmp_packets'] += 1
        
        # Check against all rules
        for rule in self.rules:
            rule_matched = self._matches_rule(packet, rule)
            if rule_matched:
                print(f"   [DEBUG] Rule matched: {rule.get('msg', 'N/A')} (protocol={rule.get('protocol')})")
                # Check incoming traffic filter (only for rules with "Incoming" in message)
                if 'incoming' in rule.get('msg', '').lower():
                    # Verify destination IP is one of host's IPs
                    if packet.haslayer(IP):
                        dst_ip = str(packet[IP].dst)
                    elif packet.haslayer(IPv6):
                        dst_ip = str(packet[IPv6].dst)
                    else:
                        # No IP layer, can't determine - skip
                        print(f"   [DEBUG] Rule matched but no IP layer - skipping")
                        continue
                    
                    # Check if destination IP is in host IPs (EXACT IP match, not subnet)
                    if not hasattr(self, 'host_ips') or len(self.host_ips) == 0:
                        # Host IPs not collected - skip to avoid false positives
                        print(f"   [DEBUG] Rule matched but host_ips empty - skipping incoming rule")
                        continue
                    
                    # Check if destination IP EXACTLY matches any host IP (complete IP address check)
                    # This prevents false positives when other computers on same subnet (e.g., 172.17.x.x) 
                    # send packets that would match our host IP if we did subnet matching
                    print(f"   [DEBUG] Checking incoming: dst_ip={dst_ip}, host_ips={self.host_ips}, match={dst_ip in self.host_ips}")
                    if dst_ip not in self.host_ips:
                        # This is outgoing traffic or traffic to another computer on same network - skip
                        print(f"   [DEBUG] Skipping - {dst_ip} not in host_ips")
                        continue
                    # If we get here, dst_ip EXACTLY matches one of our host IPs - this is incoming traffic!
                    print(f"   [DEBUG] Incoming traffic confirmed: {dst_ip} matches host IPs!")
                
                # Generate alert
                print(f"   [DEBUG] Generating alert for rule: {rule.get('msg', 'N/A')}")
                self._generate_alert(packet, rule)
                self.alert_count += 1
                self.stats['alerts'] += 1
                break  # Only trigger once per packet
    
    def _generate_alert(self, packet, rule):
        """Generate and log an alert"""
        try:
            timestamp = datetime.now()
            
            # Extract packet info
            src_ip = "unknown"
            dst_ip = "unknown"
            src_port = 0
            dst_port = 0
            protocol = "unknown"
            
            # Extract IP information (support both IPv4 and IPv6)
            if packet.haslayer(IP):
                ip_packet = packet[IP]
                src_ip = str(ip_packet.src)
                dst_ip = str(ip_packet.dst)
                
                # Map WSL IPs to Windows IPs if in WSL
                if self.is_wsl and (self.windows_host_ip or self.windows_network_ip) and self.wsl_ip:
                    src_ip = map_ip_to_windows(src_ip, self.windows_network_ip, self.windows_host_ip, self.wsl_ip)
                    dst_ip = map_ip_to_windows(dst_ip, self.windows_network_ip, self.windows_host_ip, self.wsl_ip)
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    tcp_packet = packet[TCP]
                    src_port = tcp_packet.sport
                    dst_port = tcp_packet.dport
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    udp_packet = packet[UDP]
                    src_port = udp_packet.sport
                    dst_port = udp_packet.dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
            elif packet.haslayer(IPv6):
                # Handle IPv6 packets
                ipv6_packet = packet[IPv6]
                src_ip = str(ipv6_packet.src)
                dst_ip = str(ipv6_packet.dst)
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    tcp_packet = packet[TCP]
                    src_port = tcp_packet.sport
                    dst_port = tcp_packet.dport
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    udp_packet = packet[UDP]
                    src_port = udp_packet.sport
                    dst_port = udp_packet.dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMPv6"
            else:
                # No IP layer - this shouldn't match TCP/UDP rules, but handle gracefully
                src_ip = "N/A"
                dst_ip = "N/A"
            
            # Create alert message
            alert_msg = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] ALERT: {rule['msg']} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {protocol} | Priority: {rule['priority']}"
            
            # Log to file
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(alert_msg + '\n')
                    f.flush()  # Ensure immediate write
            except Exception as e:
                print(f"Error writing to log file: {e}")
            
            print(f"[ALERT] {alert_msg}")
        
        except Exception as e:
            print(f"Error generating alert: {e}")
    
    def start(self):
        """Start packet capture"""
        self.running = True
        
        print(f"\n{'='*60}")
        print(f"Starting Scapy Packet Capture Engine")
        print(f"{'='*60}")
        print(f"Interface: {self.interface}")
        print(f"Rules: {len(self.rules)}")
        print(f"Press Ctrl+C to stop")
        print(f"{'='*60}\n")
        
        try:
            # Start sniffing
            if self.interface == "any":
                print("[CAPTURING] Capturing on all interfaces...")
            else:
                print(f"[CAPTURING] Capturing on interface: {self.interface}")
            
            # Sniff packets
            sniff(
                iface=self.interface if self.interface != "any" else None,
                prn=self._process_packet,
                store=False
            )
            
        except KeyboardInterrupt:
            print("\n\n[STOPPING] Stopping packet capture...")
            self.stop()
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        print(f"\n{'='*60}")
        print(f"Capture Statistics")
        print(f"{'='*60}")
        print(f"Total packets captured: {self.stats['total_packets']}")
        print(f"TCP packets: {self.stats['tcp_packets']}")
        print(f"UDP packets: {self.stats['udp_packets']}")
        print(f"ICMP packets: {self.stats['icmp_packets']}")
        print(f"Alerts generated: {self.stats['alerts']}")
        print(f"{'='*60}")
        print(f"\n[INFO] All packets saved to: logs/all_packets.log")
        print(f"[INFO] Alerts saved to: logs/alerts.log")
        print(f"{'='*60}")


def main():
    """Main entry point"""
    # Parse arguments
    interface = "any"
    
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not available. Please install it:")
        print("   pip install scapy")
        sys.exit(1)
    
    # Check for root privileges on Linux/macOS (not required on Windows with Npcap)
    if os.name != 'nt' and os.geteuid() != 0:
        print("[WARNING] This script requires root privileges to capture packets on Linux/macOS")
        print("   Run with: sudo python3 scapy_capture.py")
        print("   On Windows, Npcap must be installed for packet capture to work")
        # Don't exit, let it try
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Create and start capture engine
    engine = PacketCaptureEngine(interface=interface)
    engine.start()


if __name__ == "__main__":
    main()

