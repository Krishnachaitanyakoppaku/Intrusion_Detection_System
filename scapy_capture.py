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
            
            # Check IP match
            if packet.haslayer(IP):
                ip_packet = packet[IP]
                
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
        
        # Log ALL packets (whether they match rules or not)
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
            if self._matches_rule(packet, rule):
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
            
            if packet.haslayer(IP):
                ip_packet = packet[IP]
                src_ip = str(ip_packet.src)
                dst_ip = str(ip_packet.dst)
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = ip_packet.sport
                    dst_port = ip_packet.dport
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = ip_packet.sport
                    dst_port = ip_packet.dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
            else:
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

