#!/usr/bin/env python3
"""Test firewall parser with debug output"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firewall_parser_python import FirewallEventParser

parser = FirewallEventParser()

# Test lines from firewall.log
test_lines = [
    "[2025-11-02 15:19:54] client-hostname kernel: sudo ufw reset 192.168.1.100",
    "[2025-11-02 15:21:00] server-01 kernel: systemctl stop firewalld executed by user admin",
    "[2025-11-02 15:21:15] client-05 syslog: firewall-cmd --reload executed successfully",
    "[2025-11-02 15:21:30] workstation-01 auth.log: chmod 777 /etc/passwd attempted by user test",
    "[2025-11-02 15:22:00] client-01 syslog: iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
    "[2025-11-02 15:22:15] server-03 auth: su - root executed by user admin",
]

print("Testing individual log lines:")
print("=" * 70)

for i, line in enumerate(test_lines, 1):
    print(f"\nTest {i}: {line[:60]}...")
    event = parser.parse_log_line(line)
    if event:
        print(f"  ✓ Detected: {event.get('event_type')} - {event.get('severity')}")
        print(f"    Description: {event.get('description')}")
    else:
        print(f"  ✗ No event detected")

print("\n" + "=" * 70)
print("\nTesting full log file:")
events = parser.get_recent_events(20)
print(f"Found {len(events)} events")
for i, e in enumerate(events[:10], 1):
    print(f"{i}. {e.get('event_type')}: {e.get('description')} [{e.get('severity')}]")

