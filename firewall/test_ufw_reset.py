#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firewall_parser_python import FirewallEventParser

parser = FirewallEventParser()
print(f"Parser library loaded: {parser.lib is not None}\n")

# Test with log lines containing "sudo ufw reset"
test_lines = [
    "[2025-11-02 15:19:54] client-hostname kernel: [12345.678] user=root uid=0 sudo: root : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/sbin/ufw --force reset 192.168.1.100",
    "[2025-11-02 15:19:54] server-01 auth.log: user admin executed: sudo ufw reset 10.0.0.50",
    "[2025-11-02 15:19:54] workstation-02 syslog: root@192.168.50.10 executed command: sudo ufw reset",
]

print("Testing individual lines with 'sudo ufw reset':")
for i, line in enumerate(test_lines, 1):
    event = parser.parse_log_line(line)
    if event:
        print(f"{i}. ✓ DETECTED")
        print(f"   Type: {event.get('event_type')}")
        print(f"   Severity: {event.get('severity')}")
        print(f"   Source IP: {event.get('source_ip', 'N/A')}")
        print(f"   Description: {event.get('description')}")
        print(f"   Command: {event.get('command', 'N/A')}")
    else:
        print(f"{i}. ✗ NOT DETECTED")
    print()

print("\nTesting from log file:")
events = parser.get_recent_events(20)
print(f"Found {len(events)} events from log file")
if events:
    for i, event in enumerate(events[:10], 1):
        print(f"{i}. {event.get('event_type')} - {event.get('severity')}")
        print(f"   IP: {event.get('source_ip', 'N/A')}")
        print(f"   Description: {event.get('description')}")
        if event.get('raw_line'):
            print(f"   Raw: {event.get('raw_line')[:80]}")
        print()
else:
    print("No events detected. Check if firewall.log has 'sudo ufw reset' commands.")






