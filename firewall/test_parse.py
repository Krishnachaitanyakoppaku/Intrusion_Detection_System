#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firewall_parser_python import FirewallEventParser

parser = FirewallEventParser()
print(f"Parser library loaded: {parser.lib is not None}")

# Test with actual log lines
test_lines = [
    "[2025-11-02 15:19:54] client-hostname kernel: [12345.678] user=root uid=0 sudo: root : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/sbin/ufw --force reset",
    "[2025-11-02 15:19:54] server-01 auth.log: user admin executed: sudo ufw disable",
    "[2025-11-02 15:19:54] workstation-02 syslog: root@192.168.50.10 executed command: iptables -F",
    "[2025-11-02 15:19:54] client-03 security.log: sudo iptables --flush detected from 192.168.50.15",
    "[2025-11-02 15:19:54] server-01 kernel: systemctl stop firewalld executed by user admin",
]

print("\nTesting individual lines:")
for i, line in enumerate(test_lines, 1):
    event = parser.parse_log_line(line)
    if event:
        print(f"{i}. ✓ {event.get('event_type')} - {event.get('severity')}: {event.get('description')}")
    else:
        print(f"{i}. ✗ No event detected")

print("\nTesting from log file:")
events = parser.get_recent_events(20)
print(f"Found {len(events)} events from log file")
if events:
    for i, event in enumerate(events[:10], 1):
        print(f"{i}. {event.get('event_type')} - {event.get('severity')}: {event.get('description')}")
        if event.get('raw_line'):
            print(f"   Raw: {event.get('raw_line')[:80]}")
else:
    print("No events detected. Check if firewall.log exists and has firewall commands.")

