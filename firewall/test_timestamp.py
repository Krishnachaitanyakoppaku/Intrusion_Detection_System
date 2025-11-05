#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from firewall_parser_python import FirewallEventParser

parser = FirewallEventParser()
events = parser.get_recent_events(5)

print(f"Found {len(events)} events\n")

for i, e in enumerate(events[:5], 1):
    print(f"Event {i}:")
    print(f"  Type: {e.get('event_type', 'N/A')}")
    print(f"  Timestamp: {e.get('timestamp', 'Unknown')}")
    print(f"  Source IP: {e.get('source_ip', 'N/A')}")
    print(f"  Severity: {e.get('severity', 'N/A')}")
    print()






