#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firewall_parser_python import FirewallEventParser

parser = FirewallEventParser()
events = parser.get_recent_events(30)

event_types = {}
for e in events:
    etype = e.get('event_type', 'unknown')
    event_types[etype] = event_types.get(etype, 0) + 1

print("Detected Event Types:")
print("=" * 50)
for etype, count in sorted(event_types.items()):
    print(f"  {etype}: {count} events")

print(f"\nTotal events detected: {len(events)}")
print(f"Unique event types: {len(event_types)}")

