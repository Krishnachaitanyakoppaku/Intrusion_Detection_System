#!/usr/bin/env python3
"""Test rule validation and file writing"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web_ids import WebIDSHandler

# Create a mock handler instance
class MockRequest:
    def __init__(self, path, data):
        self.path = path
        self.data = data
        self.headers = {}
        self.response_sent = False
        self.response_data = None
        self.response_status = None
    
    def read(self, length):
        return self.data.encode()
    
    def write(self, data):
        self.response_data = data.decode()
    
    def get(self, key, default=None):
        return str(len(self.data)) if key == 'Content-Length' else default

# Test rule that matches active.rules format
test_rule = 'alert icmp any any -> any any (msg:"Test ICMP";priority:3);'

print(f"Testing rule: {test_rule}")
print("=" * 70)

# Test validation
handler = WebIDSHandler(None, None, None)
valid, err = handler._validate_rule_syntax(test_rule)
print(f"Validation result: {'PASS' if valid else 'FAIL'}")
if not valid:
    print(f"Error: {err}")
    sys.exit(1)

# Test normalization
normalized = handler._normalize_rule(test_rule)
print(f"Normalized rule: {normalized}")

# Test file writing
print("\nTesting file append...")
result = handler._append_to_active_rules_if_missing(test_rule)
print(f"Append result: {'SUCCESS' if result else 'FAILED (might already exist)'}")

# Verify file was written
print("\nChecking active.rules file...")
rules_file = os.path.join(os.path.dirname(__file__), 'rules', 'active.rules')
if os.path.exists(rules_file):
    with open(rules_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        print(f"File has {len(lines)} lines")
        if test_rule.strip() in [l.strip() for l in lines]:
            print("✓ Rule found in file!")
        else:
            print("✗ Rule not found in file")
else:
    print("✗ active.rules file not found")

print("\nTest completed!")

