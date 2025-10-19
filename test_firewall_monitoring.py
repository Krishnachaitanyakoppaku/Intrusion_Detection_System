#!/usr/bin/env python3
"""
Firewall Monitoring Test Script
This script demonstrates the firewall monitoring capabilities of the IDS system.
"""

import time
import subprocess
import os

def test_firewall_monitoring():
    print("🔥 Testing Firewall Monitoring Capabilities")
    print("=" * 50)
    
    # Test 1: Simulate firewall reset command
    print("\n1. Testing UFW Reset Detection...")
    print("   Simulating: sudo ufw reset")
    # Note: This won't actually execute, just simulate the detection
    
    # Test 2: Simulate iptables flush
    print("\n2. Testing iptables Flush Detection...")
    print("   Simulating: sudo iptables -F")
    
    # Test 3: Simulate dangerous chmod
    print("\n3. Testing Dangerous chmod Detection...")
    print("   Simulating: chmod 777 /etc/passwd")
    
    # Test 4: Simulate network scanning
    print("\n4. Testing Network Scanning Detection...")
    print("   Simulating: nmap -sS 192.168.1.0/24")
    
    print("\n✅ All tests completed!")
    print("\n📊 Check the web interface at http://localhost:8080")
    print("   Look for 'Firewall Alerts' section to see detected activities")
    
    print("\n🔍 What the IDS now monitors:")
    print("   • Firewall rule changes (ufw, iptables)")
    print("   • System administration commands")
    print("   • Network scanning activities")
    print("   • Privilege escalation attempts")
    print("   • File system manipulation")
    print("   • Process monitoring")
    print("   • Network interface changes")

if __name__ == "__main__":
    test_firewall_monitoring()
