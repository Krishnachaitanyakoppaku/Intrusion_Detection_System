#!/usr/bin/env python3
"""
Generate sample alerts for testing the web interface
This simulates real IDS alerts being written to logs/alerts.log
"""
import time
from datetime import datetime

def generate_sample_alerts():
    """Generate sample alerts for testing"""
    
    alerts = [
        ("Directory Traversal - Unix Style", "192.168.1.100", 54321, "10.0.0.1", 80, "TCP", 2),
        ("Command Injection - Semicolon", "192.168.1.100", 54322, "10.0.0.1", 80, "TCP", 1),
        ("Malicious File Upload - PHP Shell", "192.168.1.100", 54323, "10.0.0.1", 80, "TCP", 2),
        ("SQL Injection Attempt", "192.168.1.100", 54324, "10.0.0.1", 80, "TCP", 1),
        ("XSS Attack Detected", "192.168.1.100", 54325, "10.0.0.1", 80, "TCP", 2),
        ("DNS Query", "192.168.1.105", 54326, "8.8.8.8", 53, "UDP", 5),
        ("HTTPS Traffic", "192.168.1.100", 54327, "1.1.1.1", 443, "TCP", 5),
        ("ICMP Flood Attack", "192.168.1.100", 0, "10.0.0.1", 0, "ICMP", 4),
    ]
    
    print("Generating sample alerts...")
    
    with open('logs/alerts.log', 'a', encoding='utf-8') as f:
        for alert in alerts:
            msg, src_ip, src_port, dst_ip, dst_port, proto, priority = alert
            
            alert_line = (
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"ALERT: {msg} | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"Protocol: {proto} | Priority: {priority}\n"
            )
            
            f.write(alert_line)
            print(f"✅ Generated: {msg}")
            time.sleep(0.5)  # Small delay between alerts
    
    print("\n✅ All sample alerts generated!")
    print("Check the web interface to see them in the Live Alerts panel")

if __name__ == "__main__":
    import os
    os.makedirs('logs', exist_ok=True)
    generate_sample_alerts()

