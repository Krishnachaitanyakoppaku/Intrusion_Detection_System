#!/usr/bin/env python3
"""Quick test to verify alert system works"""
import time
from datetime import datetime

# Clear and add a new alert to test
alert_msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ALERT: TEST - System Working | 192.168.1.100:54321 -> 10.0.0.1:80 | Protocol: TCP | Priority: 1"

with open('logs/alerts.log', 'a', encoding='utf-8') as f:
    f.write(alert_msg + '\n')
    f.flush()

print("✅ Test alert added to logs/alerts.log")
print(f"Alert: {alert_msg}")
print("\nNow check the web UI - you should see this alert appear!")

