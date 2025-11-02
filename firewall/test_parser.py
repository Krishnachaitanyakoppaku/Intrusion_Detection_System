#!/usr/bin/env python3
"""
Test script to generate sample firewall log entries for testing the parser
"""

import os
import time
from datetime import datetime

# Get the firewall logs directory
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(script_dir, 'logs', 'firewall.log')

# Ensure log directory exists
os.makedirs(os.path.dirname(log_file), exist_ok=True)

# Sample firewall log entries
sample_logs = [
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] client-hostname kernel: [12345.678] user=root uid=0 sudo: root : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/sbin/ufw --force reset",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] server-01 auth.log: user admin executed: sudo ufw disable",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] workstation-02 syslog: root@192.168.50.10 executed command: iptables -F",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] client-03 security.log: sudo iptables --flush detected from 192.168.50.15",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] server-01 kernel: systemctl stop firewalld executed by user admin",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] client-05 syslog: firewall-cmd --reload executed successfully",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] workstation-01 auth.log: chmod 777 /etc/passwd attempted by user test",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] server-02 security: ufw allow 22/tcp added from 192.168.50.20",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] client-01 syslog: iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] server-03 auth: su - root executed by user admin",
]

def append_logs():
    """Append sample logs to the firewall log file"""
    print(f"Adding {len(sample_logs)} sample firewall log entries to {log_file}")
    
    with open(log_file, 'a', encoding='utf-8') as f:
        for log_entry in sample_logs:
            f.write(log_entry + '\n')
            print(f"Added: {log_entry[:80]}...")
    
    print(f"\n✅ Sample logs added to {log_file}")
    print("Now check the web interface at http://localhost:8080 to see the firewall events!")

if __name__ == '__main__':
    append_logs()


