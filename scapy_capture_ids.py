#!/usr/bin/env python3
"""
Lightweight Scapy packet capture for IDS
- Captures packets and appends to logs/all_packets.log
- Interface is optional; if omitted, Scapy will choose a default
"""

import os
import sys
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except Exception as e:
    print(f"[ERROR] Failed to import Scapy: {e}", file=sys.stderr)
    sys.exit(1)


LOG_DIR = 'logs'
PACKETS_LOG = os.path.join(LOG_DIR, 'all_packets.log')


def format_entry(pkt) -> str:
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    size = len(pkt)

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = 0
        dport = 0
        proto = 'IP'
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = 'TCP'
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = 'UDP'
        elif ICMP in pkt:
            proto = 'ICMP'
        return f"{ts} | {src_ip}:{sport} -> {dst_ip}:{dport} | {proto} | Size: {size}B\n"
    else:
        return f"{ts} | Unknown packet | Size: {size}B\n"


def handle(pkt):
    try:
        line = format_entry(pkt)
        with open(PACKETS_LOG, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as e:
        print(f"[WARN] Failed to log packet: {e}", file=sys.stderr)


def main():
    # Ensure logs folder exists
    os.makedirs(LOG_DIR, exist_ok=True)
    # Clear file on start
    try:
        open(PACKETS_LOG, 'w', encoding='utf-8').close()
    except Exception:
        pass

    iface = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg and arg.lower() != 'any':
            iface = arg

    print(f"[IDS] Starting Scapy capture (iface={'default' if iface is None else iface}) ...")
    try:
        sniff(iface=iface, prn=handle, store=0)
    except KeyboardInterrupt:
        print("\n[IDS] Capture stopped by user.")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()


