#!/usr/bin/env python3
import sys
import time
import socket
import subprocess

try:
	import requests
except Exception:
	requests = None


def info(msg):
	print(f"[+] {msg}")


def do_http():
	try:
		info("HTTP GET http://example.com")
		if requests:
			requests.get('http://example.com', timeout=5)
		else:
			# Fallback using sockets
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(5)
			s.connect(("93.184.216.34", 80))
			s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			s.recv(1024)
			s.close()
	except Exception as e:
		print(f"HTTP error: {e}")


def do_dns():
	try:
		info("UDP DNS query to 8.8.8.8:53")
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(3)
		# Minimal DNS query for 'example.com'
		query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
		s.sendto(query, ("8.8.8.8", 53))
		try:
			_ = s.recvfrom(512)
		except socket.timeout:
			pass
		s.close()
	except Exception as e:
		print(f"DNS error: {e}")


def do_icmp():
	try:
		info("ICMP ping to 1.1.1.1 (requires privileges)")
		if sys.platform.startswith('win'):
			subprocess.run(["ping", "-n", "2", "1.1.1.1"], check=False)
		else:
			subprocess.run(["ping", "-c", "2", "1.1.1.1"], check=False)
	except Exception as e:
		print(f"ICMP error: {e}")


def do_tcp_connect():
	try:
		info("TCP connect to localhost:22 (may fail if SSH not running)")
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(2)
		try:
			s.connect(("127.0.0.1", 22))
		except Exception:
			pass
		s.close()
	except Exception as e:
		print(f"TCP connect error: {e}")


def main():
	info("Generating test traffic to trigger IDS rules...")
	do_http()
	time.sleep(0.5)
	do_dns()
	time.sleep(0.5)
	do_icmp()
	time.sleep(0.5)
	do_tcp_connect()
	info("Done. Check the web UI live alerts panel.")


if __name__ == "__main__":
	main()
