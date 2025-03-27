#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import ssl
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000


# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'xiang%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

os.system(f"ip addr add 192.168.53.11/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')
context.load_verify_locations(cafile="cert.pem")
context.verify_mode = ssl.CERT_REQUIRED

IP_A = "0.0.0.0"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP_A, PORT))
sock.listen()

print(f"VPN server is listening on {IP_A}:{PORT}")
ssl_sock = context.wrap_socket(sock, server_side=True)
conn, addr = ssl_sock.accept()
conn.send(b"Connected to VPN server")
print(f"Client {addr} connected")

while True:
	# This will block until at least one interface is ready
	ready, _, _ = select.select([conn, tun], [], [])
	for fd in ready:
		if fd is conn:
			data = conn.recv(2048)
			pkt = IP(data)
			print(f"From socket <==: {pkt.src} --> {pkt.dst}")
			os.write(tun, bytes(pkt))

		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print(f"From tun ==>: {pkt.src} --> {pkt.dst}")
			conn.send(packet)

