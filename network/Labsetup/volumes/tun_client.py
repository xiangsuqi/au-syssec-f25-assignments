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
print(f"Interface Name: {ifname}")

os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")
os.system(f"ip route add 192.168.60.0/24 dev {ifname}")


context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain('cert.pem', 'key.pem')
context.load_verify_locations(cafile="cert.pem")
context.verify_mode = ssl.CERT_REQUIRED

SERVER_IP = '10.9.0.11'
SERVER_PORT = 9090

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ssl_sock = context.wrap_socket(sock, server_hostname=SERVER_IP)
ssl_sock.connect((SERVER_IP, SERVER_PORT))
data = ssl_sock.recv(2048)
print(data.decode('utf-8'))

while True:
    # This will block until at least one interface is ready
    ready, _, _ = select.select([ssl_sock, tun], [], [])

    for fd in ready:
        if fd is ssl_sock:
            try:
                data = ssl_sock.recv(2048)
                pkt = IP(data)
                print(f"From socket <==: {pkt.src} --> {pkt.dst}")
                os.write(tun, bytes(pkt))
            except Exception as e:
                print(1)
                print(e)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f"From tun ==>: {pkt.src} --> {pkt.dst}")
            ssl_sock.send(packet)
            