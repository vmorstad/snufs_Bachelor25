# port_scanner.py
from scapy.all import IP, TCP, sr1
import socket

def scan_device_ports(ip, port_range=(1, 1024)):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=0.5, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            # Send a RST packet to gracefully close the connection
            sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=0.5, verbose=False)
    return open_ports

def grab_service_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner if banner else "No banner received"
    except Exception:
        return None
