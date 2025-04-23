# backend/device_discovery.py
import socket
import subprocess
from scapy.all import sr1, IP, ICMP

def detect_os(ip):
    """
    Try Nmap OS detection, then TTL-guess, then fallback to unknown.
    """
    # 1) Nmap OS fingerprint
    try:
        out = subprocess.check_output([
            "nmap", "-O", "--osscan-guess", "--osscan-limit", ip
        ], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("OS details:"):
                return line.split("OS details:")[1].strip()
            if line.startswith("Running:"):
                return line.split("Running:")[1].strip()
    except:
        pass

    # 2) TTL-based guess
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
        if pkt and pkt.ttl:
            ttl = pkt.ttl
            if ttl >= 128:
                return f"Likely Windows (TTL={ttl})"
            return f"Likely Linux/Unix (TTL={ttl})"
    except:
        pass

    return "Unknown OS"

def get_device_name(ip):
    """
    Reverse-DNS lookup.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown device name"
