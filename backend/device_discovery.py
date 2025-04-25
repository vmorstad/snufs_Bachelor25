# backend/device_discovery.py
import socket
import subprocess
from scapy.all import ARP, Ether, srp
import platform
import re

def discover_network_devices(subnet="192.168.1.0/24"):
    """
    Actively discover devices on the network using ARP scanning.
    Returns list of discovered IP addresses.
    """
    try:
        # Create ARP request packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and get response
        result = srp(packet, timeout=3, verbose=False)[0]
        
        # Extract IP addresses of responding hosts
        devices = []
        for sent, received in result:
            devices.append(received.psrc)
            
        return devices
    except Exception as e:
        print(f"[ERROR] Network discovery failed: {e}")
        return []

def detect_os(ip):
    """
    Enhanced OS detection using multiple methods.
    """
    os_info = {"name": "Unknown OS", "version": "", "confidence": "low"}
    
    # 1. Try Nmap OS detection first (most accurate)
    try:
        out = subprocess.check_output([
            "nmap", "-O", "--osscan-guess", "--osscan-limit", 
            "-T4", "--max-retries", "2", ip
        ], text=True, stderr=subprocess.DEVNULL, timeout=30)
        
        for line in out.splitlines():
            line = line.strip()
            if "OS details:" in line:
                os_info["name"] = line.split("OS details:")[1].strip()
                os_info["confidence"] = "high"
                # Try to extract version
                version_match = re.search(r'\b\d+\.?\d*\b', os_info["name"])
                if version_match:
                    os_info["version"] = version_match.group()
                return os_info
    except:
        pass

    # 2. Try TTL-based detection (less accurate)
    try:
        out = subprocess.check_output(["ping", "-n", "1", ip] if platform.system() == "Windows" 
                                    else ["ping", "-c", "1", ip], 
                                    text=True, stderr=subprocess.DEVNULL)
        
        ttl_match = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl >= 128:
                os_info["name"] = "Windows"
                os_info["confidence"] = "medium"
            elif ttl >= 64:
                os_info["name"] = "Linux/Unix"
                os_info["confidence"] = "medium"
    except:
        pass

    return os_info

def get_device_name(ip):
    """
    Enhanced device name detection.
    """
    names = []
    
    # Try reverse DNS
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        if hostname:
            names.append(hostname)
        names.extend(aliases)
    except:
        pass
        
    # Try NetBIOS name (Windows networks)
    try:
        out = subprocess.check_output(
            ["nbtscan", "-q", ip], 
            text=True, 
            stderr=subprocess.DEVNULL
        )
        match = re.search(r"(\S+)\s+<00>", out)
        if match:
            names.append(match.group(1))
    except:
        pass
        
    return names[0] if names else "Unknown device name"
