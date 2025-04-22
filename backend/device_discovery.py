import re
import socket
from scapy.all import ARP, Ether, srp
import subprocess

def scan_network(network_range):
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=True)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def parse_os_info(nmap_output):
    lines = nmap_output.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("OS details:"):
            return line.replace("OS details:", "").strip()
        elif line.startswith("Running:"):
            return line.replace("Running:", "").strip()
    if "No exact OS matches" in nmap_output:
        return "No exact OS match"
    return "Unknown OS or Version"

def detect_os(ip_address):
    try:
        nmap_result = subprocess.check_output(["nmap", "-O", ip_address], universal_newlines=True)
        os_info = parse_os_info(nmap_result)
        return os_info
    except subprocess.CalledProcessError as e:
        return f"Error running Nmap on {ip_address}: {e}"

def get_device_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown device name"

def scan_ports(ip_address):
    """
    Uses Nmap to perform a port scan with service/version detection (-sV).
    Returns a list of open port lines containing the port number and service info.
    """
    try:
        nmap_output = subprocess.check_output(["nmap", "-sV", ip_address], universal_newlines=True)
        open_ports = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return open_ports
    except subprocess.CalledProcessError as e:
        return [f"Error scanning ports on {ip_address}: {e}"]

if __name__ == "__main__":
    # For standalone testing
    network_range = "192.168.0.0/24"
    print("Scanning network for devices...")
    devices = scan_network(network_range)
    if devices:
        print("\nDiscovered devices:")
        for device in devices:
            print(f"IP: {device['ip']}\tMAC: {device['mac']}")
        print("\nRunning OS and Port detection on discovered devices:")
        for device in devices:
            ip = device['ip']
            print(f"\nResults for {ip}:")
            print("OS Info:", detect_os(ip))
            print("Port Scan:", scan_ports(ip))
    else:
        print("No devices discovered. Check your network settings, firewall, or interface.")
    print("Scan complete.")
