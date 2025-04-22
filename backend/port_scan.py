# backend/port_scan.py

import subprocess

def scan_ports(ip_address):
    """
    Use Nmap with service/version detection (-sV) to scan ports on the given IP.
    Returns a list of strings describing open ports.
    """
    try:
        nmap_output = subprocess.check_output(
            ["nmap", "-sV", ip_address],
            universal_newlines=True
        )
        open_ports = [
            line.strip()
            for line in nmap_output.splitlines()
            if "/tcp" in line and "open" in line
        ]
        return open_ports
    except subprocess.CalledProcessError as e:
        return [f"Error scanning ports on {ip_address}: {e}"]
