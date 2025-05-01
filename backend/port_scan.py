# backend/port_scan.py

import subprocess
import re

def scan_device(ip_address):
    """
    Perform a comprehensive scan of a device including:
    - Open ports
    - Service detection
    - OS detection
    - Version detection
    
    Returns a dictionary containing:
    - ports: List of open ports with service info
    - os: Detected operating system
    """
    try:
        # Use -A for aggressive scan, -O for OS detection, -sV for service/version detection
        nmap_cmd = ["nmap", "-A", "-O", "-sV", "-p-", ip_address]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running Nmap: {result.stderr}")
            return {"ports": [], "os": "Unknown"}
            
        # Parse the output
        output = result.stdout
        ports = []
        os_info = "Unknown"
        
        # Extract open ports with service information
        for line in output.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                ports.append(line)
            
            # Extract OS information
            if "OS details:" in line:
                os_match = re.search(r'OS details: ([^,]+)', line)
                if os_match:
                    os_info = os_match.group(1)
            elif "OS CPE:" in line:
                cpe_match = re.search(r'cpe:/[^:]+:([^:]+):', line)
                if cpe_match:
                    os_info = cpe_match.group(1).replace('_', ' ').title()
        
        return {
            "ports": ports,
            "os": os_info
        }
    except Exception as e:
        print(f"Error scanning device {ip_address}: {e}")
        return {"ports": [], "os": "Unknown"}
