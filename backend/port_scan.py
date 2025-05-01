# backend/port_scan.py

import subprocess
import re

def scan_device(ip_address):
    """
    Perform a targeted scan of a device to get open ports, services, and OS information.
    Uses a more efficient scanning strategy to reduce scan time.
    
    Args:
        ip_address (str): IP address to scan
        
    Returns:
        dict: Dictionary containing:
            - ports: List of open ports with service info
            - os: OS information if detected
    """
    try:
        # Run nmap with optimized flags:
        # -sV: Service detection
        # -O: OS detection
        # -T4: Aggressive timing template
        # -p-: Scan all ports
        # --min-rate 1000: Send at least 1000 packets per second
        # --max-retries 1: Reduce retries
        # --version-intensity 5: Balance between speed and accuracy
        cmd = f"nmap -sV -O -T4 -p- --min-rate 1000 --max-retries 1 --version-intensity 5 {ip_address}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running nmap: {result.stderr}")
            return {"ports": [], "os": "Unknown"}
            
        output = result.stdout
        
        # Parse open ports and services
        ports = []
        port_section = False
        for line in output.split('\n'):
            if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
                port_section = True
                continue
            if port_section and line.strip() and not line.startswith('|'):
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0]
                        state = parts[1]
                        service = parts[2]
                        version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        ports.append({
                            "port": port,
                            "state": state,
                            "service": service,
                            "version": version
                        })
            elif port_section and not line.strip():
                port_section = False
                
        # Parse OS information
        os_info = "Unknown"
        for line in output.split('\n'):
            if 'Running:' in line:
                os_info = line.split('Running:')[1].strip()
                break
            elif 'OS details:' in line:
                os_info = line.split('OS details:')[1].strip()
                break
                
        return {
            "ports": ports,
            "os": os_info
        }
        
    except Exception as e:
        print(f"Error scanning device {ip_address}: {e}")
        return {"ports": [], "os": "Unknown"}
