# backend/port_scan.py

import subprocess
import re

def scan_device(ip_address):
    """
    Scan a device using Nmap to identify open ports, running services, and operating system.
    Returns:
        'ports': List of dicts with port, state, service, version,
        'os': Detected operating system as a string

    Nmap is called as a subprocess; errors are caught and logged.
    """
    try:

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
