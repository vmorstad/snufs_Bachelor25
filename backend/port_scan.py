# backend/port_scan.py
import subprocess
import re

# ============================================================================
# Configuration
# ============================================================================

# OS-specific port lists for targeted scanning
WINDOWS_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3389,8080"
LINUX_PORTS = "20,21,22,23,25,53,80,110,111,139,143,443,445,993,995,3306,3389,8080"
APPLE_PORTS = "22,53,80,443,445,548,631,3283,5000,5900,62078"  # Added Apple-specific ports

# ============================================================================
# Port Scanning Functions
# ============================================================================

def _get_ports_to_scan(os_info):
    """
    Determine which ports to scan based on OS information.
    
    Args:
        os_info (str): OS information string
    
    Returns:
        str or None: Comma-separated list of ports to scan, or None for full scan
    """
    if not os_info:
        return None
        
    os_info_lower = os_info.lower()
    if 'windows' in os_info_lower:
        return WINDOWS_PORTS
    elif 'linux' in os_info_lower:
        return LINUX_PORTS
    elif any(term in os_info_lower for term in ['mac', 'darwin', 'apple']):
        return APPLE_PORTS
    return None

def _build_nmap_command(ip_address, ports):
    """
    Build the Nmap command with appropriate parameters.
    
    Args:
        ip_address (str): Target IP address
        ports (str or None): Ports to scan
    
    Returns:
        str: Complete Nmap command
    """
    if ports:
        return f"nmap -sV -T4 -p {ports} --version-intensity 5 {ip_address}"
    return f"nmap -sV -T4 -p- --min-rate 1000 --max-retries 1 --version-intensity 5 {ip_address}"

def _parse_port_line(line):
    """
    Parse a single line of port information from Nmap output.
    
    Args:
        line (str): Single line of Nmap output
    
    Returns:
        dict or None: Port information dictionary if valid, None otherwise
    """
    parts = line.split()
    if len(parts) >= 3:
        return {
            "port": parts[0],
            "state": parts[1],
            "service": parts[2],
            "version": ' '.join(parts[3:]) if len(parts) > 3 else ''
        }
    return None

def _parse_nmap_output(output):
    """
    Parse Nmap output to extract port information.
    
    Args:
        output (str): Raw Nmap output
    
    Returns:
        list: List of dictionaries containing port information
    """
    ports = []
    port_section = False
    
    for line in output.split('\n'):
        # Start of port section
        if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
            port_section = True
            continue
            
        # Parse port information
        if port_section and line.strip() and not line.startswith('|'):
            if '/tcp' in line or '/udp' in line:
                port_info = _parse_port_line(line)
                if port_info:
                    ports.append(port_info)
                    
        # End of port section
        elif port_section and not line.strip():
            port_section = False
            
    return ports

def scan_device(ip_address, os_info=None):
    """
    Main function to scan a device for open ports and services.
    
    Args:
        ip_address (str): The IP address to scan
        os_info (str, optional): OS information to optimize scan parameters
    
    Returns:
        dict: Contains 'ports' key with list of port information dictionaries
              Each port dict contains: port, state, service, version
    """
    try:
        # 1. Determine scan parameters based on OS
        ports = _get_ports_to_scan(os_info)
        
        # 2. Build and execute Nmap command
        cmd = _build_nmap_command(ip_address, ports)
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running nmap: {result.stderr}")
            return {"ports": []}
            
        # 3. Parse and return results
        return {
            "ports": _parse_nmap_output(result.stdout)
        }
        
    except Exception as e:
        print(f"Error scanning device {ip_address}: {e}")
        return {"ports": []}
