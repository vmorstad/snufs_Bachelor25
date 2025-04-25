import re
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Quick check if a port is open using socket connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except:
        return False

def scan_common_ports(ip: str) -> List[int]:
    """Quick scan of common ports to identify open ones."""
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080
    ]
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(is_port_open, ip, port): port 
            for port in common_ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
    
    return sorted(open_ports)

def get_service_details(ip: str, port: int) -> Dict[str, str]:
    """Get detailed service information for a specific port."""
    try:
        # Try socket service name lookup first
        service_name = socket.getservbyport(port)
    except:
        service_name = "unknown"
    
    result = {
        "port": f"{port}/tcp",
        "service": service_name,
        "version": ""
    }
    
    # Use Nmap for version detection
    try:
        cmd = ["nmap", "-p", str(port), "-sV", "--version-intensity", "5", ip]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=30)
        
        for line in out.splitlines():
            if str(port) in line and "open" in line:
                parts = line.split(None, 3)  # Split into max 4 parts
                if len(parts) >= 3:
                    result["service"] = parts[2]
                if len(parts) >= 4:
                    result["version"] = parts[3]
                break
    except subprocess.TimeoutExpired:
        print(f"[WARNING] Nmap version scan timed out for {ip}:{port}")
    except Exception as e:
        print(f"[ERROR] Nmap version scan failed for {ip}:{port}: {e}")
    
    return result

def scan_ports(ip: str) -> List[Dict[str, Any]]:
    """
    Enhanced port scanning:
    1. Quick scan common ports first
    2. For open ports, get detailed service info
    Returns list of dicts with port, service, and version info
    """
    try:
        # First do a quick scan of common ports
        open_ports = scan_common_ports(ip)
        
        # Then get detailed info for open ports
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {
                executor.submit(get_service_details, ip, port): port 
                for port in open_ports
            }
            for future in as_completed(future_to_port):
                try:
                    results.append(future.result())
                except Exception as e:
                    port = future_to_port[future]
                    print(f"[ERROR] Failed to get service details for {ip}:{port}: {e}")
        
        return sorted(results, key=lambda x: int(x["port"].split("/")[0]))
        
    except Exception as e:
        print(f"[ERROR] Port scan failed for {ip}: {e}")
        return []
