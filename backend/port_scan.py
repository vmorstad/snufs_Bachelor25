import subprocess

def scan_ports(ip_address):
    try:
        nmap_output = subprocess.check_output(["nmap", "-sV", ip_address], universal_newlines=True)
        open_ports = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return open_ports
    except subprocess.CalledProcessError as e:
        return [f"Error scanning ports on {ip_address}: {e}"]
