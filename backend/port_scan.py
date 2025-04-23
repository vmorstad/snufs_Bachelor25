import re
import subprocess

def scan_ports(ip):
    """
    Nmap -sV → parse lines like "80/tcp open http Apache/2.4.41 Ubuntu/18.04"
    into: { port: "80/tcp", service: "http", version: "Apache/2.4.41 Ubuntu/18.04" }
    """
    try:
        out = subprocess.check_output(
            ["nmap", "-sV", ip],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        return [{"port": "", "service": "", "version": f"Error: {e}"}]

    ports = []
    for line in out.splitlines():
        # match lines: "<port>/tcp open <service> <rest...>"
        m = re.match(r"^(\d+/tcp)\s+open\s+(\S+)\s+(.+)$", line)
        if m:
            port, svc, rest = m.groups()
            version = rest.strip()   # ← keep the full remainder as version
            ports.append({
                "port":    port,
                "service": svc,
                "version": version
            })
    return ports
