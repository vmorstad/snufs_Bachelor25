import re
from cve_api import CVEAPI
import subprocess

class CPEAPI:
    def __init__(self):
        self.cve_api = CVEAPI()

    def extract_service_info(self, port_line):
        """
        Extract service name and version from Nmap port scan output.
        Example input: "80/tcp open  http    Apache httpd 2.4.41"
        """
        match = re.match(r'(\d+/tcp)\s+open\s+(\w+)(?:\s+([\w.\-]+))?(?:\s+([\d\.]+))?', port_line)
        if match:
            service = match.group(2)
            # Try to get version from group 4, or group 3 if it looks like a version
            version = match.group(4) or (match.group(3) if match.group(3) and re.match(r'\\d', match.group(3)) else None)
            return service, version
        return None, None

    def create_cpe_name(self, service, version):
        """
        Create a CPE name from service and version information
        Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        Only generate CPEs for real products with known CVEs.
        """
        # Only include real products with CVEs
        service_mapping = {
            'apache': ('apache', 'http_server'),
            'http': ('apache', 'http_server'),
            'nginx': ('nginx', 'nginx'),
            'mysql': ('mysql', 'mysql'),
            'postgresql': ('postgresql', 'postgresql'),
            'mariadb': ('mariadb', 'mariadb'),
            'ssh': ('openssh', 'openssh'),
            'ftp': ('proftpd', 'proftpd'),
            'smb': ('microsoft', 'windows'),
            'rdp': ('microsoft', 'windows'),
            'vnc': ('realvnc', 'vnc_server'),
            'express': ('expressjs', 'express'),
            'node': ('nodejs', 'nodejs'),
            # Add more as you encounter new banners
        }
        if service.lower() not in service_mapping:
            return None  # Skip generic/non-product services
        vendor, product = service_mapping[service.lower()]
        version = (version or '*').replace(' ', '_').lower()
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def analyze_device_vulnerabilities(self, device_info):
        """
        Analyze a device's vulnerabilities based on its OS and open ports.
        Returns a list of dicts, each with cpe, cpe_title, and cves.
        """
        cpe_vuln_groups = []
        seen_cpes = set()

        # Expanded OS mapping
        os_mapping = {
            # Windows
            'Microsoft Windows 10': ('microsoft', 'windows', '10'),
            'Microsoft Windows 11': ('microsoft', 'windows', '11'),
            'Microsoft Windows 7': ('microsoft', 'windows', '7'),
            'Microsoft Windows 8': ('microsoft', 'windows', '8'),
            'Microsoft Windows XP': ('microsoft', 'windows_xp', '*'),
            # Mac
            'Apple Mac OS X': ('apple', 'mac_os_x', '*'),
            'Mac OS X': ('apple', 'mac_os_x', '*'),
            'macOS': ('apple', 'mac_os_x', '*'),  # Use mac_os_x for all Mac versions
            # Linux (common distros)
            'Ubuntu': ('canonical', 'ubuntu_linux', '*'),
            'Debian': ('debian', 'debian_linux', '*'),
            'CentOS': ('centos', 'centos', '*'),
            'Red Hat': ('redhat', 'enterprise_linux', '*'),
            'Fedora': ('fedoraproject', 'fedora', '*'),
            'Arch Linux': ('archlinux', 'arch_linux', '*'),
            'Kali Linux': ('offensive_security', 'kali_linux', '*'),
            'Linux': ('linux', 'linux_kernel', '*'),
            # Add more as you encounter them!
        }

        # Check OS vulnerabilities
        if device_info.get('os'):
            os_match = re.match(r'([^(]+)(?:\(([^)]+)\))?', device_info['os'])
            if os_match:
                os_name = os_match.group(1).strip()
                os_version = os_match.group(2).strip() if os_match.group(2) else None
                os_name_clean = os_name.split('|')[0].strip()
                vendor, product, default_version = os_mapping.get(os_name_clean, (os_name_clean.lower(), os_name_clean.lower(), os_version or '*'))
                # For Mac, try to extract version from os_name if not present
                if product == 'mac_os_x':
                    version_match = re.search(r'\d+[\.\d]*', os_name)
                    version = version_match.group(0) if version_match else (os_version or default_version)
                elif default_version == '*' and os_version is None:
                    version_match = re.search(r'\d+[\.\d]*', os_name_clean)
                    version = version_match.group(0) if version_match else '*'
                else:
                    version = os_version or default_version
                os_cpe = f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                if os_cpe not in seen_cpes:
                    os_vulns = self.cve_api.search_cves(os_cpe)
                    cpe_vuln_groups.append({
                        "cpe": os_cpe,
                        "cpe_title": f"{os_name} {os_version or ''}".strip(),
                        "cves": os_vulns
                    })
                    seen_cpes.add(os_cpe)

        # Check service vulnerabilities
        if device_info.get('ports'):
            for port_info in device_info['ports']:
                service, version = self.extract_service_info(port_info)
                if service:
                    service_cpe = self.create_cpe_name(service, version)
                    if not service_cpe:
                        continue  # Skip generic/non-product services
                    if service_cpe not in seen_cpes:
                        service_vulns = self.cve_api.search_cves(service_cpe)
                        cpe_vuln_groups.append({
                            "cpe": service_cpe,
                            "cpe_title": f"{service} {version or ''}".strip(),
                            "cves": service_vulns
                        })
                        seen_cpes.add(service_cpe)

        # Optionally, sort by number of CVEs or severity
        cpe_vuln_groups.sort(key=lambda x: -len(x['cves']))
        return cpe_vuln_groups

# Create a global instance
cpe_api = CPEAPI()

# Export the function
def analyze_device_vulnerabilities(device_info):
    return cpe_api.analyze_device_vulnerabilities(device_info)

def scan_ports(ip):
    # Use -A -O -sV for best detection
    nmap_cmd = ["nmap", "-A", "-O", "-sV", "-p-", ip]
    result = subprocess.run(nmap_cmd, capture_output=True, text=True)
    return result.stdout.splitlines() 