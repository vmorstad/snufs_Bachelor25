import re
from cve_api import CVEAPI

class CPEAPI:
    def __init__(self):
        self.cve_api = CVEAPI()

    def extract_service_info(self, port_line):
        """
        Extract service name and version from Nmap port scan output.
        Example input: "80/tcp open  http    Apache httpd 2.4.41"
        """
        match = re.match(r'\d+/tcp\s+open\s+(\w+)\s+(.*)', port_line)
        if match:
            service = match.group(1)
            version = match.group(2).strip()
            return service, version
        return None, None

    def create_cpe_name(self, service, version):
        """
        Create a CPE name from service and version information
        Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        """
        # Map common services to their CPE format
        service_mapping = {
            'apache': ('apache', 'http_server'),
            'http': ('apache', 'http_server'),
            'ssh': ('openssh', 'openssh'),
            'mysql': ('mysql', 'mysql'),
            'postgresql': ('postgresql', 'postgresql'),
            'nginx': ('nginx', 'nginx'),
            'tomcat': ('apache', 'tomcat'),
            'iis': ('microsoft', 'internet_information_services'),
            'samba': ('samba', 'samba'),
            'ftp': ('proftpd', 'proftpd'),
            'telnet': ('microsoft', 'telnet'),
            'smb': ('microsoft', 'windows'),
            'rdp': ('microsoft', 'windows'),
            'vnc': ('realvnc', 'vnc_server')
        }

        # Default to service name if no mapping found
        vendor, product = service_mapping.get(service.lower(), (service.lower(), service.lower()))
        
        # Clean version string, use '*' if version is None
        version = (version or '*').replace(' ', '_').lower()
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def analyze_device_vulnerabilities(self, device_info):
        """
        Analyze a device's vulnerabilities based on its OS and open ports.
        Returns a list of dicts, each with cpe, cpe_title, and cves.
        """
        cpe_vuln_groups = []
        seen_cpes = set()

        # Check OS vulnerabilities
        if device_info.get('os'):
            os_match = re.match(r'([^(]+)(?:\(([^)]+)\))?', device_info['os'])
            if os_match:
                os_name = os_match.group(1).strip()
                os_version = os_match.group(2).strip() if os_match.group(2) else None
                os_cpe = self.create_cpe_name(os_name, os_version)
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