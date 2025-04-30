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
        Uses Nmap service detection data for accurate vulnerability matching.
        """
        vulnerabilities = []
        
        # Check OS vulnerabilities
        if device_info.get('os'):
            # Extract OS name and version if possible
            os_match = re.match(r'([^(]+)(?:\(([^)]+)\))?', device_info['os'])
            if os_match:
                os_name = os_match.group(1).strip()
                os_version = os_match.group(2).strip() if os_match.group(2) else None
                
                # Create CPE name for OS
                os_cpe = self.create_cpe_name(os_name, os_version)
                os_vulns = self.cve_api.search_cves(os_cpe)
                vulnerabilities.extend(os_vulns)
        
        # Check service vulnerabilities
        if device_info.get('ports'):
            for port_info in device_info['ports']:
                service, version = self.extract_service_info(port_info)
                if service and version:
                    # Create CPE name for service
                    service_cpe = self.create_cpe_name(service, version)
                    service_vulns = self.cve_api.search_cves(service_cpe)
                    vulnerabilities.extend(service_vulns)
        
        # Sort by severity (critical -> high -> medium -> low)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'].lower(), 4))
        
        return vulnerabilities

# Create a global instance
cpe_api = CPEAPI()

# Export the function
def analyze_device_vulnerabilities(device_info):
    return cpe_api.analyze_device_vulnerabilities(device_info) 