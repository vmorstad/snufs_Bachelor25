from scapy.all import ARP, Ether, srp, conf
import subprocess

# We start with a function to scan devices in a network range using ARP requests
# We use Scapy to send ARP requests and receive responses from devices in the network
# We use ARP requests to find devices on the local network
def scan_network(network_range):
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, verbose=True)[0]

    # We set the devices we find in a list from the result that came from the scan
    # The result is a list of tuples (sent, received)
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

    # We use Nmap to detect the operating system of the devices we found
    # We run Nmap with the -O flag to enable OS detection
def detect_os(ip_address):
    try:
        # Run Nmap with OS detection (-O flag)
        result = subprocess.check_output(["nmap", "-O", ip_address], universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error running Nmap on {ip_address}: {e}"

if __name__ == "__main__":
    network_range = "192.168.0.0/24"
    print("Scanning network for devices...")
    devices = scan_network(network_range)
    
    if devices:
        print("\nDiscovered devices:")
        for device in devices:
            print(f"IP: {device['ip']} \t MAC: {device['mac']}")
        
        print("\nRunning OS detection on discovered devices:")
        for device in devices:
            ip = device['ip']
            print(f"\nOS detection for {ip}:")
            os_info = detect_os(ip)
            print(os_info)
    else:
        print("No devices discovered. Check your network settings, firewall, or interface.")
    
    print("Scan complete.")
