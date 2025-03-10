from scapy.all import ARP, Ether, srp, IP, TCP, sr1

# Scan for active devices in the network
def scan_network(network):
    print("\n[+] Scanning network for active devices...")
    arp_request = ARP(pdst=network)
    ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# Scan open ports on a target device using Scapy (Replaces Nmap)
def scan_ports(target_ip, port_range=(1, 1024)):
    print(f"Scanning {target_ip} for open ports...")
    open_ports = []

    for port in range(port_range[0], port_range[1] + 1):
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")  # SYN scan
        response = sr1(packet, timeout=0.5, verbose=False)

        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK received
            open_ports.append(port)
            # Send RST to close connection
            sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=0.5, verbose=False)

    return open_ports

# Run scans
network = "192.168.1.0/24"
devices = scan_network(network)

for device in devices:
    print(f"Found Device: {device['ip']} ({device['mac']})")
    open_ports = scan_ports(device['ip'], port_range=(1, 100))  # Scan only 1-100 for speed
    print(f"  Open Ports: {open_ports}")
