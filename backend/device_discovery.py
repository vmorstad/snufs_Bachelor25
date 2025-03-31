from scapy.all import ARP, Ether, srp

def discover_devices(network):
    arp_request = ARP(pdst=network)
    ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
    return devices
