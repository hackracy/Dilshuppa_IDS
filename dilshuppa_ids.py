import scapy.all as scapy
import sys
from collections import defaultdict
import time

# Dictionary to track connection attempts
connection_attempts = defaultdict(int)

# Time window to detect port scanning activity
SCAN_TIME_WINDOW = 60  # seconds
SCAN_THRESHOLD = 10  # number of packets within the time window

# Timestamp for port scan detection
last_scan_time = time.time()

# Detect SYN scan
def detect_syn_scan(packet):
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
        print(f"[SYN Scan Detected] Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")

# Detect Denial of Service (DoS) - Ping flood
def detect_dos(packet):
    if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 8:  # Echo Request
        print(f"[DoS Attack Detected] Source IP: {packet[scapy.IP].src} sending high ICMP traffic")

# Detect Xmas scan (TCP scan with FIN, PSH, URG flags)
def detect_xmas_scan(packet):
    if packet.haslayer(scapy.TCP):
        flags = packet[scapy.TCP].flags
        if flags == "FPU":  # FIN, PSH, URG
            print(f"[Xmas Scan Detected] Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")

# Detect NULL Scan (TCP scan with no flags set)
def detect_null_scan(packet):
    if packet.haslayer(scapy.TCP):
        flags = packet[scapy.TCP].flags
        if flags == 0:  # No flags
            print(f"[NULL Scan Detected] Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")

# Detect FIN Scan (TCP scan with only FIN flag set)
def detect_fin_scan(packet):
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == "F":  # FIN flag only
            print(f"[FIN Scan Detected] Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")

# Detect ARP Spoofing/Poisoning (ARP replies from unexpected sources)
def detect_arp_spoofing(packet):
    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:  # ARP Reply
            # Check if the ARP reply comes from an unexpected MAC address for a given IP
            if packet[scapy.ARP].psrc not in connection_attempts:
                connection_attempts[packet[scapy.ARP].psrc] = packet[scapy.ARP].hwsrc
            else:
                if connection_attempts[packet[scapy.ARP].psrc] != packet[scapy.ARP].hwsrc:
                    print(f"[ARP Spoofing Detected] IP: {packet[scapy.ARP].psrc} is being spoofed by MAC: {packet[scapy.ARP].hwsrc}")

# Detect Port Scanning - Multiple connection attempts in a short time
def detect_port_scan(packet):
    global last_scan_time

    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        current_time = time.time()

        # If time window passed, reset
        if current_time - last_scan_time > SCAN_TIME_WINDOW:
            connection_attempts.clear()

        connection_attempts[ip_src] += 1

        # If a certain number of connections are made within a short time, consider it a port scan
        if connection_attempts[ip_src] > SCAN_THRESHOLD:
            print(f"[Port Scan Detected] Source IP: {ip_src} made {connection_attempts[ip_src]} attempts in the last {SCAN_TIME_WINDOW} seconds.")
            connection_attempts[ip_src] = 0

        last_scan_time = current_time

# Packet callback function to apply all detections
def packet_callback(packet):
    detect_syn_scan(packet)
    detect_dos(packet)
    detect_xmas_scan(packet)
    detect_null_scan(packet)
    detect_fin_scan(packet)
    detect_arp_spoofing(packet)
    detect_port_scan(packet)

# Start sniffing for a given number of packets
def start_sniffing(packet_count):
    print(f"[*] Starting packet capture for {packet_count} packets...")
    scapy.sniff(count=int(packet_count), prn=packet_callback, store=0)

if __name__ == "__main__":
    # Author Information and Attack Detection Details
    print("""
    ***********************************************
    *      Dilshuppa_IDS by Dilshuppa          *
    *                                           *
    *      Detects the following attacks:      *
    *                                           *
    *  1. SYN Scan                              *
    *  2. Denial of Service (DoS)               *
    *  3. Xmas Scan                             *
    *  4. NULL Scan                             *
    *  5. FIN Scan                              *
    *  6. ARP Spoofing/Poisoning                *
    *  7. Port Scanning                        *
    *                                           *
    ***********************************************
    """)

    if len(sys.argv) != 2:
        print("Usage: dilshuppa_ids <number_of_packets>")
        sys.exit(1)

    packet_count = sys.argv[1]
    start_sniffing(packet_count)
