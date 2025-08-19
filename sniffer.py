from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def packet_handler(packet):
    if IP in packet:  # If packet has IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto  # Protocol number

        # Check protocol type
        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"[+] {ip_src} --> {ip_dst} | Protocol: {protocol}")

        # If packet has payload
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            if payload:
                print(f"    Payload: {payload[:50]}...")  # Print first 50 bytes

# Start sniffing (Ctrl+C to stop)
print("Starting packet sniffer... Press CTRL+C to stop.\n")
sniff(prn=packet_handler, count=0)  # count=0 means infinite
