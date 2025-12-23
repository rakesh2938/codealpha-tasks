from scapy.all import sniff, IP, TCP, UDP, Raw
print("Starting packet capture... Press Ctrl+C to stop.")
def packet_analyzer(packet):
    if IP in packet:
        print("\n==============================")
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)
 if TCP in packet:
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)
 elif UDP in packet:
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)
 if packet.haslayer(Raw):
            print("Payload        :", packet[Raw].load)
# Start sniffing (requires root/admin)
sniff(prn=packet_analyzer)
 
