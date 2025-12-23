 """
Network Sniffer Project 🌐
 
Description:
This project was developed during my internship for capture and analyze live network traffic.
It bridges theoretical knowledge with practical experience in networking, cybersecurity, and Python programming.

Key Learnings and Skills:
- Python programming and network packet analysis
- Understanding of TCP, UDP, IP protocols
- Handling encrypted HTTPS traffic
- Using Scapy and raw sockets for packet sniffing
- Version control and collaboration using Git

Project Highlights:
- Captures live network packets and displays source/destination IPs, ports, protocols, and payloads
- Demonstrates encrypted HTTPS traffic analysis (payload appears encrypted)
- Provides insight into real-world network traffic for cybersecurity learning

Tools & Technologies:
- Python 3
- Scapy library
- Kali Linux / Parrot OS

Author: [Your Name]
Date: [Date]

"""

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

