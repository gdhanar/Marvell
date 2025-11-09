Overview:

The project implements PacketSniffer class for reading the pcap files and analyze the packets based up on several factors starting from Source and Destination mac address , 
L4 protocol details and other use full information like timestamp and processing time. and it will generate reports.

Installtion requirements : 

1 pip install scapy
2 Python 3.8+ recommended.

Usage : 

python PacketSniffer.py

Class Structure. 
   -  __init__ (file Path) Open Pacp file for read/write 
   -  Read_packets (count = None ): Read packets 
   -  process_packet = process the packet provide the below infomation in dict (decorators for logging and measuring time)
                - Packet number
                - Timestamp
                - Packet type
                - Source and destination addresses
                - Processing time
                
   -  generate_report = print the packet processed information at higher overview with the below details. 
              - Total number of packets read
              - Average processing time per packet
               - Number of packets per type (TCP, UDP, ICMP, etc.)
               - Number of packets per source MAC address 

