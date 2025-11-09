import logging,time
from datetime import datetime
from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def log_event(func):
    """
    Decorator to log entry and exit of methods, including args on entry and result on exit.
    For packet details (e.g., in process_packet), the result dict will be logged automatically.
    """
    
    def log_event(*args):
        result = func(*args)
        logger.info(f"{result}")
        return result
    return log_event

def measure_time(func):
    """
    Decorator to measure execution time of a function and add it to the return value.
    Assumes the function returns a dict; adds 'processing_time' key with time in seconds.
    """
    def measure_time(*args):
        start_time = time.perf_counter()
        result = func(*args)
        end_time = time.perf_counter()
        processing_time = end_time - start_time

        # Add timing to result (assume dict; if not, could log instead)
        if isinstance(result, dict):
            result['processing_time'] = processing_time
        else:
            # Fallback: Log if result isn't a dict
            logger.info(f"execution time: {processing_time:.6f} seconds")
        return result
    return measure_time



class PacketSniffer:
    def __init__(self, pcap_file: str):
        '''
        Initalize the PCAP processor with the file path
        Args:
        pcap_file(str) : Path to the pcap file or pcap files
        
        '''
        self.pcap_file = pcap_file
        self.processed_results = []  # Store processed packet results for reporting
        self.packet_counter = 0  # counter for packet numbers


    def read_packets(self, count: int = None):
        """
        Read a random number of packets from the PCAP file if count is None 

        Args :

        count (int) : No of packets needs to be processed
        if count is none : Read random no of packets with the max count being the total no of packets.

        Retruns : 

        List : List of packets Objects
         
           Consideration: 
           1. Arbitrary max range based on the number of packets present in the pcap to avoid the index out of range problem
           2. Reading pcap as file operation.
        """
        
        read_lenght_of_pcap = rdpcap(self.pcap_file)
        if count is None:
           count = random.randint(1, len(read_lenght_of_pcap))
        packet = []
        
        with PcapReader(self.pcap_file) as pcap_reader:
          for i, pkt in enumerate(pcap_reader):
             if i >= count:
                break
             packet.append(pkt)
        return packet
        
    
    @log_event
    @measure_time
    def process_packet(self, packet):
        """
        Parse headers and payload, measure processing time
        Extract the sournce and destination mac address if ethernet layer is present.
        Source, Destination Ip address and Procotol information.

        Args: 

        packet [list] : Packet scapy object

        Returns : 

        Dictionary : Result contains below details
         packet_num (int)
         Timestamp (time)
         src_mac (str)
         dst_mac (str)
         src_dst_ip (str)
         Protocol (str)
         Payload_size (str)
         processing_time  (float in seconds)
        """
        
        # Auto-assign packet number internally
        self.packet_counter += 1 
        packet_num = self.packet_counter

        pkt_timestamp = packet.time
        if pkt_timestamp:
            # Convert epoch time to human readable format.        
            pkt_timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(pkt_timestamp)))
        else:
            pkt_timestamp_str = "Unknown"
        
        # Parse headers: extract layer information
        headers = []
        current_layer = packet

        while current_layer:
            #print(current_layer.name)
            layer_name = current_layer.name
            layer_fields = {field.name: field.value for field in current_layer.fields_desc if hasattr(field, 'value')}
            headers.append({
                'layer': layer_name,
                'fields': layer_fields
            })
            current_layer = current_layer.payload
        
        # Extract raw payload (last layer's data if no more payload)
        payload = bytes(packet.payload) if packet.payload else b''
        
        # Extract MAC addresses if Ethernet layer present
        src_mac = dst_mac = None
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
        # Extract IP addresses if IP layer present
        src_ip = dst_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        
        # Extract protocol if TCP or UDP layer present
        protocol = None
        if packet.haslayer(TCP):
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            protocol = 'UDP'
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
        elif packet.haslayer(BOOTP):
            protocol = 'BOOTP'     
        elif packet.haslayer(ARP):
            protocol = 'ARP' 
        elif packet.haslayer(OSPF_Hdr):
            protocol = 'OSPF'          
        
        result = {
            'packet_num': packet_num,
            'Timestamp': pkt_timestamp_str,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'src_dst_ip': [src_ip,dst_ip],
            'Protocol': protocol,
            'Payload_size' : len(payload)
            #'processing_time': processing_time
        } 
    
        # Store result for reporting
        self.processed_results.append(result)
        return result

    def generate_report(self):
        """
        Print summary of captured packets and statistics

        Self.processed_results is populated from process_packet 
        
        The report contains:
        - Total number of packets read
        - Average processing time per packet
        - Number of packets per type (TCP, UDP, ICMP, etc.)
        - Number of packets per source MAC address

        """

        if not self.processed_results:
            print("No processed results available. Run process_packet first.")
            return
        
        total_packets = len(self.processed_results)
        total_time = sum(r['processing_time'] for r in self.processed_results)
        avg_time = total_time / total_packets if total_packets > 0 else 0
        
        # Protocol stats: Number of packets per type
        protocol_counts = {}
        for r in self.processed_results:
            proto = r['Protocol'] or 'Unknown'
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        # Source MAC stats: Number of packets per source MAC address
        src_mac_counts = {}
        for r in self.processed_results:
            mac = r['src_mac']
            if mac:
                src_mac_counts[mac] = src_mac_counts.get(mac, 0) + 1
        
        print("=== PCAP Processing Report ===")
        print(f"Total Number of Packets Read: {total_packets}")
        print(f"Average Processing Time per Packet: {avg_time:.5f} seconds")

        print("\nNumber of Packets per Type:")
        for proto, count in sorted(protocol_counts.items()):
            print(f"  {proto}: {count}")
        print("\nNumber of Packets per Source MAC Address:")
        for mac, count in sorted(src_mac_counts.items()):
            print(f"  {mac}: {count}")
        print("==============================")


if __name__ == "__main__":
    processor = PacketSniffer('C:/Users/Blackstream/Downloads/sample.pcap')
    
    # Read a specific number of packets (or None for random)
    # Or processor.read_packets() for random
    packets = processor.read_packets()
    
    # Process each packet
    for i, pkt in enumerate(packets):
        result = processor.process_packet(pkt)
    processor.generate_report()    
    
