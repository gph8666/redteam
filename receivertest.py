from scapy.all import *
import logging

# Configure logging to write to a file for persistence
logging.basicConfig(filename='icmp_sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def icmp_sniffer():
    # Callback function to process each sniffed packet
    def packet_callback(packet):
        # Check if the packet contains an ICMP layer
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            icmp_payload = bytes(packet[ICMP].payload)

            # Check if it's an ICMP Echo Request (ping)
            if icmp_type == 8:  # ICMP Type 8 is Echo Request (ping)
                print(f"[*] ICMP Echo Request from {src_ip} to {dst_ip}")
            # Check if it's an ICMP Echo Reply
            elif icmp_type == 0:  # ICMP Type 0 is Echo Reply
                print(f"[*] ICMP Echo Reply from {src_ip} to {dst_ip}")
            
            # Extract payload from ICMP packet (passwords or exfiltrated data)
            if icmp_payload:
                decoded_payload = icmp_payload.decode('utf-8', errors='ignore')  # Decode with error handling
                print(f"[+] Extracted ICMP Payload: {decoded_payload}")
                # Log the payload for further analysis
                logging.info(f"ICMP Payload from {src_ip} to {dst_ip}: {decoded_payload}")

    # Sniff ICMP packets indefinitely, calling the callback for each packet
    sniff(filter="icmp", prn=packet_callback)

# Start the ICMP sniffer
icmp_sniffer()