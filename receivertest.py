from scapy.all import *
import logging


logging.basicConfig(filename='icmp_sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def icmp_sniffer():

    def packet_callback(packet):
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            icmp_payload = bytes(packet[ICMP].payload)

            if icmp_type == 8:  
                print(f"[*] ICMP Echo Request from {src_ip} to {dst_ip}")
            # Check if it's an ICMP Echo Reply
            elif icmp_type == 0: 
                print(f"[*] ICMP Echo Reply from {src_ip} to {dst_ip}")
            
            if icmp_payload:
                decoded_payload = icmp_payload.decode('utf-8', errors='ignore')
                print(f"[+] Extracted ICMP Payload: {decoded_payload}")
                logging.info(f"ICMP Payload from {src_ip} to {dst_ip}: {decoded_payload}")

    sniff(filter="icmp", prn=packet_callback)

icmp_sniffer()