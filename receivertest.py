#!/usr/bin/python3

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
                payload = list(decoded_payload)
                joined_payload = ', '.join(f'{w}' for w in payload)
                finished_list = []
                for c in joined_payload:
                    if c == "'" or c == '"' or c == ',' or c == ' ' or c == '[' or c == ']':
                        continue
                    else:
                        finished_list.append(c)
                finished_list = ''.join(finished_list)
                print(f"[+] Extracted ICMP Payload: {finished_list}")
                logging.info(f"ICMP Payload from {src_ip} to {dst_ip}: {finished_list}")

    sniff(filter="icmp", prn=packet_callback)

icmp_sniffer()
