#!/usr/bin/env python3

import scapy.all as scapy
import scapy.layers import http

def sniff(interface):
#store=False arg tells scapy to not store packets
#prn arg allows call back func to be executed every time packet is captured
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
                                                                                       
def process_sniffed_packet():
#print only HTTPRequest packets
    if packet.haslayer(http.HTTPRequest):
#only displaying packets with Raw layer
        if packet.haslayer(scapy.Raw):
#scapy.Raw will only print the raw layer of the packet no additional info
#.load will only print load info from raw layer
            print(packet[scapy.Raw].load)

#sniff interface (hardcoded)
sniff("eth0")