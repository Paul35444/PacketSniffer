#!/usr/bin/env python3

import scapy.all as scapy
import scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #store=False arg tells scapy to not store packets
                                                                          #prn arg allows call back func to be executed every time packet is captured
                                                                                       
def process_sniffed_packet():
    if packet.haslayer(http.HTTPRequest): #print only HTTPRequest packets
        print(packet)

sniff("eth0") #sniff interface