#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()):
#only get packets that have DNS request response
    if scapy_packet.haslayer(scapy.DNSRR):