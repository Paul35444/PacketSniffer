#!/usr/bin/env python

import netfilterqueue

#create instance of NetFilterQueue obj
queue = netfilterqueue.NetfilterQueue()
#invoke method bind to queue number 0 after "," is callback func process_packet
queue.bind(0, process_packet)
queue.run
