#!/usr/bin/python

# ARP Spoofing detect script and send to syslog server.
# Author: Anton Molotkov (DarkCat)
# Usage ./main
# Tested on: Linux
# Dependencies: scapy, netsyslog

import time
from scapy.all import *
import netsyslog
import syslog

def send_syslog():
    global src
    loggers = netsyslog.Logger()
    loggers.add_host("192.168.1.175")
    loggers.log(syslog.LOG_USER, syslog.LOG_NOTICE, "Alert! Attack from %s" % src)

arp_table = {}
def arp_inspection(pkt):
    if not pkt.haslayer(ARP): return
    op = pkt[ARP].op
    global src
    src = pkt.getlayer(Ether).src
    if op == 1:
        arp_table[src] = time.time()
    if op == 2:
       dst = pkt.getlayer(Ether).dst 
       if dst in arp_table:
          time_arp_req = arp_table.pop(dst, None)
          if int(time.time() - time_arp_req) > 5:  
              print "Alert! Attack from %s" % src
              send_syslog()
          else:
              print "Alert! Attack from %s" % src
              send_syslog()
sniff(filter='arp', prn=arp_inspection)

