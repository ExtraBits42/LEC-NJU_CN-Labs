#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
from tkinter.messagebox import NO
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = self.net.interfaces()
        self.arp_table = {}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        for key in list(self.arp_table.keys()):
            if(time.time() >= self.arp_table[key][1]):
                self.arp_table.pop(key)
        arp = packet.get_header(Arp)
        if arp:
            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time() + 1200]    # TTL: current time + 20 minutes
            # show ARP Table information
            log_info(f"ARP Table information here:")
            log_info("===========================")
            for it in self.arp_table.keys():
                log_info(f"{it} | {self.arp_table[it][0]} | {self.arp_table[it][1]}")
            log_info("===========================")
            for it in self.interfaces:
                if it.ipaddr == arp.targetprotoaddr:
                    reply_pkt = create_ip_arp_reply(it.ethaddr, arp.senderhwaddr, it.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, reply_pkt)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
