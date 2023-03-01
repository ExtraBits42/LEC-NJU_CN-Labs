#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from multiprocessing.connection import wait
import time
from tkinter.messagebox import NO
import switchyard
from switchyard.lib.userlib import *

class WaitPacket:
    ### WaitPacket Initialization ###
    def __init__(self, nextip, interface, packet):
        self.nextip = packet[IPv4].dst if nextip == IPv4Address('0.0.0.0') else nextip
        self.interface = interface
        self.packet = packet
        self.latest_arp_time = -2
        self.arp_cnt = 0
        self.arp_request = 0

class Router(object):
    ### Router Initialization ###
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = self.net.interfaces()
        # ARP Table Initialization
        # | ip address | mac address |
        self.arp_table = []
        # Forwarding Table Initialization
        # | network address / subnet address | next hop address | interface |
        self.forwarding_table = []
        # Initialize from interfaces
        for it in self.interfaces:
            self.forwarding_table.append({
                                            'ipv4network' : IPv4Network((str(IPv4Address(int(it.ipaddr) & int(it.netmask)))) + '/' + str(it.netmask)),
                                            'nextip' : IPv4Address('0.0.0.0'),
                                            'interface' : it.name
                                        })
        # Initialize from txt file
        with open('forwarding_table.txt') as fp:
            for line in fp.readlines():
                buffer = line.split()
                self.forwarding_table.append({
                                                'ipv4network' : IPv4Network(buffer[0] + '/' + buffer[1]),
                                                'nextip' : IPv4Address(buffer[2]),
                                                'interface' : buffer[3]
                                            })
        # Show Forwarding Table information--
        log_info(f'Forwarding Table information here:')
        log_info('===================================')
        for it in self.forwarding_table:
            log_info(f'{it}')
        log_info('===================================')
        # Show Forwarding Table information--
        # Some queues for scheduling
        self.waiting_queue = []
        self.delete_queue = []

    ### Handle ARP Packet ###
    def handle_arp_packet(self, arp_header, ifaceName, packet):
        # Update ARP Table
        self.arp_table.append({
                                'ipaddr' : arp_header.senderprotoaddr,
                                'macaddr' : arp_header.senderhwaddr,
                                'ttl' : time.time() + 1200
                            })
        # Show ARP Table information--
        log_info(f'ARP Table information here:')
        log_info('============================')
        for it in self.arp_table:
            log_info(f'{it}')
        log_info('============================')
        # Show ARP Table information--
        # Handle ARP Request
        if arp_header.operation == ArpOperation.Request:
            for it in self.interfaces:
                if it.ipaddr == arp_header.targetprotoaddr:
                    reply_pkt = create_ip_arp_reply(it.ethaddr, arp_header.senderhwaddr, it.ipaddr, arp_header.senderprotoaddr)
                    self.net.send_packet(ifaceName, reply_pkt)
        # Handle ARP Reply
        elif arp_header.operation == ArpOperation.Reply:
            return None

    ### Handle IPv4 Packet ###
    def handle_ipv4_packet(self, ipv4_header, ifaceName, packet):
        # Decrease TTL
        packet[IPv4].ttl -= 1
        # If Targetip belongs to one of router interfaces, do nothing
        for it in self.interfaces:
            if packet[IPv4].dst == it.ipaddr:
                return None
        # Search matched item in Forwarding Table
        max_matched_prefixlen = 0
        target_item = {}
        for it in self.forwarding_table:
            if packet[IPv4].dst in it['ipv4network'] and it['ipv4network'].prefixlen > max_matched_prefixlen:
                max_matched_prefixlen = it['ipv4network'].prefixlen
                target_item = it
        # If no find matched item, do nothing
        if max_matched_prefixlen == 0:
            return None
        # Find interface
        for it in self.interfaces:
            if it.name == target_item['interface']:
                target_interface = it
        # Add to waiting queue
        waitpacket = WaitPacket(target_item['nextip'], target_interface, packet)
        self.waiting_queue.append(waitpacket)

    ### Handle Packet ###
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp_header = packet.get_header(Arp)
        ipv4_header = packet.get_header(IPv4)
        # ARP Logic
        if arp_header:
            self.handle_arp_packet(arp_header, ifaceName, packet)
        # IPv4 Logic
        elif ipv4_header:
            self.handle_ipv4_packet(ipv4_header, ifaceName, packet)

    ### Try To Forward ###
    def forward_packet(self):
        # Make delete queue empty
        self.delete_queue = []
        # If waiting queue is empty, do nothing
        if len(self.waiting_queue) == 0:
            return None
        # Get the front of waiting queue
        waitpkt = self.waiting_queue[0]
        # For debugg--
        # Show ARP Table information--
        log_info(f'ARP Table information here:')
        log_info('============================')
        for it in self.arp_table:
            log_info(f'{it}')
        log_info('============================')
        # Show ARP Table information--
        log_info(f'waitpkt nextip : {waitpkt.nextip} | waitpkt packet ipv4 dst : {waitpkt.packet[IPv4].dst}')
        # For debugg--
        nextmac = None
        for arp_it in self.arp_table:
            # For debugg--
            tmp = arp_it['ipaddr']
            log_info(f'{tmp}:{type(tmp)} compare {waitpkt.nextip}:{type(waitpkt.nextip)} == {tmp == waitpkt.nextip}')
            # For debugg--
            if arp_it['ipaddr'] == waitpkt.nextip:
                nextmac = str(arp_it['macaddr'])
        # For debugg--
        log_info(f'mac address of next ipaddr : {nextmac}')
        # For debugg--
        # Have matched item exits in ARP Table
        if nextmac:
            for it in self.waiting_queue:
                if it.packet[IPv4].dst == self.waiting_queue[0].packet[IPv4].dst:
                    it.packet[Ethernet].src = waitpkt.interface.ethaddr
                    it.packet[Ethernet].dst = nextmac
                    self.net.send_packet(it.interface.name, it.packet)
                    self.delete_queue.append(it)
        # No matched item exits in ARP Table!
        # ARP Request time not less than 5
        elif waitpkt.arp_cnt >= 5:
            for it in self.waiting_queue:
                if it.packet[IPv4].dst == self.waiting_queue[0].packet[IPv4].dst:
                    self.delete_queue.append(it)
        # ARP Request time less than 5
        elif waitpkt.arp_cnt < 5:
            if time.time() - waitpkt.latest_arp_time < 1:
                return None
            # Build ARP Request
            if waitpkt.arp_cnt == 0:
                ethernet_header = Ethernet()
                ethernet_header.ethertype = EtherType.ARP
                ethernet_header.src = waitpkt.interface.ethaddr
                ethernet_header.dst = 'ff:ff:ff:ff:ff:ff'
                arp_data = Arp(
                                operation=ArpOperation.Request,
                                senderhwaddr=waitpkt.interface.ethaddr,
                                senderprotoaddr=waitpkt.interface.ipaddr,
                                targethwaddr='ff:ff:ff:ff:ff:ff',
                                targetprotoaddr=waitpkt.nextip
                            )
                arp_request_pkt = ethernet_header + arp_data
                waitpkt.arp_request = arp_request_pkt
            # Send ARP Requst and update WaitPacket
            self.net.send_packet(waitpkt.interface.name, waitpkt.arp_request)
            waitpkt.arp_cnt += 1
            waitpkt.latest_arp_time = time.time()
        for it in self.delete_queue:
            self.waiting_queue.remove(it)

    ### Message Loop ###
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            # # ARP Table Timeout
            # buffer = []
            # for it in self.arp_table:
            #     if time.time() < it['ttl']:
            #         buffer.append(it)
            # self.arp_table = buffer
            # Try to forward packets
            self.forward_packet()
            # Some Cases
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.stop()

    ### Message Exit ###
    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()