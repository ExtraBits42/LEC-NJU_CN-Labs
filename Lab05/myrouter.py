#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from multiprocessing.connection import wait
import time
from tkinter.messagebox import NO
import switchyard
from switchyard.lib.userlib import *

from testcases.router3_testscenario_template import get_raw_pkt

class WaitPacket:
    ### WaitPacket Initialization ###
    def __init__(self, nextip, interface, packet, ifaceName):
        self.nextip = packet[IPv4].dst if nextip == IPv4Address('0.0.0.0') else nextip
        self.interface = interface
        self.packet = packet
        self.latest_arp_time = -2
        self.arp_cnt = 0
        self.arp_request = 0
        self.ifaceName = ifaceName

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
        
    def get_raw_pkt(pkt, xlen):
        pkt = deepcopy(pkt)
        i = pkt.get_header_index(Ethernet)
        if i >= 0:
            del pkt[i]
        b = pkt.to_bytes()[:xlen]
        return b

    ### ICMP Error ###
    def icmp_error(self, ori_pkt, err_type, err_code, ifaceName):
        # Find interface which receive packet causes the ICMP error
        for it in self.interfaces:
            if it.name == ifaceName:
                interface = it
                break
        # Build IP Header
        ip_header = IPv4()
        ip_header.dst = ori_pkt[IPv4].src
        ip_header.src = interface.ipaddr
        ip_header.protocol = IPProtocol.ICMP
        ip_header.ttl = 64
        ip_header.ipid = 0
        # Build ICMP error message
        # Include original packet information(28 bytes)
        oridata = deepcopy(ori_pkt)
        i = oridata.get_header_index(Ethernet)
        del oridata[i]
        icmp = ICMP()
        icmp.icmptype = err_type
        icmp.icmpcode = err_code
        # Mark the length of original packet
        icmp.icmpdata.origdgramlen = len(ori_pkt)
        icmp.icmpdata.data = oridata.to_bytes()[:28]
        # Build Packet
        icmp_error_pkt = Ethernet() + ip_header + icmp
        # Lookup forwarding table and add to waiting queue
        max_matched_prefixlen = 0
        for it in self.forwarding_table:
            if icmp_error_pkt[IPv4].dst in it['ipv4network'] and it['ipv4network'].prefixlen > max_matched_prefixlen:
                max_matched_prefixlen = it['ipv4network'].prefixlen
                target_item = it
        if max_matched_prefixlen == 0:
            return None
        for it in self.interfaces:
            if it.name == target_item['interface']:
                target_interface = it
        waitpkt = WaitPacket(target_item['nextip'], target_interface, icmp_error_pkt, ifaceName)
        tmp = target_item['nextip']
        log_info(f'Wow!{tmp}')
        self.waiting_queue.append(waitpkt)
    
    ### Handle ICMP Packet###
    def handle_icmp_request_packet(self, icmp_header, ifaceName, packet):
        log_info(f'Receive ICMP Request::Src:{packet[IPv4].src} > Dst:{packet[IPv4].dst}')
        # Build ICMP echo Reply packet
        echo_reply = ICMP()
        echo_reply.icmptype = ICMPType.EchoReply
        echo_reply.icmpdata.sequence = icmp_header.icmpdata.sequence
        echo_reply.icmpdata.identifier = icmp_header.icmpdata.identifier
        echo_reply.icmpdata.data = icmp_header.icmpdata.data
        reply_ip_header = IPv4()
        reply_ip_header.dst = packet[IPv4].src
        reply_ip_header.src = packet[IPv4].dst
        reply_ip_header.ttl = 64
        ehternet_header = Ethernet()
        ehternet_header.ethertype = EtherType.IPv4
        echo_reply_pkt = ehternet_header + reply_ip_header + echo_reply
        # Lookup forwarding table and add to waiting queue
        max_matched_prefixlen = 0
        for it in self.forwarding_table:
            if echo_reply_pkt[IPv4].dst in it['ipv4network'] and it['ipv4network'].prefixlen > max_matched_prefixlen:
                tmp = it['ipv4network']
                tmp1 = it['nextip']
                log_info(f'{echo_reply_pkt[IPv4].dst} >< {tmp} >< {tmp1}')
                max_matched_prefixlen = it['ipv4network'].prefixlen
                target_item = it
        if max_matched_prefixlen == 0:
            return None
        for it in self.interfaces:
            if it.name == target_item['interface']:
                target_interface = it
        waitpkt = WaitPacket(target_item['nextip'], target_interface, echo_reply_pkt, ifaceName)
        self.waiting_queue.append(waitpkt)

    ### Handle IPv4 Packet ###
    def handle_ipv4_packet(self, ipv4_header, ifaceName, packet):
        # If Targetip belongs to one of router interfaces, do nothing
        for it in self.interfaces:
            if packet[IPv4].dst == it.ipaddr:
                icmp_header = packet.get_header(ICMP)
                # If received a ICMP Request
                if icmp_header and icmp_header.icmptype == ICMPType.EchoRequest:
                    self.handle_icmp_request_packet(icmp_header, ifaceName, packet)
                else:
                    self.icmp_error(packet, ICMPType.DestinationUnreachable, 3, ifaceName)
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
            self.icmp_error(packet, ICMPType.DestinationUnreachable, 0, ifaceName)
            return None
        # Decrease TTL
        # FAQ02 If DestinationUnreachable and TTL Zero at the same time, send DestinationUnreachable error message
        packet[IPv4].ttl -= 1
        if packet[IPv4].ttl == 0:
            self.icmp_error(packet, ICMPType.TimeExceeded, 0, ifaceName)
            return None
        # Find interface
        for it in self.interfaces:
            if it.name == target_item['interface']:
                target_interface = it
        # Add to waiting queue
        waitpacket = WaitPacket(target_item['nextip'], target_interface, packet, ifaceName)
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
        for it in self.waiting_queue:
            log_info(f'Waiting Queue: NextIP: {it.nextip} | IPv4 Dst: {it.packet[IPv4].dst}')
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
                    log_info(f'Send Packet!::Send Packet {it.packet} to Interface {it.interface.name}')
                    self.delete_queue.append(it)
        # No matched item exits in ARP Table!
        # ARP Request time not less than 5
        elif waitpkt.arp_cnt >= 5:
            for it in self.waiting_queue:
                # FAQ03 only once
                if it.packet[IPv4].dst == self.waiting_queue[0].packet[IPv4].dst:
                    self.icmp_error(it.packet, ICMPType.DestinationUnreachable, 1, it.ifaceName)
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