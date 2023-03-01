from concurrent.futures import thread
from multiprocessing.connection import wait
import time
import threading
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
        self.arp_table = []
        self.forwarding_table = []
        for it in self.interfaces:
            self.forwarding_table.append({
                                            'ipv4network' : IPv4Network((str(IPv4Address(int(it.ipaddr) & int(it.netmask)))) + '/' + str(it.netmask)),
                                            'nextip' : IPv4Address('0.0.0.0'), 
                                            'interface' : it.name
                                        })
        with open('forwarding_table.txt') as fp:
            for line in fp.readlines():
                buffer = line.split()
                self.forwarding_table.append({
                                                'ipv4network' : IPv4Network(buffer[0] + '/' + buffer[1]),
                                                'nextip' : IPv4Address(buffer[2]),
                                                'interface' : buffer[3]
                                            })
        self.waiting_queue = []
        self.send_thread_exit = False
        self.send_thread = None

    ### Handle ARP Packet ###
    def handle_arp_packet(self, arp_header, ifaceName, packet):
        self.arp_table.append({
                                'ipaddr' : arp_header.senderprotoaddr,
                                'macaddr' : arp_header.senderhwaddr,
                                'ttl' : time.time() + 1200
                            })
        if arp_header.operation == ArpOperation.Request:
            for it in self.interfaces:
                if it.ipaddr == arp_header.targetprotoaddr:
                    reply_pkt = create_ip_arp_reply(it.ethaddr, arp_header.senderhwaddr, it.ipaddr, arp_header.senderprotoaddr)
                    self.net.send_packet(ifaceName, reply_pkt)
        elif arp_header.operation == ArpOperation.Reply:
            return None

    ### Handle IPv4 Packet ###
    def handle_ipv4_packet(self, ipv4_header, ifaceName, packet):
        packet[IPv4].ttl -= 1
        for it in self.interfaces:
            if packet[IPv4].dst == it.ipaddr:
                return None
        max_matched_prefixlen = 0
        target_item = {}
        for it in self.forwarding_table:
            if packet[IPv4].dst in it['ipv4network'] and it['ipv4network'].prefixlen > max_matched_prefixlen:
                max_matched_prefixlen = it['ipv4network'].prefixlen
                target_item = it
        if max_matched_prefixlen == 0:
            return None
        for it in self.interfaces:
            if it.name == target_item['interface']:
                target_interface = it
        waitpacket = WaitPacket(target_item['nextip'], target_interface, packet)
        self.waiting_queue.append(waitpacket)

    ### Handle Packet ###
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp_header = packet.get_header(Arp)
        ipv4_header = packet.get_header(IPv4)
        if arp_header:
            self.handle_arp_packet(arp_header, ifaceName, packet)
        elif ipv4_header:
            self.handle_ipv4_packet(ipv4_header, ifaceName, packet)

    ### Try To Forward ###
    def forward_packet(self):
        while True:
            if self.send_thread_exit:
                break
            if len(self.waiting_queue) == 0:
                continue
            waitpkt = self.waiting_queue[0]
            nextmac = None
            for arp_it in self.arp_table:
                if arp_it['ipaddr'] == waitpkt.nextip:
                    nextmac = str(arp_it['macaddr'])
            if nextmac:
                waitpkt.packet[Ethernet].src = waitpkt.interface.ethaddr
                waitpkt.packet[Ethernet].dst = nextmac
                self.net.send_packet(waitpkt.interface.name, waitpkt.packet)
                self.waiting_queue.remove(waitpkt)
            elif waitpkt.arp_cnt >= 5:
                self.waiting_queue.remove(waitpkt)
            elif waitpkt.arp_cnt < 5:
                if time.time() - waitpkt.latest_arp_time < 1:
                    pass
                else:
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
                    self.net.send_packet(waitpkt.interface.name, waitpkt.arp_request)
                    waitpkt.arp_cnt += 1
                    waitpkt.latest_arp_time = time.time()
    def receive(self):
        while True:
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
        self.send_thread_exit = True
        self.net.shutdown()

    ### Message Loop ###
    def start(self):
        self.send_thread = threading.Thread(target=self.forward_packet)
        self.send_thread.start()
        self.receive()

def main(net):
    router = Router(net)
    router.start()