#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.ip = '192.168.200.1'   # FAQ01: hardcode
        self.targetip = blasterIp
        self.recv_num = int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        # log_info(f"Pkt: {packet}")
        # log_info(f"{type(packet[3])}")
        
        # Packet: | Ethernet | IPv4 | UDP | sequence_num(4bytes) | length(2bytes) | vpayload |
        # -> ACK: | Ethernet | IPv4 | UDP | sequence_num(4bytes) | payload(8bytes) |
        
        # build headers and set address
        ack = Ethernet() + IPv4() + UDP()
        # finish Etheret header
        ack[Ethernet].src = '20:00:00:00:00:00'
        ack[Ethernet].dst = '40:00:00:00:00:00'
        # finish IPv4 header
        ack[IPv4].src = self.ip
        ack[IPv4].dst = self.targetip
        ack[IPv4].protocol = IPProtocol.UDP
        ack[IPv4].ttl = 64
        
        seq_num = int.from_bytes(packet[3].to_bytes()[0:4], 'big')
        log_info(f"I got a packet from {fromIface} which sequence_num is {seq_num}")
        
        # build sequence number
        ack += packet[3].to_bytes()[0:4]
        # build 8bytes payload
        freelen = int.from_bytes(packet[3].to_bytes()[4:6], 'big')
        if freelen >= 8:
            ack += packet[3].to_bytes()[6:14]
        else:
            ack += packet[3].to_bytes()[6:] + bytes(8-freelen)
        
        # send packet
        self.net.send_packet('blastee-eth0', ack)

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
