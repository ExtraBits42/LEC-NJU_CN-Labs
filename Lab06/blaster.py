#!/usr/bin/env python3

from encodings import utf_8
from threading import Timer
# from msilib import sequence
import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.ip = '192.168.100.1'   # FAQ01: hardcode
        self.targetip = blasteeIp
        self.send_num = int(num)
        self.try_num = int(num)
        self.pkt_payload_maxlen = int(length)
        # SW
        self.swlen = int(senderWindow)
        self.lhs = 1
        self.rhs = 1
        # Simulation Window
        self.acked = []     # 0 : not acked, 1 : acked
        # Timeout
        self.timeout = float(timeout) / 1000.0    # 300ms
        self.recv_timeout = float(recvTimeout) / 1000.0    # 100ms
        self.timer = 0
        
        # statistic info
        self.begin_time = 0
        self.total_tx_time = 0
        self.number_retx = 0
        self.number_timeout = 0
        self.goodtx_bytes = 0       # bytes number of successfully trans
        self.retx_bytes = 0         # bytes number of retrans
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        '''Receive ACK from blastee'''
        _, fromIface, packet = recv
        # Update statistic info
        self.total_tx_time = time.time() - self.begin_time
        # Get seqnum and update SW
        seqnum = int.from_bytes(packet[3].to_bytes()[:4], byteorder='big')
        if seqnum < self.lhs:
            return None
        log_info(f"I got a packet seqnum:{seqnum} LHS:{self.lhs} RHS:{self.rhs}")
        # Some packet Acked
        self.acked[seqnum-self.lhs] = 1
        if self.acked[0] == 1:
            self.timer = time.time()
        # Try to move LHS
        ori_lhs = self.lhs
        while self.lhs - ori_lhs + 1 <= len(self.acked) and self.acked[self.lhs - ori_lhs] == 1:
            self.lhs += 1
            # Decrease send_num
            self.send_num -= 1
        # Update timer only when LHS moved + FAQ03
        if(self.lhs != ori_lhs):
            self.timer = time.time()
        # Update SW
        self.acked = self.acked[self.lhs - ori_lhs:]
        

    def handle_no_packet(self):
        '''Not received ACK from blastee, so send packet'''
        # log_info("Didn't receive anything")
        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        # Finish Ethernet header
        pkt[Ethernet].src = '10:00:00:00:00:00'
        pkt[Ethernet].dst = '40:00:00:00:00:00'
        # Finish IPv4 header
        pkt[IPv4].src = self.ip
        pkt[IPv4].dst = self.targetip
        pkt[IPv4].ttl = 64
        pkt[IPv4].protocol = IPProtocol.UDP
        
        if self.rhs - self.lhs + 1 < self.swlen and self.try_num > 0:
            self.send_new_pkt(pkt)
            self.try_num -= 1
        elif(time.time() - self.timer >= self.timeout):
            self.repeat_pkts(pkt)
        else:
            pass
        
    def send_new_pkt(self, pkt): # + FAQ06: one packet each time
        '''SW is not full, send new packet'''
        log_info(f"I'm send new packet {self.rhs}")
        # Add SequenceNum
        pkt += self.rhs.to_bytes(4, byteorder='big')
        # Add Payload Length
        # data = f"hhhhhhhh".encode(encoding="UTF-8")
        # data += bytes(100-len(data))
        data = bytes(self.pkt_payload_maxlen)
        pkt += len(data).to_bytes(2, byteorder='big')
        # Add variable payload
        pkt += data
        # Update SW
        self.rhs += 1
        self.acked.append(0)
        # Send Packet
        self.net.send_packet('blaster-eth0', pkt)
        # Initialize statistic info
        if self.rhs == 2:
            self.timer = time.time()
            self.begin_time = time.time()
        self.goodtx_bytes += len(data)
    
    def repeat_pkts(self, pkt):
        '''Timeout, Repeat Packets'''
        log_info(f"I'm repeating original packet {self.lhs}")
        # FAQ03: How timeout work?
        for index, val in enumerate(self.acked):
            # If not ACKed, repeat it!
            if val == 0:
                # Add SequenceNum
                pkt += (self.lhs + index).to_bytes(4, byteorder='big')
                # Add Payload Length
                # data = f"hhhhhhhh".encode(encoding="UTF-8")
                # data += bytes(100-len(data))
                data = bytes(self.pkt_payload_maxlen)
                pkt += len(data).to_bytes(2, byteorder='big')
                # Add variable payload
                pkt += data
                # Send Packet and reset timer
                self.net.send_packet('blaster-eth0', pkt)
                # Update statistic info
                self.number_retx += 1
                self.retx_bytes += len(data)
        # Update statistic info
        self.number_timeout += 1
    
    def show_info(self):
        '''show statistic information'''
        log_info("Statistic Info:")
        log_info(f'Total TX time:        {self.total_tx_time:.1f} in seconds')
        log_info(f'Number of reTX:       {self.number_retx}')
        log_info(f'Number of coarse TOs: {self.number_timeout}')
        log_info(f'Throughput(Bps):      {(self.goodtx_bytes + self.retx_bytes) / self.total_tx_time:.1f}')
        log_info(f'Goodput(Bps):         {self.goodtx_bytes / self.total_tx_time:.1f}')

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            # Task Done
            log_info(f"Now send_num is {self.send_num}")
            if self.send_num <= 0:
                break
            
            try:
                recv = self.net.recv_packet(timeout=self.recv_timeout)     # 100ms
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
        # Show Statistic Info
        self.show_info()

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
