#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    in_num = 0
    out_num = 0
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            in_num = in_num + 1
            log_info (f"in: {in_num} out: {out_num}")
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            in_num = in_num + 1
        else:
            in_num = in_num + 1
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    out_num = out_num + 1
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)
        log_info (f"in: {in_num} out: {out_num}")

    net.shutdown()
