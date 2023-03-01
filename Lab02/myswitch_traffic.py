'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from struct import pack
from tkinter import E
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # 交换机表
    switch_table = {}
    switch_table_maxlen = 5
    traffic_vols = {}

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
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.src not in switch_table.keys():  # 不在交换机表中
                if len(switch_table) >= switch_table_maxlen:
                    del_key = min(zip(traffic_vols.values(), traffic_vols.keys()))[1]
                    log_info(f"The switch table is full, so delete the least traffic volume: {del_key}, traffic_vols:{traffic_vols[del_key]}")
                    del switch_table[del_key]
                    del traffic_vols[del_key]
                log_info(f"Not found, add the item: {eth.src}, 0 to switch table")
                switch_table[eth.src] = fromIface
                traffic_vols[eth.src] = 0
            elif (eth.src in switch_table.keys()) and (switch_table[eth.src] != fromIface):     # 在交换机表中，但端口改变了
                switch_table[eth.src] = fromIface
                # 基于流量，拓扑改变，保持主机流量计数相同，不将其设置为0
            elif (eth.src in switch_table.keys()):      # 在交换机表中，且端口未改变    -增加流量
                traffic_vols[eth.src] += 1
                log_info(f"increase traffic of item: {eth.src}")
            if (eth.dst not in switch_table.keys() or eth.dst == "ff:ff:ff:ff:ff:ff"):      # 未找到表项/接收到广播帧，向接收端口之外的所有端口进行泛洪
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        net.send_packet(intf, packet)
                log_info(f"Not Found destination item, so broadcast")
            else:           # 找到了对应表项且不为广播帧，直接查询对应表项转发到相应端口    增加表项流量
                traffic_vols[eth.dst] += 1
                net.send_packet(switch_table[eth.dst], packet)
                log_info(f"Found destination item: {eth.dst}")
    net.shutdown()
