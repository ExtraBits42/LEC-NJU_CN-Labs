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
    # lru表
    ages = {}
    switch_table_maxlen = 5

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        # 接收到非因特网帧，直接退出
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        # 接收到目的地址为交换机本机的包，直接丢弃
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.src not in switch_table.keys():  # 不在交换机表中
                # 如果已经满了，使用LRU算法删除一个表项
                if len(switch_table) >= switch_table_maxlen:
                    del_key = max(zip(ages.values(), ages.keys()))[1]
                    log_info(f"The switch table is full, but still need to add new item, so LRU Algorithm order us to delete the item: {del_key}, age: {ages[del_key]}")
                    del switch_table[del_key]
                    del ages[del_key]
                # 添加新的表项，并为其设置age
                switch_table[eth.src] = fromIface
                ages[eth.src] = 0
                log_info(f"Add new item to switch table: {eth.src}, age: {ages[eth.src]}")
            elif (eth.src in switch_table.keys()) and (switch_table[eth.src] != fromIface):     # 在交换机表中，但端口改变了
                # 更新表项，基于LRU，拓扑变化，不更新其LRU信息
                switch_table[eth.src] = fromIface
                log_info(f"The structure of topo has been changed, so update switch table item {eth.src}'s port to {fromIface}")
            elif (eth.src in switch_table.keys()):      # 在交换机中，且端口未改变
                ages[eth.src] = 0
            # 老化其他所有表项
            ages = {key : val + 1 if key != eth.src else val for key, val in ages.items()}
            if (eth.dst not in switch_table.keys() or eth.dst == "ff:ff:ff:ff:ff:ff"):      # 未找到表项/接收到广播帧，向接收端口之外的所有端口进行泛洪
                log_info(f"Not Found item, so forward packet to all other ports except received port")
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        net.send_packet(intf, packet)
            else:           # 找到了对应表项且不为广播帧，直接查询对应表项转发到相应端口
                # 依据表项转发包，更新该表项的age，并且老化其他表项
                log_info(f"Found item: {eth.dst}, age: {ages[eth.dst]} in switch_table!")
                net.send_packet(switch_table[eth.dst], packet)
                ages[eth.dst] = 0
                ages = {key : val + 1 if key != eth.dst else val for key, val in ages.items()}
    net.shutdown()