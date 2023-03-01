'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from struct import pack
from tkinter import E
import switchyard
import time
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # 交换机表
    switch_table = {}

    while True:
        try:
            # 根据计时来删除超过10s的表项
            for key in list(switch_table.keys()):
                if time.time() - switch_table[key]["timestamp"] >= 10:
                    log_info(f"The item: {key}, {switch_table[key]['interface']}, {switch_table[key]['timestamp']} expired, now is {time.time()}, so delete it!")
                    del switch_table[key]
            # 时间戳，接收端口，数据包本身
            timestamp, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        # 接收到非因特网包  -直接退出
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        # 接收到发给自己的包    -直接丢弃（本实验中）
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        # 接收到指定地址的包
        else:
            # 查询，为源地址添加表项
            if eth.src not in switch_table.keys():  # 不在交换机表中
                log_info(f"Add item: {eth.src}, {fromIface}, {time.time()} to switch table")
                switch_table[eth.src] = { "interface" : fromIface, "timestamp" : time.time()}
            elif (eth.src in switch_table.keys()) and (switch_table[eth.src]["interface"] != fromIface):     # 在交换机表中，但端口改变了
                # 基于超时，拓扑变化，刷新该主机计时器
                log_info(f"Found src and interface changed, so update item: {eth.src}, {fromIface}, {timestamp} in switch table")
                switch_table[eth.src] = {"interface" : fromIface, "timestamp" : time.time()}
            elif (eth.src in switch_table.keys()):       # 在交换机表中，且端口并未改变，更新时间戳
                log_info(f"Found src and interface not changed, so update timestamp: {eth.src}, {fromIface}, {timestamp}")
                switch_table[eth.src]["timestamp"] = time.time()
            # 查询交换机表中有无目的地址表项，没有则泛洪
            if (eth.dst not in switch_table.keys() or eth.dst == "ff:ff:ff:ff:ff:ff"):      # 未找到表项/接收到广播帧，向接收端口之外的所有端口进行泛洪
                for intf in my_interfaces:
                    if fromIface != intf.name:
                        log_info(f"Not Found or Received a boardcast, so flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:           # 找到了对应表项且不为广播帧，直接查询对应表项转发到相应端口
                log_info(f"Found item: {eth.dst}, { switch_table[eth.dst]['interface'] } in switch table, and sent packet to {eth.dst}")
                net.send_packet(switch_table[eth.dst]["interface"], packet)
    net.shutdown()
