#!/usr/bin/env python

from sys import displayhook
from switchyard.lib.userlib import *
from copy import deepcopy

def get_raw_pkt(pkt, xlen):
    pkt = deepcopy(pkt)
    i = pkt.get_header_index(Ethernet)
    if i >= 0:
        del pkt[i]
    b = pkt.to_bytes()[:xlen]
    return b

def mk_arpreq(hwsrc, ipsrc, ipdst):
    arp_req = Arp()
    arp_req.operation = ArpOperation.Request
    arp_req.senderprotoaddr = IPAddr(ipsrc)
    arp_req.targetprotoaddr = IPAddr(ipdst)
    arp_req.senderhwaddr = EthAddr(hwsrc)
    arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr("ff:ff:ff:ff:ff:ff")
    ether.ethertype = EtherType.ARP
    return ether + arp_req

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
        icmppkt.icmpcode = ICMPCodeEchoReply.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
        icmppkt.icmpcode = ICMPCodeEchoRequest.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    print(payload)
    return ether + ippkt + icmppkt 

def mk_icmperr(hwsrc, hwdst, ipsrc, ipdst, xtype, xcode=0, origpkt=None, ttl=64):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    icmppkt.icmptype = xtype
    icmppkt.icmpcode = xcode
    if origpkt is not None:
        icmppkt.icmpdata.origdgramlen = len(origpkt)
        xpkt = deepcopy(origpkt)
        i = xpkt.get_header_index(Ethernet)
        if i >= 0:
            del xpkt[i]
        icmppkt.icmpdata.data = xpkt.to_bytes()[:28]
        print(icmppkt.icmpdata.data)

    return ether + ippkt + icmppkt 

def mk_udp(hwsrc, hwdst, ipsrc, ipdst, ttl=64, srcport=10000, dstport=10000, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.UDP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    udppkt = UDP()
    udppkt.src = srcport
    udppkt.dst = dstport
    return ether + ippkt + udppkt + RawPacketContents(payload)

def icmp_tests():
    s = TestScenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
''')

    nottinyttl = '''lambda pkt: pkt.get_header(IPv4).ttl >= 8'''

    # Your tests here
    # Test case 1 : Received a ICMP echo request, and reply it successfully
    test1_rec_pkt = mk_ping(
                                "20:00:00:00:00:01", 
                                "10:00:00:00:00:01", 
                                "172.16.128.1", 
                                "192.168.1.1"
                            )
    s.expect(
        PacketInputEvent('router-eth1', test1_rec_pkt, display=Ethernet),
        ("router-eth1 received a ICMP request")
    )
    test1_sen_arp = mk_arpreq(
                                "10:00:00:00:00:02",
                                "10.10.0.1",
                                "10.10.0.254"
                            )
    s.expect(
        PacketOutputEvent('router-eth1', test1_sen_arp, display=Ethernet),
        ("router-eth1 sent an ARP Request to resolve srcIP")
    )
    test1_rec_arp = mk_arpresp(
                                    test1_sen_arp,
                                    "30:00:00:00:00:01"
                                )
    s.expect(
        PacketInputEvent('router-eth1', test1_rec_arp, display=Ethernet),
        ("router-eth1 received an ARP Reply")
    )
    test1_sen_pkt = mk_ping(
                                "10:00:00:00:00:02",
                                "30:00:00:00:00:01",
                                "192.168.1.1",
                                "172.16.128.1",
                                reply=True
                            )
    s.expect(
        PacketOutputEvent('router-eth1', test1_sen_pkt, display=Ethernet),
        ("router-eth1 sent a ICMP reply")
    )
    # Test case 2 : ICMP ERROR 1 - no matched entry in forwarding table
    test2_rec_pkt = mk_ping(
                                "20:00:00:00:00:01",
                                "20:00:00:00:00:03",
                                "172.16.128.1",
                                "188.0.0.2"
                            )
    s.expect(
        PacketInputEvent('router-eth0', test2_rec_pkt),
        ('router-eth0 received a packet, but no matched entry in forwarding table')
    )
    test2_rec_pkt = mk_ping(
                                "20:00:00:00:00:01",
                                "20:00:00:00:00:03",
                                "172.16.128.1",
                                "188.0.0.2"
                            )
    
    test2_err_pkt = mk_icmperr(
        '10:00:00:00:00:02',
        '30:00:00:00:00:01',
        '192.168.1.1',
        '172.16.128.1',
        ICMPType.DestinationUnreachable,
        0,
        test2_rec_pkt
    )
    s.expect(
        PacketOutputEvent('router-eth1', test2_err_pkt, display=Ethernet),
        ('router-eth0 sent a ICMP error message')
    )
    # Test case 3 : ICMP ERROR 2 - not ICMP Request but dst is one of router interfaces
    test3_rec_pkt = mk_udp(
                                "20:00:00:00:00:01", 
                                "10:00:00:00:00:01", 
                                "172.16.128.1", 
                                "192.168.1.1"
                            )
    s.expect(
        PacketInputEvent('router-eth1', test3_rec_pkt, display=Ethernet),
        ('router-eth1 received a packet, but not ICMP Request and dst is one of router interfaces')
    )
    test3_err_pkt = mk_icmperr(
        '10:00:00:00:00:02',
        '30:00:00:00:00:01',
        '10.10.0.1',
        '172.16.128.1',
        ICMPType.DestinationUnreachable,
        3,
        test3_rec_pkt
    )
    s.expect(
        PacketOutputEvent('router-eth1', test3_err_pkt, display=Ethernet),
        ('router-eth1 sent a ICMP error message')
    )
    # Test case 4 : ICMP ERROR 3 - TTL decrease to zero
    test4_rec_pkt = mk_ping(
                                '30:00:00:00:00:01',
                                '10:00:00:00:00:02',
                                '10.10.0.254',
                                '172.16.64.1',
                                ttl=1
                            )
    s.expect(
        PacketInputEvent('router-eth1', test4_rec_pkt, display=Ethernet),
        ('router-eth1 received a ICMP request, but ttl decread to zero')
    )
    test4_rec_pkt = mk_ping(
                                '30:00:00:00:00:01',
                                '10:00:00:00:00:02',
                                '10.10.0.254',
                                '172.16.64.1',
                                ttl=0
                            )
    test4_err_pkt = mk_icmperr(
                                    '10:00:00:00:00:02',
                                    '30:00:00:00:00:01',
                                    '10.10.0.1',
                                    '10.10.0.254',
                                    ICMPType.TimeExceeded,
                                    0,
                                    test4_rec_pkt
                                )
    s.expect(
        PacketOutputEvent('router-eth1', test4_err_pkt, display=Ethernet),
        ('router-eth1 sent a ICMP error message')
    )
    # Test case 5 : ICMP ERROR 4 - ARP Failed
    test5_rec_pkt = mk_ping(
                                '30:00:00:00:00:01',
                                '10:00:00:00:00:02',
                                '10.10.0.254',
                                '10.100.0.99'
                            )
    s.expect(
        PacketInputEvent('router-eth1', test5_rec_pkt, display=Ethernet),
        ('router-eth1 received a ICMP request, but ARP failed')
    )
    for i in range(5):
        arp = mk_arpreq('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
        s.expect(
            PacketOutputEvent('router-eth2', arp),
            (f'{i}th ARP, buf not received ARP Reply')
        )
    test5_rec_pkt = mk_ping(
                                '30:00:00:00:00:01',
                                '10:00:00:00:00:02',
                                '10.10.0.254',
                                '10.100.0.99',
                                ttl=63
                            )
    test5_err_pkt = mk_icmperr(
                                '10:00:00:00:00:02',
                                '30:00:00:00:00:01',
                                '10.10.0.1',
                                '10.10.0.254',
                                ICMPType.DestinationUnreachable,
                                1,
                                test5_rec_pkt
                            )
    s.expect(
        PacketOutputEvent('router-eth1', test5_err_pkt, display=Ethernet),
        ('router-eth1 sent a ICMP error message')
    )

    return s

scenario = icmp_tests()
