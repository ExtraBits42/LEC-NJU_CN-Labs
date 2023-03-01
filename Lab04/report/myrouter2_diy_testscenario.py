from dis import dis
from struct import pack
from sys import displayhook
from switchyard.lib.userlib import *
from tkinter.messagebox import NO
import switchyard
import time

def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def test_myrouter_forwarding_arprequest():
    s = TestScenario("myrouter forward packet and arp request tests")
    s.add_interface('router-eth0', '10:00:00:00:00:00', '192.168.100.1/30')
    s.add_interface('router-eth1', '10:00:00:00:00:01', '192.168.101.1/30')
    s.add_interface('router-eth2', '10:00:00:00:00:02', '192.168.102.1/30')
    # test1 : received a packet which ipv4 header's target ip exist in one of router interfaces
    test1pkt = new_packet(
        '30:00:00:00:00:01',
        '10:00:00:00:00:02',
        '192.181.99.1',
        '192.168.102.1'
    )
    s.expect(
        PacketInputEvent('router-eth0', test1pkt, display=Ethernet),
        ("eth0 received a packet which target ip exists in one of router interfaces")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ('except router do nothing, drop the packet')
    )
    # test2 : received a packet which have no matched item in forwarding table, should do nothing
    test2pkt = new_packet(
        '30:00:00:00:00:02',
        '40:00:00:00:00:01',
        '192.181.99.2',
        '172.181.0.1'
    )
    s.expect(
        PacketInputEvent('router-eth0', test2pkt, display=Ethernet),
        ('eth0 received a packet which not have matched item int forwarding table')
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ('expect router do nothing, drop the packet')
    )
    # test3 : received a packet which have matched item in forwarding table and can resolve it
    test3pkt = new_packet(
        '30:00:00:00:00:03',
        '40:00:00:00:00:02',
        '192.181.99.3',
        '172.16.128.9'
    )
    test3pkt_out = test3pkt
    test3pkt_out[Ethernet].src =  '10:00:00:00:00:01'
    test3pkt_out[Ethernet].dst = '50:00:00:00:00:01'
    test3pkt_out[IPv4].ttl = 1
    s.expect(
        PacketInputEvent('router-eth0', test3pkt, display=Ethernet),
        ('eth1 received a packet which have matched item in forwarding table, and can resolve it')
    )
    test3_arp_request = create_ip_arp_request('10:00:00:00:00:01', '192.168.101.1', '10.10.0.254')
    s.expect(
        PacketOutputEvent('router-eth1', test3_arp_request, display=Ethernet),
        ('router should send arp request from eth1 for resolving target ip address 10.10.0.254')
    )
    test3_arp_reply = create_ip_arp_reply('50:00:00:00:00:01', '10:00:00:00:00:01', '10.10.0.254', '192.168.101.1')
    s.expect(
        PacketInputEvent('router-eth1', test3_arp_reply, display=Ethernet),
        ('router should receive a arp reply')
    )
    s.expect(
        PacketOutputEvent('router-eth1', test3pkt_out, exact=False, display=Ethernet),
        ('router should forward the table from eth1')
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ('the packet has been successfully sent, do nothing')
    )
    # test4 : received a packet which have matched item in forwarding table but can't resolve it
    test4pkt = new_packet(
        '30:00:00:00:00:04',
        '40:00:00:00:00:03',
        '192.181.99.4',
        '172.16.0.99'
    )
    s.expect(
        PacketInputEvent('router-eth2', test4pkt, display=Ethernet),
        ('eth2 received a packet which have matched item in forwarding table, but can"t resolve it')
    )
    test4_arp_request = create_ip_arp_request('10:00:00:00:00:00', '192.168.100.1', '192.168.1.2')
    prev_time = time.time()
    i = 0
    while i < 5:
        if time.time() - prev_time >= 1:
            prev_time = time.time()
            i += 1
            s.expect(
                PacketOutputEvent('router-eth0', test4_arp_request, display=Ethernet),
                (f'the {i}st time send ARP Request')
            )
    # test5 : after 5 ARP request, do nothing
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ('after 5 ARP Request, do nothing')
    )
    return s

scenario = test_myrouter_forwarding_arprequest()