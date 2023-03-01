from dis import dis
from struct import pack
from sys import displayhook
from tkinter import Pack
from switchyard.lib.userlib import *

def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def test_myswitch_traffic():
    s = TestScenario("basic switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')
    s.add_interface('eth4', '10:00:00:00:00:05')
    s.add_interface('eth5', '10:00:00:00:00:06')
    s.add_interface('eth6', '10:00:00:00:00:07')
    '''
    testcase for traffic
    '''
    pkt1to0 = new_packet(
        "30:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.2",
        "172.168.100.1"
    )
    pkt2to0 = new_packet(
        "40:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.3",
        "172.168.100.1"
    )
    pkt3to0 = new_packet(
        "50:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.4",
        "172.168.100.1"
    )
    pkt4to0 = new_packet(
        "60:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.5",
        "172.168.100.1"
    )
    pkt5to0 = new_packet(
        "70:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.5",
        "172.168.100.1"
    )
    pkt6to0 = new_packet(
        "80:00:00:00:00:01",
        "20:00:00:00:00:01",
        "172.168.100.7",
        "172.168.100.1"
    )
    pkt0to6 = new_packet(
        "20:00:00:00:00:01",
        "80:00:00:00:00:01",
        "172.168.100.1",
        "172.168.100.7"
    )
    
    s.expect(
        PacketInputEvent('eth0', pkt0to6, display=Ethernet),
        ("The eth0 first send packet, and not eth0 exist in switch table")
    )
    s.expect(
        PacketOutputEvent('eth1', pkt0to6, 'eth2', pkt0to6, 'eth3', pkt0to6,
                          'eth4', pkt0to6, 'eth5', pkt0to6, 'eth6', pkt0to6,
                          display=Ethernet),
        ("Now the eth6-item has not existed in switch table, the packet should be forward to all ports except eth0")
    )
    for i in range(5):
        s.expect(
            PacketInputEvent('eth1', pkt1to0, display=Ethernet),
            ("eth1 send packet to eth0")
        )
        s.expect(
            PacketOutputEvent('eth0', pkt1to0, display=Ethernet),
            ("eth0 exist in switch table, switch should only forward packet to eth0")
        )
    for i in range(5):
        s.expect(
            PacketInputEvent('eth2', pkt2to0, display=Ethernet),
            ("eth2 send packet to eth0")
        )
        s.expect(
            PacketOutputEvent('eth0', pkt2to0, display=Ethernet),
            ("eth0 exist in switch table, switch should only forward packet to eth0")
        )
    for i in range(5):
        s.expect(
            PacketInputEvent('eth3', pkt3to0, display=Ethernet),
            ("eth3 send packet to eth0")
        )
        s.expect(
            PacketOutputEvent('eth0', pkt3to0, display=Ethernet),
            ("eth0 exist in switch table, switch should only forward packet to eth0")
        )
    s.expect(
        PacketInputEvent('eth6', pkt6to0, display=Ethernet),
        ("eth6 send packet to eth0")
    )
    s.expect(
        PacketOutputEvent('eth0', pkt6to0, display=Ethernet),
        ("eth0 exist in switch table, switch should only forward packet to eth0")
    )
    s.expect(
        PacketInputEvent('eth5', pkt5to0, display=Ethernet),
        ("eth5 first send packets to eth0")
    )
    s.expect(
        PacketOutputEvent('eth0', pkt5to0, display=Ethernet),
        ("Now the eth6-item has not existed in switch table, the packet should be forward to all ports except eth0")
    )
    # now, eth6-item should be deleted
    s.expect(
        PacketInputEvent('eth0', pkt0to6, display=Ethernet),
        ("eth0 send packets to eth6")
    )
    s.expect(
        PacketOutputEvent('eth1', pkt0to6, 'eth2', pkt0to6, 'eth3', pkt0to6,
                          'eth4', pkt0to6, 'eth5', pkt0to6, 'eth6', pkt0to6,
                          display=Ethernet),
        ("Now the eth6-item has not existed in switch table, the packet should be forward to all ports except eth0")
    )
    return s


scenario = test_myswitch_traffic()