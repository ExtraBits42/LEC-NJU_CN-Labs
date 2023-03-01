from dis import dis
from struct import pack
from switchyard.lib.userlib import *
from tkinter.messagebox import NO
import switchyard

def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

def test_myrouter_arp_respond():
    s = TestScenario("myrouter arp respond tests")
    s.add_interface("router-eth0", "10:00:00:00:00:01", "192.168.100.1")
    s.add_interface("router-eth1", "10:00:00:00:00:02", "192.168.100.2")
    s.add_interface("router-eth2", "10:00:00:00:00:03", "192.168.100.3")
    s.add_interface("router-eth3", "10:00:00:00:00:04", "192.168.100.4")
    # test1 : received a packet, but not a arp request
    not_arp_pkt = new_packet(
        "20:00:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
        "172.168.100.1",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent('router-eth0', not_arp_pkt, display=Ethernet),
        ("eth0 received a packet but not a arp request!")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("because not a arp request, so do nothing")
    )
    # test2 : received a packet, is a arp request, but targetprotoip not exist in router's interfaces
    test2_pkt = create_ip_arp_request("20:00:00:00:00:01",  "192.168.200.1", "192.168.255.1")
    s.expect(
        PacketInputEvent('router-eth0', test2_pkt, display=Ethernet),
        ("eth0 received a packet but targetprotoaddr not exists in router interfaces")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("because not have interface's ip is same with targetprotoaddr, so do nothing")
    )
    # test3 : received a packet, is a arp request, and router have interface's ip is same with targetprotoaddr
    test3_request_pkt = create_ip_arp_request("20:00:00:00:00:01", "192.168.200.1", "192.168.100.1")
    test3_reply_pkt = create_ip_arp_reply("10:00:00:00:00:01", "20:00:00:00:00:01", "192.168.100.1", "192.168.200.1")
    s.expect(
        PacketInputEvent('router-eth0', test3_request_pkt, display=Ethernet),
        ("eth0 received a packet which is a arp request, and router have a interface whose ip addr is same with targetprotoaddr")
    )
    s.expect(
        PacketOutputEvent('router-eth0', test3_reply_pkt, display=Ethernet),
        ("router sents the arp reply through the interface which the arp request arrived")
    )
    return s

scenario = test_myrouter_arp_respond()