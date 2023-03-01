from dis import dis
from struct import pack
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

def test_myswitch():
    s = TestScenario("basic switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    # test case 1: a frame with broadcast destination should get sent out other ports except ingress
    broadcastpkt = new_packet(
        "20:00:00:00:00:01",
        "ff:ff:ff:ff:ff:ff",
        "172.168.100.1",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent('eth0', broadcastpkt, display=Ethernet),
        ("eth0 received an Ethernet frame with a broadcase destination address"
         "should forward out ports eth1 and eth2")
    )
    s.expect(
        PacketOutputEvent("eth1", broadcastpkt, "eth2", broadcastpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address"
         "has been received by ports eth1 and eth2")
    )
    
    # test case 2: a frame with switch destination should get sent out no any ports
    switchpkt = new_packet(
        "20:00:00:00:00:01",
        "10:00:00:00:00:01",
        "172.168.100.8",
        "172.16.42.2"
    )
    s.expect(
        PacketInputEvent("eth2", switchpkt, display=Ethernet),
        ("An Ethernet frame should arrive on eth2 with destination address"
         "the same as eth0's address")
    )
    s.expect(
        PacketInputTimeoutEvent(1.0),
        ("The switch should not do anything in response to a frame arriving with"
         "a destination address referring to the switch itself")
    )
    
    # test case 3: a frame with destination address which the switch have not learned should be send to other ports
    pkt0to1 = new_packet(
        "80:00:00:00:00:01",
        "90:00:00:00:00:02",
        "172.168.100.1",
        "172.168.100.2"
    )
    s.expect(
        PacketInputEvent('eth0', pkt0to1, display=Ethernet),
        ("eth0 received an Ethernet frame with a destination address which the switch have not learned"
         ", should forward out ports eth1 and eth2")
    )
    s.expect(
        PacketOutputEvent("eth1", pkt0to1, "eth2", pkt0to1, display=Ethernet),
        ("The Ethernet frame should forward out ports eth1 and eth2")
    )
    
    # then the ip address with MAC address: 192.168.800.1 - 10:00:00:00:00:01 should be learned
    
    # test case 4: a frame with destination address which the switch have learned should be send to specific port
    pkt1to0 = new_packet(
        "90:00:00:00:00:02",
        "80:00:00:00:00:01",
        "172.168.100.2",
        "172.168.100.1"
    )
    s.expect(
        PacketInputEvent('eth1', pkt1to0, display=Ethernet),
        ("eth1 received and Ethernet frame with a destination address which the switch have learned"
         "should forward out specific port eth0")
    )
    s.expect(
        PacketOutputEvent("eth0", pkt1to0, display=Ethernet),
        ("The Ethernet frame should forward out port eth0")
    )
    return s


scenario = test_myswitch()