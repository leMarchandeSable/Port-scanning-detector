from scapy.all import *


def get_interface_name(pkt):
    interface = pkt.show(dump=True)
    return interface.split("[ ")[1].split(" ]")[0]


def get_IP(pkt):
    interface_name = get_interface_name(pkt)
    src = pkt[interface_name]["IP"].src
    dst = pkt[interface_name]["IP"].dst
    return src, dst


def get_port(pkt):
    interface_name = get_interface_name(pkt)
    src = pkt[interface_name]["IP"]["TCP"].sport
    dst = pkt[interface_name]["IP"]["TCP"].dport
    return src, dst


def get_flag(pkt):
    interface_name = get_interface_name(pkt)
    # S = SYN
    # R = RST
    # A = ACK
    # P = PSH
    return pkt[interface_name]["IP"]["TCP"].flags


def get_window_size(pkt):
    interface_name = get_interface_name(pkt)
    return pkt[interface_name]["IP"]["TCP"].window


def get_header_lenght(pkt):
    interface_name = get_interface_name(pkt)
    return pkt[interface_name]["IP"].len


def is_IP(pkt):
    interface_name = get_interface_name(pkt)
    # Ethernet          Loopback
    # 2048 = IP         2 = IP
    # 2054 = ARP        24 = RAW
    return pkt[interface_name].type == 2048 or pkt[interface_name].type == 2


def is_TCP(pkt):
    interface_name = get_interface_name(pkt)
    if is_IP(pkt):
        # 17 = UDP
        # 6 = TCP
        if pkt[interface_name]["IP"].proto == 6:
            return True

    return False


def conversation_complitness(pkts):
    return len(pkts)
