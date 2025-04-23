# probing/passive.py
from typing import Optional
from scapy.all import *
from scapy.layers import l2, inet, inet6
# from scapy.layers.l2 import (
#     Ether,
#     Dot3,
#     ARP,
#     LLC,
#     SNAP,
#     Dot1Q
# )
# from scapy.layers.inet import (
#     IP,
#     TCP,
#     UDP
# )
from .definitions import *
from .packet_logger import *

def passive_probing(iface:str,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """

    if data != None:
        print(f"\n[*] Passive Probing: Sniffing and logging packets on interface {iface}...\n")
    else:
        print(f"\n[*] Passive Probing: Sniffing and displaying packets on interface {iface}...\n")

    # Ignoring packets sent by this devices
    # mac = get_if_hwaddre(iface)
    # print(f"Ignonring packets sent by this device: {mac}")

    sniff(iface=iface, prn=lambda pkt: passive_handle(pkt,data,log))


def passive_handle(pkt, data:Optional[dict]=None, log: Optional[bool]=None):
    """
    Handle the sniffed packets.
    """
    if pkt.haslayer(Ether):
        handle_Ether(pkt,data,log)
    elif pkt.haslayer(Dot3):
        handle_Dot3(pkt,data,log)
    else:
        t = "Unknown"

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################
def handle_Ether(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    Handle Ethernet packets.
    """
    # TODO: Change Ether type detection
    if isinstance(log,bool) and log == True:
        if pkt[Ether].type in ETHER_TYPES:
            t = ETHER_TYPES[pkt[Ether].type]
        else:
            t = f"0x{pkt[Ether].type:x}"
        print(f"Ethernet Packet: {pkt[Ether].src} -> {pkt[Ether].dst}; Type: {t}")

    if isinstance(data,dict):
        add_sum_layer(data,pkt[Ether].src,'Ether')
        add_sum_dst_mac(data,pkt[Ether].src,pkt[Ether].dst)
        add_sum_ether_type(data,pkt[Ether].src,pkt[Ether].type)

    if pkt.haslayer(IP):
        handle_IPv4(pkt,data,log)
    elif pkt.haslayer(ARP):
        handle_ARP(pkt,data,log)
    elif pkt.haslayer(IPv6):
        handle_IPv6(pkt,data,log)
    elif pkt.haslayer(Dot1Q): # VLAN
        handle_Dot1Q(pkt,data,log)
        return

def handle_Dot1Q(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    # TODO: logging & Protocol switch case
    if isinstance(log,bool) and log == True:
        prio = pkt[Dot1Q].prio
        dei = pkt[Dot1Q].dei
        vlan = pkt[Dot1Q].vlan
        t = ETHER_TYPES[pkt[Dot1Q].type] if pkt[Dot1Q].type in ETHER_TYPES else f"0x{pkt[Dot1Q].type:x}"
        print(f"VLAN Packet: {pkt[Ether].src} -> {pkt[Ether].dst}; VID: {vlan}; Prio: {prio}; DEI: {dei}; type: {t}")

def handle_Dot3(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    # TODO: logging & next layer detection
    if isinstance(log,bool) and log == True:
        src = pkt[Dot3].src
        dst = pkt[Dot3].dst
        len = pkt[Dot3].len
        print(f"Dot3 Packet: {src} -> {dst}; Length: {len}")


###############################################################
# x. Layer 2.5
###############################################################
def handle_ARP(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    if isinstance(log,bool) and log == True:
        hwtype = HARDWARE_TYPES[pkt[ARP].hwtype] if pkt[ARP].hwtype in HARDWARE_TYPES else f"0x{pkt[ARP].hwtype:x}"
        ptype = ETHER_TYPES[pkt[ARP].ptype] if pkt[ARP].ptype in ETHER_TYPES else f"0x{pkt[ARP].ptype:x}"
        op = ARP_OPERATIONS[pkt[ARP].op] if pkt[ARP].op in ARP_OPERATIONS else f"0x{pkt[ARP].op:x}"
        print(f"ARP Packet: {pkt[ARP].psrc} -> {pkt[ARP].pdst}; HW Type: {hwtype}; P Type: {ptype} Operation: {op}; srcMAC: {pkt[ARP].hwsrc}; dstMAC: {pkt[ARP].hwdst}; srcIP: {pkt[ARP].psrc}; dstIP: {pkt[ARP].pdst}")

    if isinstance(data,dict):
        add_sum_layer(data, pkt[Ether].src,'ARP')
        add_arp(data,pkt[ARP].hwtype,pkt[ARP].ptype,pkt[ARP].op,pkt[ARP].hwsrc,pkt[ARP].psrc,pkt[ARP].hwdst,pkt[ARP].pdst, raw(pkt).hex())

def handle_DHCP(pkt,data:Optional[dict]=None, log:Optional[bool]=None):
    """
    """
    # TODO: all

###############################################################
# x. Layer 3 (IPv4/6, ICMP, ...)
###############################################################
def handle_IPv4(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    Handle the sniffed IPv4 packets.
    """
    if isinstance(log,bool) and log == True:
        version = pkt[IP].version
        ihl = pkt[IP].ihl
        tos = pkt[IP].tos
        length = pkt[IP].len
        id = pkt[IP].id
        flags = pkt[IP].flags
        frag = pkt[IP].frag
        ttl = pkt[IP].ttl
        proto = IP_PROTOCOLS[pkt[IP].proto] if pkt[IP].proto in IP_PROTOCOLS else pkt[IP].proto
        chksum = f"0x{pkt[IP].chksum:x}"
        src = pkt[IP].src
        dst = pkt[IP].dst
        options = pkt[IP].options
        # print(f"IPv4 Packet: {src} -> {dst}; Version: {version}; IHL: {ihl}; TOS: {tos}; Length: {length}; ID: {id}; Flags: {flags}; Frag: {frag}; TTL: {ttl}; Proto: {proto}; Chksum: {chksum}; Options: {options}; Raw: {raw(pkt[IP]).hex()}")
        print(f"IPv4 Packet: {src} -> {dst}; Version: {version}; IHL: {ihl}; TOS: {tos}; Length: {length}; ID: {id}; Flags: {flags}; Frag: {frag}; TTL: {ttl}; Proto: {proto}; Chksum: {chksum}; Options: {options}")
    
    if isinstance(data,dict):
        add_sum_layer(data,pkt[Ether].src,"IPv4")
        add_sum_src_ip(data,pkt[Ether].src, pkt[IP].src)
        add_sum_dst_ip(data,pkt[Ether].src, pkt[IP].dst)
        add_sum_prtcl(data,pkt[Ether].src,pkt[IP].proto)


    if pkt[IP].proto == IP_PROTOCOLS["icmp"]:
        handle_ICMP(pkt,data,log)
        return
    elif pkt[IP].proto == IP_PROTOCOLS["igmp"]:
        return
    elif pkt[IP].proto == IP_PROTOCOLS["tcp"]:
        handle_TCP(pkt,data,log)
    elif pkt[IP].proto == IP_PROTOCOLS["udp"]:
        handle_UDP(pkt,data,log)
    else:
        # Handle other protocols
        if isinstance(log,bool) and log == True:
            print(f"Unknown Protocol: {proto}")
        add_ip_prtcl_unknown(data,pkt[Ether].src,pkt[Ether].dst,pkt[IP].dst,pkt[IP].proto,raw(pkt).hex())

def handle_IPv6(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    if isinstance(log, bool) and log == True:
        version = pkt[IPv6].version
        tc = pkt[IPv6].tc
        fl = pkt[IPv6].fl
        plen = pkt[IPv6].plen
        nh = IPV6NH[pkt[IPv6].nh] if pkt[IPv6].nh in IPV6NH else pkt[IPv6].nh
        hlim = pkt[IPv6].hlim
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst

        print(f"IPv6 Packet: {src} -> {dst}; Version: {version}; TC: {tc}; FL: {fl}; PLen: {plen}; NH: {nh}; Hlim: {hlim}; Load: {pkt[IPv6].payload}")

    if isinstance(data,dict):
        add_sum_layer(data,pkt[Ether].src,'IPv6')
        add_sum_src_ip(data,pkt[Ether].src,pkt[IPv6].src)
        add_sum_dst_ip(data,pkt[Ether].src,pkt[IPv6].dst)
        add_sum_prtcl(data,pkt[Ether].src,pkt[IPv6].nh)

    if pkt[IPv6].nh == IPV6NH['TCP']:
        handle_TCP(pkt,data,log)
    elif pkt[IPv6].nh == IPV6NH['UDP']:
        handle_UDP(pkt,data,log)

def handle_ICMP(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    # TODO: data loging
    if isinstance(log,bool) and log == True:
        t = pkt[ICMP].type
        code = pkt[ICMP].code
        chksum = pkt[ICMP].chksum
        id = pkt[ICMP].id
        seq = pkt[ICMP].seq
        ts_ori = pkt[ICMP].ts_ori
        ts_rx = pkt[ICMP].ts_rx
        ts_tx = pkt[ICMP].ts_tx
        gw = pkt[ICMP].gw
        ptr = pkt[ICMP].ptr
        res = pkt[ICMP].reserved
        len = pkt[ICMP].length
        addr_mask = pkt[ICMP].addr_mask
        nexthopmtu = pkt[ICMP].nexthopmtu
        extpad = pkt[ICMP].extpad
        ext = pkt[ICMP].ext
        print(f"ICMP Packet: {pkt[IP].src} -> {pkt[IP].dst}; Type: {t}; Code: {code}; chksum: 0x{chksum:x}; Id: {id}; Seq: {seq}; ts_ori: {ts_ori}; ts_rx:{ts_rx}; ts_tx:{ts_tx}; GW: {gw}; ptr: {ptr}; res: {res}; Addr. Mask: {addr_mask}; nexthopmtu: {nexthopmtu}; extpad: {extpad}; ext: {ext}")
    
    if isinstance(data,dict):
        add_sum_layer(data,pkt[Ether].src,"ICMP")

def handle_IGMP(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    # TODO: all
    return

###############################################################
# x. Layer 4 (TCP & UDP)
###############################################################
def handle_TCP(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    if isinstance(log,bool) and log == True:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        flags = pkt[TCP].flags
        window = pkt[TCP].window
        chksum = f"0x{pkt[TCP].chksum:x}"
        urgptr = pkt[TCP].urgptr
        options = pkt[TCP].options
        if isinstance(pkt[TCP].underlayer,inet.IP):
            print(f"TCP Packet: {pkt[IP].src}:{src_port} -> {pkt[IP].dst}:{dst_port}; Seq: {seq}; Ack: {ack}; Flags: {flags}; Window: {window}; Chksum: {chksum}; Urgptr: {urgptr}; Options: {options}; Load: {pkt[TCP].payload}")
        elif isinstance(pkt[TCP].underlayer,inet6.IPv6):
            print(f"TCP Packet: {pkt[IPv6].src}:{src_port} -> {pkt[IPv6].dst}:{dst_port}; Seq: {seq}; Ack: {ack}; Flags: {flags}; Window: {window}; Chksum: {chksum}; Urgptr: {urgptr}; Options: {options}; Load: {pkt[TCP].payload}")

    if not isinstance(data,dict):
        return
    
    add_sum_layer(data,pkt[Ether].src,'TCP')
    add_sum_src_port(data,pkt[Ether].src,pkt[TCP].sport)
    add_sum_dst_port(data,pkt[Ether].src,pkt[TCP].dport)
    # add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IP].dst,pkt[IP].proto,pkt[TCP].dport,raw(pkt).hex())
    if isinstance(pkt[TCP].underlayer,inet.IP):
        add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IP].dst,pkt[IP].proto,pkt[TCP].dport,raw(pkt).hex())
    if isinstance(pkt[TCP].underlayer,inet6.IPv6):
        add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IPv6].dst,pkt[IPv6].nh,pkt[TCP].dport,raw(pkt).hex())

def handle_UDP(pkt,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    if isinstance(log,bool) and log == True:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        length = pkt[UDP].len
        chksum = f"0x{pkt[UDP].chksum:x}"
        load = pkt[UDP].payload
        if isinstance(pkt[UDP].underlayer,inet.IP):
            print(f"UDP Packet: {pkt[IP].src}:{src_port} -> {pkt[IP].dst}:{dst_port}; Length: {length}; Chksum: {chksum}; Load: {load}")
        elif isinstance(pkt[UDP].underlayer,inet6.IPv6):
            print(f"UDP Packet: {pkt[IPv6].src}:{src_port} -> {pkt[IPv6].dst}:{dst_port}; Length: {length}; Chksum: {chksum}; Load: {load}")


    if not isinstance(data,dict):
        return

    add_sum_layer(data,pkt[Ether].src,'UDP')
    add_sum_src_port(data,pkt[Ether].src,pkt[UDP].sport)
    add_sum_dst_port(data,pkt[Ether].src,pkt[UDP].dport)
    # add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IP].dst,pkt[IP].proto,pkt[UDP].dport,raw(pkt).hex())
    if isinstance(pkt[UDP].underlayer,inet.IP):
        add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IP].dst,pkt[IP].proto,pkt[UDP].dport,raw(pkt).hex())
    elif isinstance(pkt[UDP].underlayer,inet6.IPv6):
        add_raw_data(data,pkt[Ether].src,pkt[Ether].dst,pkt[IPv6].dst,pkt[IPv6].nh,pkt[UDP].dport,raw(pkt).hex())
        
