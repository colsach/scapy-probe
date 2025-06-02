# probing/passive.py
from typing import Optional
from scapy.all import *
from scapy.layers import inet, inet6
from .definitions import *
from .packet_logger import *

def passive_probing(iface:CustomIfaces,stop_event,data:PacketLogger,log:Optional[bool]=None):
    """
    Passive probing function to sniff and log packets on the specified interface.

    :param iface: Network interface to sniff on
    :param stop_event: Event to stop sniffing
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    """
    if data != None:
        print(f"\n[*] Passive Probing: Sniffing and logging packets on interface {iface.print_iface_names()}...\n")
        # data.__context.dtype = 'passive'
    else:
        print(f"\n[*] Passive Probing: Sniffing and displaying packets on interface {iface.print_iface_names()}...\n")
    # conf.layers.filter([Ether, Dot3, Dot1Q, IP, IPv6, ARP, ICMP, inet6.ICMPv6ND_NA,inet6.ICMPv6ND_NS,inet6.ICMPv6ND_RA,inet6.ICMPv6ND_RS, TCP, UDP])
    ifaces = iface.get_ifaces_names()
    if len(ifaces) == 1:
        ifaces = ifaces[0]
    print(f"[*] Sniffing on interface(s): {ifaces}")
    try:
        sniff(iface=ifaces, prn=lambda pkt: passive_handle(pkt,data,log), stop_filter=lambda pkt: stop_sniffing(pkt,stop_event))
    except Exception as e:
        print(f"[*] Error while sniffing: {e}")
        if data != None:
            data.save_to_json()
        else:
            print("[*] No data to save.")

def stop_sniffing(pkt,stop_event) -> bool:
    """
    Stop sniffing packets.
    :param pkt: Sniffed packet
    :param stop_event: Event to stop sniffing
    :return: True if stop event is set, False otherwise
    """
    # print("\n[*] Stopping sniffing...")
    return stop_event.is_set()
    # return False

def passive_handle(pkt, data:PacketLogger, log: Optional[bool]=None) -> None:
    """
    Handle the sniffed packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by passive_probing() for each sniffed packet
    """
    if pkt.haslayer(Ether):
        handle_Ether(pkt,data,log)
    elif pkt.haslayer(Dot3):
        handle_Dot3(pkt,data,log)
    
    return

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################
def handle_Ether(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle Ethernet packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by passive_handle()
    """
    src = pkt[Ether].src
    dst = pkt[Ether].dst
    tp = pkt[Ether].type
    if isinstance(log,bool) and log == True:
        t = ETHER_TYPES[tp] if tp in ETHER_TYPES else f"0x{tp:x}"
        print(f"Ethernet Packet: {src} -> {dst}; Type: {t}")

    data.add_sum_layer(src,'Ether')
    data.add_sum_dst_mac(src,dst)
    data.add_sum_ethertype(src,tp)

    if pkt.haslayer(Dot1Q): # If VLAN tag is present
        handle_Dot1Q(pkt,data,log)
    
    if pkt.haslayer(IP):
        handle_IPv4(pkt,data,log)
    elif pkt.haslayer(ARP):
        handle_ARP(pkt,data,log)
    elif pkt.haslayer(IPv6):
        handle_IPv6(pkt,data,log)
    
    return

def handle_Dot3(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle Dot3 packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by passive_handle()
    """
    # TODO: logging & next layer detection
    if isinstance(log,bool) and log == True:
        src = pkt[Dot3].src
        dst = pkt[Dot3].dst
        len = pkt[Dot3].len
        print(f"Dot3 Packet: {src} -> {dst}; Length: {len}")

    
    data.add_sum_layer(pkt[Dot3].src,'Dot3')

    # if pkt.haslayer(LLC):
    #     hanlde_LLC(pkt,data,log)
    return

def handle_Dot1Q(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle Dot1Q (VLAN) packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_Ether()
    """
    if isinstance(log,bool) and log == True:
        prio = pkt[Dot1Q].prio
        dei = pkt[Dot1Q].dei
        vlan = pkt[Dot1Q].vlan
        t = ETHER_TYPES[pkt[Dot1Q].type] if pkt[Dot1Q].type in ETHER_TYPES else f"0x{pkt[Dot1Q].type:x}"
        print(f"VLAN Packet: {pkt[Ether].src} -> {pkt[Ether].dst}; VID: {vlan}; Prio: {prio}; DEI: {dei}; type: {t}")
    
    data.add_sum_layer(pkt[Ether].src,'VLAN')
    data.add_sum_dst_mac(pkt[Ether].src,pkt[Ether].dst)
    data.add_sum_vlan_id(pkt[Ether].src,pkt[Dot1Q].vlan)
    # No need to detect next layer, as it is already done
    # in the handle_Ether function afer the VLAN tag
    return

###############################################################
# x. Layer 2.5
###############################################################
def handle_ARP(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle ARP packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_Ether()
    """
    src_mac = pkt[ARP].hwsrc
    dst_mac = pkt[ARP].hwdst
    src_ip = pkt[ARP].psrc
    dst_ip = pkt[ARP].pdst
    hwtype = pkt[ARP].hwtype
    op = pkt[ARP].op
    if isinstance(log,bool) and log == True:
        hwt = HARDWARE_TYPES[hwtype] if hwtype in HARDWARE_TYPES else f"0x{hwtype:x}"
        ptype = ETHER_TYPES[pkt[ARP].ptype] if pkt[ARP].ptype in ETHER_TYPES else f"0x{pkt[ARP].ptype:x}"
        o = ARP_OPERATIONS[op] if op in ARP_OPERATIONS else f"0x{op:x}"
        print(f"ARP Packet: {src_ip} -> {dst_ip}; HW Type: {hwt}; P Type: {ptype} Operation: {o}; srcMAC: {src_mac}; dstMAC: {dst_mac}")

    data.add_sum_layer(pkt[Ether].src,'ARP')
    data.add_arp(src_mac,src_ip,dst_mac,dst_ip, hwtype, op, raw(pkt).hex())
    return

###############################################################
# x. Layer 3 (IPv4/6, ICMP, ...)
###############################################################
def handle_IPv4(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed IPv4 packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_Ether()
    """
    src = pkt[IP].src
    dst = pkt[IP].dst
    prtcl = pkt[IP].proto
    if isinstance(log,bool) and log == True:
        version = pkt[IP].version
        ihl = pkt[IP].ihl
        tos = pkt[IP].tos
        length = pkt[IP].len
        id = pkt[IP].id
        flags = pkt[IP].flags
        frag = pkt[IP].frag
        ttl = pkt[IP].ttl
        proto = IP_PROTOCOLS[prtcl] if prtcl in IP_PROTOCOLS else prtcl
        chksum = f"0x{pkt[IP].chksum:x}"
        options = pkt[IP].options
        print(f"IPv4 Packet: {src} -> {dst}; Version: {version}; IHL: {ihl}; TOS: {tos}; Length: {length}; ID: {id}; Flags: {flags}; Frag: {frag}; TTL: {ttl}; Proto: {proto}; Chksum: {chksum}; Options: {options}")
    
    
    data.add_sum_layer(pkt[Ether].src,"IPv4")
    data.add_sum_src_ip(pkt[Ether].src, src)
    data.add_sum_dst_ip(pkt[Ether].src, dst)
    data.add_sum_protocol(pkt[Ether].src,prtcl)

    if prtcl == IP_PROTOCOLS["icmp"]:
        handle_ICMP(pkt,data,log)
    elif prtcl == IP_PROTOCOLS["tcp"]:
        handle_TCP(pkt,data,log)
    elif prtcl == IP_PROTOCOLS["udp"]:
        handle_UDP(pkt,data,log)
    
    return

def handle_IPv6(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed IPv6 packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_Ether()
    """
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    nh = pkt[IPv6].nh
    if isinstance(log, bool) and log == True:
        version = pkt[IPv6].version
        tc = pkt[IPv6].tc
        fl = pkt[IPv6].fl
        plen = pkt[IPv6].plen
        nh = IPV6NH[nh] if nh in IPV6NH else nh
        hlim = pkt[IPv6].hlim
        
        load = pkt[IPv6].payload
        print(f"IPv6 Packet: {src} -> {dst}; Version: {version}; TC: {tc}; FL: {fl}; PLen: {plen}; NH: {nh}; Hlim: {hlim}; Load: {load}")

    data.add_sum_layer(pkt[Ether].src,'IPv6')
    data.add_sum_src_ip(pkt[Ether].src,src)
    data.add_sum_dst_ip(pkt[Ether].src,dst)
    data.add_sum_protocol(pkt[Ether].src,nh)

    if nh == IPV6NH['ICMPv6']:
        handle_ICMPv6(pkt,data,log)
    elif nh == IPV6NH['TCP']:
        handle_TCP(pkt,data,log)
    elif nh == IPV6NH['UDP']:
        handle_UDP(pkt,data,log)
    return

def handle_ICMP(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMP packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_IPv4()
    """
    src = pkt[IP].src
    dst = pkt[IP].dst
    t = pkt[ICMP].type
    code = pkt[ICMP].code
    if isinstance(log,bool) and log == True:
        chksum = pkt[ICMP].chksum
        id = pkt[ICMP].id
        seq = pkt[ICMP].seq
        ts_ori = pkt[ICMP].ts_ori
        ts_rx = pkt[ICMP].ts_rx
        ts_tx = pkt[ICMP].ts_tx
        gw = pkt[ICMP].gw
        ptr = pkt[ICMP].ptr
        res = pkt[ICMP].reserved
        addr_mask = pkt[ICMP].addr_mask
        nexthopmtu = pkt[ICMP].nexthopmtu
        extpad = pkt[ICMP].extpad
        ext = pkt[ICMP].ext
        print(f"ICMP Packet: {src} -> {dst}; Type: {t}; Code: {code}; chksum: 0x{chksum:x}; Id: {id}; Seq: {seq}; ts_ori: {ts_ori}; ts_rx:{ts_rx}; ts_tx:{ts_tx}; GW: {gw}; ptr: {ptr}; res: {res}; Addr. Mask: {addr_mask}; nexthopmtu: {nexthopmtu}; extpad: {extpad}; ext: {ext}")
    
    data.add_sum_layer(pkt[Ether].src,"ICMP")
    data.add_icmp( pkt[Ether].src, pkt[Ether].dst, dst, t, code, raw(pkt).hex())
    return

def handle_ICMPv6(pkt, data:PacketLogger, log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMPv6 packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_IPv6()
    """
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    if isinstance(log,bool) and log == True:
        icmp_layer = bytes(pkt[IPv6].payload)    
        t = icmp_layer[0]
        code = icmp_layer[1]
        print(f"ICMPv6 Packet: {src} -> {dst}; Type: {t}; Code: {code}")

    if pkt.haslayer(inet6.ICMPv6ND_NA):
        handle_ICMPv6_NA(pkt,data,log)
    elif pkt.haslayer(inet6.ICMPv6ND_NS):
        handle_ICMPv6_NS(pkt,data,log)
    elif pkt.haslayer(inet6.ICMPv6ND_RS):
        handle_ICMPv6_RS(pkt,data,log)
    elif pkt.haslayer(inet6.ICMPv6ND_RA):
        handle_ICMPv6_RA(pkt,data,log)
    
    icmp_layer = bytes(pkt[IPv6].payload)
    data.add_sum_layer(pkt[Ether].src,"ICMPv6")
    data.add_sum_src_ip(pkt[Ether].src,src)
    data.add_sum_dst_ip(pkt[Ether].src,dst)
    data.add_icmp(pkt[Ether].src, pkt[Ether].dst, dst, icmp_layer[0], icmp_layer[1], raw(pkt).hex())
    return

def handle_ICMPv6_NA(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMPv6 Neighbor Advertisement packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_ICMPv6()
    """
    lladdr = pkt[inet6.ICMPv6NDOptDstLLAddr].lladdr if pkt.haslayer(inet6.ICMPv6NDOptDstLLAddr) else None
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    if isinstance(log,bool) and log == True:
        icmp_layer = bytes(pkt[IPv6].payload)
        t = icmp_layer[0]
        code = icmp_layer[1]
        if lladdr != None:
            print(f"ICMPv6 NA Packet: {src} -> {dst}; Type: {t}; Code: {code}; LLADDR: {lladdr}")
        else:
            print(f"ICMPv6 NA Packet: {src} -> {dst}; Type: {t}; Code: {code}")

    data.add_ndp(pkt[Ether].src,src,pkt[Ether].dst,dst,NDP_TYPES['NA'],raw(pkt).hex(),lladdr)
    return

def handle_ICMPv6_NS(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMPv6 Neighbor Solicitation packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_ICMPv6()
    """
    lladdr = pkt[inet6.ICMPv6NDOptSrcLLAddr].lladdr if pkt.haslayer(inet6.ICMPv6NDOptSrcLLAddr) else None
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    if isinstance(log,bool) and log == True:
        icmp_layer = bytes(pkt[IPv6].payload)
        t = icmp_layer[0]
        code = icmp_layer[1]
        if lladdr != None:
            print(f"ICMPv6 NS Packet: {src} -> {dst}; Type: {t}; Code: {code}; LLADDR: {lladdr}")
        elif pkt.haslayer(inet6.ICMPv6NDOptUnknown):
            data = pkt[inet6.ICMPv6NDOptUnknown].data
            print(f"ICMPv6 NS Packet: {src} -> {dst}; Type: {t}; Code: {code}; Data: {data}")
        else:
            print(f"ICMPv6 NS Packet: {src} -> {dst}; Type: {t}; Code: {code}")

    data.add_ndp(pkt[Ether].src,src,pkt[Ether].dst,dst,NDP_TYPES['NS'],raw(pkt).hex(),lladdr)
    return

def handle_ICMPv6_RS(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMPv6 Router Solicitation packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_ICMPv6()
    """
    lladdr = pkt[inet6.ICMPv6NDOptSrcLLAddr].lladdr if pkt.haslayer(inet6.ICMPv6NDOptSrcLLAddr) else None
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    if isinstance(log,bool) and log == True:
        icmp_layer = bytes(pkt[IPv6].payload)
        t = icmp_layer[0]
        code = icmp_layer[1]
        if lladdr != None:
            print(f"ICMPv6 RS Packet: {src} -> {dst}; Type: {t}; Code: {code}; LLADDR: {lladdr}")
        else:
            print(f"ICMPv6 RS Packet: {src} -> {dst}; Type: {t}; Code: {code}")

    data.add_ndp(pkt[Ether].src,src,pkt[Ether].dst,dst,NDP_TYPES['RS'],raw(pkt).hex(),lladdr)
    return

def handle_ICMPv6_RA(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed ICMPv6 Router Advertisement packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_ICMPv6()
    """
    lladdr = pkt[inet6.ICMPv6NDOptDstLLAddr].lladdr if pkt.haslayer(inet6.ICMPv6NDOptDstLLAddr) else None
    src = pkt[IPv6].src
    dst = pkt[IPv6].dst
    if isinstance(log,bool) and log == True:
        icmp_layer = bytes(pkt[IPv6].payload)
        t = icmp_layer[0]
        code = icmp_layer[1]
        if lladdr != None:
            print(f"ICMPv6 RA Packet: {src} -> {dst}; Type: {t}; Code: {code}; LLADDR: {lladdr}")
        else:
            print(f"ICMPv6 RA Packet: {src} -> {dst}; Type: {t}; Code: {code}")
   
    data.add_ndp(pkt[Ether].src,src,pkt[Ether].dst,dst,NDP_TYPES['RA'],raw(pkt).hex(),lladdr)
    return

###############################################################
# x. Layer 4 (TCP & UDP)
###############################################################
def handle_TCP(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed TCP packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_IPv4() and handle_IPv6()
    """
    if isinstance(pkt[TCP].underlayer,inet6.IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto

    dst_port = pkt[TCP].dport
    src_port = pkt[TCP].sport

    if isinstance(log,bool) and log == True:
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        flags = pkt[TCP].flags
        window = pkt[TCP].window
        chksum = f"0x{pkt[TCP].chksum:x}"
        urgptr = pkt[TCP].urgptr
        options = pkt[TCP].options
        load = pkt[TCP].payload
        print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}; Seq: {seq}; Ack: {ack}; Flags: {flags}; Window: {window}; Chksum: {chksum}; Urgptr: {urgptr}; Options: {options}; Load: {load}")
    try:
        # data.add_sum_layer(pkt[Ether].src,'TCP')
        # data.add_sum_src_port(pkt[Ether].src,src_port)
        # data.add_sum_dst_port(pkt[Ether].src,dst_port)
        data.add_raw_data(pkt[Ether].src,pkt[Ether].dst,dst_ip,proto,dst_port,raw(pkt).hex())
    except Exception as e:
        print(f"[*] Error while handling TCP packet: {e}")
        if data != None:
            data.save_to_json()
        else:
            print("[*] No data to save.")
        exit(1)
    return

def handle_UDP(pkt,data:PacketLogger,log:Optional[bool]=None) -> None:
    """
    Handle the sniffed UDP packets.
    :param pkt: Sniffed packet
    :param data: PacketLogger object to log packets
    :param log: Boolean to indicate whether to log packets in shell or not
    :return: None
    :note: This function is called by handle_IPv4() and handle_IPv6()
    """
    if isinstance(pkt[UDP].underlayer,inet6.IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto

    src_port = pkt[UDP].sport
    dst_port = pkt[UDP].dport

    if isinstance(log,bool) and log == True:
        length = pkt[UDP].len
        chksum = f"0x{pkt[UDP].chksum:x}"
        load = pkt[UDP].payload
        print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}; Length: {length}; Chksum: {chksum}; Load: {load}")

    data.add_sum_layer(pkt[Ether].src,'UDP')
    data.add_sum_src_port(pkt[Ether].src,src_port)
    data.add_sum_dst_port(pkt[Ether].src,dst_port)
    data.add_raw_data(pkt[Ether].src,pkt[Ether].dst,dst_ip,proto,dst_port,raw(pkt).hex())
    return