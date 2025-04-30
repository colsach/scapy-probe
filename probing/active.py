# probing/active.py
from typing import Optional
from scapy.all import *
from scapy.layers import l2, inet, inet6
from scapy.interfaces import resolve_iface
from scapy.utils import ltoa
from .definitions import *
from .packet_logger import *
import ipaddress
import random
###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################

def active_probing(iface:str, scan_type:Optional[list]=None, data:Optional[dict]=None, log:Optional[bool]=None):
    """
    """
    output = "\n[*] Active Probing: "

    if isinstance(data,dict) and data != None:
        output = output + "logging, "
    
    if isinstance(log,bool) and log == True:
        output = output + "displaying, "

    if isinstance(scan_type,list) and scan_type != None:
        for t in scan_type:
            if t == 'passive' or t == SCAN_TYPES['passive']: 
                continue
            if isinstance(t,int):
                output = output + SCAN_TYPES[t] +", "    
            else:
                output = output + t +", "
    
    output = output[0:len(output)-2] + " "      # Remove last ','
    # Get interface infos
    if_mac = get_if_hwaddr(iface)
    if_ip = get_if_addr(iface)
    if_gw = conf.route.route(if_ip)[2]
    if_msk = 0xffffffff
    if_net = 0

    for net,msk,gw,ifa,addr,_ in conf.route.routes:
        # print(f"Net: {net}; MSK: {msk}; GW: {gw}; IFACE: {ifa}; Addr: {addr}")
        if gw == if_gw and ifa == iface and msk > 4026531840 and msk < if_msk:       # 4026531840 = F0000000 -> 240.0.0.0 reserved
            if_msk = msk
            if_net = net
    
    # if isinstance(ipaddress.ip_address(if_ip),ipaddress.IPv4Address):
    #     if_msk = ltoa(if_msk)
    if_msk = ltoa(if_msk)
    if_net = ltoa(if_net)

    ciface = Ciface(if_mac,if_ip,if_gw,if_msk,if_net,iface)

    # print(output + f"packets on interface {iface}: {if_mac}; {if_ip}; {if_net}/{if_msk}...\n")
    print(output + f"packets on interface {ciface} ...\n")
    handle_TCP_active(ciface,data,log)

    if SCAN_TYPES['mac'] in scan_type or 'mac' in scan_type:
        return
    if SCAN_TYPES['ip'] in scan_type or 'ip' in scan_type:
        return
    if SCAN_TYPES['arp'] in scan_type or 'arp' in scan_type:
        return
    if SCAN_TYPES['icmp'] in scan_type or 'icmp' in scan_type:
        return
    if SCAN_TYPES['tcp'] in scan_type or 'tcp' in scan_type:
        # handle_TCP(ciface,data,log)
        return
    if SCAN_TYPES['udp'] in scan_type or 'udp' in scan_type:
        return
    

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################


###############################################################
# x. Layer 4 (UDP, TCP, ...)
###############################################################
def handle_TCP_active(ciface:Ciface,data:Optional[dict]=None,log:Optional[bool]=None):
    """
    """
    port_range = (1,100)
    # port_range = (1,65000)
    # port_range = [80,8080,443]
    dst_ip = "192.168.1.50"
    dst_mac = "d8:3a:dd:6e:b6:55"
    res = ports_scan(ciface.name,ciface.mac,dst_mac,ciface.ip,dst_ip,port_range,log)

    if isinstance(log,bool) and log == True:
        print(f"Result:\n {res}")


###############################################################
# x. Helpers
###############################################################
def port_scan(iface:str,src_mac:str,dst_mac:str,src_ip:str,dst_ip:str,port:int,log:Optional[bool]=None):
    """
    """
    eth = Ether(src=src_mac,dst=dst_mac)
    ip = IP(src=src_ip,dst=dst_ip)
    tcp = TCP(sport=RandShort(),dport=port,flags="S")
    ans = srp1(eth/ip/tcp,iface=iface)
    flags = str(ans[TCP].flags)
    if flags == 'SA':
        status = "open"
        ans = 1
    elif flags == 'RA' or flags == 'R':
        status = "closed"
        ans = 0
    else:
        status = "unknown"
        ans = -1

    if isinstance(log,bool) and log == True:
        print(f"Port {port} is {status}")
    
    return ans

def ports_scan(iface:str,src_mac:str,dst_mac:str,src_ip:str,dst_ip:str,port_range:Optional[int|list|tuple]=None,log:Optional[bool]=None):
    """
    """
    data = {}
    if isinstance(port_range,int):
        ans = port_scan(iface,src_mac,dst_mac,src_ip,dst_ip,port_range,log)
        data = {str(port_range):ans}
    
    if isinstance(port_range,tuple) and len(port_range) == 2:
        start,end = port_range
        if isinstance(start,int) and isinstance(end,int):
            port_range = list(range(start,end))
            # print(port_range)
        else:
            raise ValueError("Both elements in the tuple must be integers.")

    if isinstance(port_range,list):
        ports = random.sample(port_range,len(port_range))
        for port in ports:
            ans = port_scan(iface,src_mac,dst_mac,src_ip,dst_ip,port,log)
            if str(port) not in data:
                data[str(port)] = ans
        
    return data