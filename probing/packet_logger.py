# probing/packet_logger.py
import json
from .definitions import *
###############################################################
# 1. Initializer
###############################################################

def init_logger() -> dict:
    """
    """
    return {}

def init_new_mac(data:dict, mac:str):
    """
    """
    if mac not in data:
        data[mac] = {}

def init_new_sum(data:dict,mac:str):
    """
    """
    init_new_mac(data,mac)

    if 'summary' not in data[mac]:
        data[mac]['summary'] = {}

def init_new_sum_list(data:dict,mac:str,item:str):
    """
    """
    init_new_sum(data,mac)

    if item not in data[mac]['summary']:
        data[mac]['summary'][item] = []

def check_ip_version(ip:str):
    if ':' in ip:
        return 'IPv6'
    else:
        return 'IPv4'

def check_protocol(ip_version:str,prtcl:str):
    if ip_version == 'IPv6':
        return IPV6NH[prtcl] if prtcl in IPV6NH else prtcl
    elif ip_version == 'IPv4':
        return IP_PROTOCOLS[prtcl] if prtcl in IP_PROTOCOLS else prtcl
    else:
        return 'unknown'

###############################################################
# 2. Saving functions
###############################################################

def save_to_json(data):
    """
    """
    export = json.loads(json.dumps(data, default=lambda o: list(o) if isinstance(o, set) else o))
    with open("sniff_log.json", "w") as f:
        json.dump(export, f, indent=2)

###############################################################
# 3. Summary functions
###############################################################

def add_sum_dst_mac(data:dict,mac:str,dst_mac:str):
    """
    """
    init_new_sum_list(data,mac,'macs')

    if dst_mac not in data[mac]['summary']['macs']:
        data[mac]['summary']['macs'].append(dst_mac)

def add_sum_ether_type(data:dict,mac:str,ether_type:str):
    """
    """
    init_new_sum_list(data,mac,'ethertypes')

    if ether_type not in data[mac]['summary']['ethertypes']:
        data[mac]['summary']['ethertypes'].append(ether_type)

def add_sum_hwtype(data:dict,mac:str,hwtype:int):
    """
    """
    init_new_sum_list(data,mac,'hwtypes')

    if hwtype not in data[mac]['summary']['hwtypes']:
        data[mac]['summary']['hwtypes'].append(hwtype)

def add_sum_src_ip(data:dict,mac:str,ip:str):
    """
    """
    init_new_sum_list(data,mac,'sips')

    if ip not in data[mac]['summary']['sips']:
        data[mac]['summary']['sips'].append(ip)

def add_sum_dst_ip(data:dict,mac:str,ip:str):
    """
    """
    init_new_sum_list(data,mac,'dips')

    if ip not in data[mac]['summary']['dips']:
        data[mac]['summary']['dips'].append(ip)

def add_sum_prtcl(data:dict,mac:str,prtcl:int):
    """
    """
    init_new_sum_list(data,mac,'prtcls')

    if prtcl not in data[mac]['summary']['prtcls']:
        data[mac]['summary']['prtcls'].append(prtcl)

def add_sum_src_port(data:dict,mac:str,src_port:int):
    """
    """
    init_new_sum_list(data,mac,'sports')

    if src_port not in data[mac]['summary']['sports']:
        data[mac]['summary']['sports'].append(src_port)

def add_sum_dst_port(data:dict,mac:str,dst_port:int):
    """
    """
    init_new_sum_list(data,mac,'dports')

    if dst_port not in data[mac]['summary']['dports']:
        data[mac]['summary']['dports'].append(dst_port)

def add_sum_layer(data:dict,mac:str,layer:str):
    """
    """
    init_new_sum_list(data,mac,'layers')

    if layer not in data[mac]['summary']['layers']:
        data[mac]['summary']['layers'].append(layer)

def add_sum_vlan_id(data:dict,mac:str, vid:int):
    """
    """
    init_new_sum_list(data,mac,'vids')

    if vid not in data[mac]['summary']['vids']:
        data[mac]['summary']['vids'].append(vid)

###############################################################
# 4. Transport Packet functions (Ether/IP/TCP or UDP)
###############################################################

def add_dst_mac(data:dict,mac:str,dst_mac:str):
    """
    """
    init_new_mac(data,mac)
    add_sum_dst_mac(data,mac,dst_mac)

    if dst_mac not in data[mac]:
        data[mac][dst_mac] = {}

def add_ether_type(data:dict,mac:str,dst_mac:str,ethertype:int):
    """
    """
    add_dst_mac(data,mac,dst_mac)
    
    if ethertype not in ETHER_TYPES:
        if str(ethertype) not in data[mac][dst_mac]:
            data[mac][dst_mac][str(ethertype)] = {}
    else:
        if ETHER_TYPES[ethertype] not in data[mac][dst_mac]:
            data[mac][dst_mac][ETHER_TYPES[ethertype]] = {}

def add_arp(data:dict,hwtype:int,ptype:int,op:int,src_mac:str,src_ip:str,dst_mac:str,dst_ip:str,raw:str):
    """
    """
    add_ether_type(data,src_mac,dst_mac,ETHER_TYPES['ARP'])
    if str(hwtype) not in data[src_mac][dst_mac]['ARP']:
        data[src_mac][dst_mac]['ARP'][str(hwtype)] = {}
    
    if ARP_OPERATIONS[op] not in data[src_mac][dst_mac]['ARP'][str(hwtype)]:
        data[src_mac][dst_mac]['ARP'][str(hwtype)][ARP_OPERATIONS[op]] = []
    
    if raw not in data[src_mac][dst_mac]['ARP'][str(hwtype)][ARP_OPERATIONS[op]]:
        data[src_mac][dst_mac]['ARP'][str(hwtype)][ARP_OPERATIONS[op]].append(raw)

    if op == ARP_OPERATIONS['who-has']:
        add_sum_src_ip(data,src_mac,src_ip)
        add_sum_dst_ip(data,src_mac,dst_ip)
        add_sum_hwtype(data,src_mac,hwtype)

    elif op == ARP_OPERATIONS['is-at']:
        add_sum_src_ip(data,src_mac,src_ip)
        add_sum_src_ip(data,dst_mac,dst_ip)
        add_sum_dst_ip(data,src_mac,dst_ip)
        add_sum_dst_ip(data,dst_mac,src_ip)
        add_sum_hwtype(data,src_mac,hwtype)
        add_sum_hwtype(data,dst_mac,hwtype)
    else:
        return


def add_ip(data:dict,mac:str,dst_mac,ip:str):
    """
    """
    ip_version = check_ip_version(ip)
    add_ether_type(data,mac,dst_mac,ETHER_TYPES[ip_version])
    add_sum_dst_ip(data,mac,ip)


    if ip not in data[mac][dst_mac][ip_version]:
        data[mac][dst_mac][ip_version][ip] = {}

def add_ip_prtcl(data:dict,mac:str,dst_mac:str,ip:str,prtcl:int):
    """
    """
    add_ip(data,mac,dst_mac,ip)
    add_sum_prtcl(data,mac,prtcl)
    ip_version = check_ip_version(ip)
    proto = check_protocol(ip_version,prtcl)

    if prtcl not in data[mac][dst_mac][ip_version][ip]:
        data[mac][dst_mac][ip_version][ip][proto] = {}

def add_ip_prtcl_unknown(data:dict,mac:str,dst_mac:str,ip:str,prtcl:int,raw:str):
    add_ip_prtcl(data,mac,dst_mac,ip,prtcl)
    ip_version = check_ip_version(ip)
    proto = check_protocol(ip_version,prtcl)

    if isinstance(data[mac][dst_mac][ip_version][ip][proto], dict):
        data[mac][dst_mac][ip_version][ip][proto] = []
    
    if raw not in data[mac][dst_mac][ip_version][ip][proto]:
        data[mac][dst_mac][ip_version][ip][proto].append(raw)

def add_icmp(data:dict, mac:str, dst_mac:str, ip:str, icmp_type:int, icmp_code:int, raw:str):
    """
    """
    ip_version = check_ip_version(ip)
    if ip_version == 'IPv4':
        prtcl = IP_PROTOCOLS['icmp']
        types = ICMP_TYPES[icmp_type] if icmp_type in ICMP_TYPES else icmp_type
        codes = ICMP_CODES if icmp_type in ICMP_CODES and icmp_code in ICMP_CODES[icmp_type] else icmp_code
    else:
        prtcl = IPV6NH['ICMPv6']
        types = ICMPv6_TYPES[icmp_type] if icmp_type in ICMPv6_TYPES else icmp_type
        codes = ICMPv6_CODES[icmp_type][icmp_code] if icmp_type in ICMPv6_CODES and icmp_code in ICMPv6_CODES[icmp_type] else icmp_code
    
    add_ip_prtcl(data,mac,dst_mac,ip,prtcl)
    proto = check_protocol(ip_version,prtcl)
    
    if types not in data[mac][dst_mac][ip_version][ip][proto]:
        data[mac][dst_mac][ip_version][ip][proto][types] = {}

    if codes not in data[mac][dst_mac][ip_version][ip][proto][types]:
        data[mac][dst_mac][ip_version][ip][proto][types][codes] = []
    
    if raw not in data[mac][dst_mac][ip_version][ip][proto][types][codes]:
        data[mac][dst_mac][ip_version][ip][proto][types][codes].append(raw)

def add_dst_port(data:dict,mac:str,dst_mac:str,ip:str,prtcl:int,dport:int):
    """
    """
    add_ip_prtcl(data,mac,dst_mac,ip,prtcl)
    add_sum_dst_port(data,mac,dport)
    ip_version = check_ip_version(ip)
    proto = check_protocol(ip_version,prtcl)
    
    if dport not in data[mac][dst_mac][ip_version][ip][proto]:
        data[mac][dst_mac][ip_version][ip][proto][str(dport)] = {}
    
def add_raw_data(data:dict,mac:str,dst_mac:str,ip:str,prtcl:int,dport:int,raw:str):
    """
    """
    add_dst_port(data,mac,dst_mac,ip,prtcl,dport)
    ip_version = check_ip_version(ip)
    proto = check_protocol(ip_version,prtcl)

    if 'raw' not in data[mac][dst_mac][ip_version][ip][proto][str(dport)]:
        data[mac][dst_mac][ip_version][ip][proto][str(dport)]['raw'] = []
    
    if raw not in data[mac][dst_mac][ip_version][ip][proto][str(dport)]['raw']:
        data[mac][dst_mac][ip_version][ip][proto][str(dport)]['raw'].append(raw)


###############################################################
# 4. Transport Packet functions (Ether/IP/TCP or UDP)
###############################################################