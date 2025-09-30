# probing/active.py
from typing import Optional,Union,List
from scapy.all import *
from .definitions import *
from .packet_logger import *
import ipaddress
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import time

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################

def active_probing(iface_manager:CustomIfacesManager, data:PacketLogger, scan_type:Optional[list[str]]=None, ports:Optional[Tuple[int,list[int],Tuple[int,int]]]=PORTS, log:Optional[bool]=None):
    """
    Performs active probing on the specified interfaces.
    :param iface_manager: CustomIfacesManager object containing interface information
    :param data: PacketLogger object to log scan results
    :param scan_type: List of scan types to perform. If 'ALL' is included, all scan types will be performed.
                      Options: ['ARP', 'PING', 'PORT', 'ALL']
    :param ports: Ports to scan. Can be a single port (int), a list of ports, or a tuple with a range of ports (start, end).
    :type ports: int | list[int] | tuple[int,int]
    :param log: Optional boolean to enable logging of scan results
    :return: None
    """
    if 'ALL' in scan_type or scan_type == None or scan_type == []:
        scan_type.extend(['ARP','PING','PORT'])      # Add all scan types if 'ALL' is selected

    output = "\n[*] Active Probing: "

    if isinstance(data,PacketLogger) and data != None:
        output = output + "logging, "    
    if isinstance(log,bool) and log == True:
        output = output + "displaying, "
    if isinstance(scan_type,list) and scan_type != None:
        output = output + "scanning: "
        for t in scan_type:
            if t == 'ALL':
                continue
            else:
                if t == 'PORT':
                    output = output + f"ports {PORTS}, "
                else: 
                    output = output + t + ", "
    output = output[0:len(output)-2] + " "      # Remove last ','
    print(output + f"on interfaces: \n{iface_manager}\n")
    handle_IFACES_scan(iface_manager,data,scan_type,ports,log)

    

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################
def handle_IFACES_scan(iface_manager:CustomIfacesManager, data:PacketLogger, scan_type:list, ports:Union[int,list,tuple[int,int]], log:bool):

    with ThreadPoolExecutor(max_workers=iface_manager.max_workers) as executor:
        futures = [executor.submit(handle_IFACE_scan,(name,iface,data,scan_type,ports,log)) for name, iface in iface_manager.get_ifaces()]
        for future in as_completed(futures): pass


def handle_IFACE_scan(input:Tuple[str,CustomIface,PacketLogger,list[str],Union[int,list,tuple[int,int]],bool]):
    """
    Handles the scanning of a single interface.
    :param input: Tuple containing:
                  - name: Name of the interface
                  - iface: CustomIface object with interface information
                  - data: PacketLogger object to store scan results
                  - scan_type: List of scan types to perform
                  - ports: Ports to scan (int for single port, list for multiple ports, tuple for port range)
                  - log: Optional boolean to enable logging
    """
    name, iface, data, scan_type, ports, log = input
    if log == True:
        print(f"\n🚀 Starting scan on interface {name}...\n")
    

    if 'ARP' in scan_type:
        p_arp = multiprocessing.Process(target=handle_ARP_scan, args=(iface,data,log))
        p_arp.start()
        p_arp.join()
    
    if 'PING' in scan_type:
        p_ping = multiprocessing.Process(target=handle_PING_scan, args=(iface,data,log))
        p_ping.start()
        p_ping.join()
    
    if 'PORT' in scan_type:
        p_port = multiprocessing.Process(target=handle_PORT_scan, args=(iface,data,ports,log))
        p_port.start()
        p_port.join()

def handle_ARP_scan(iface:CustomIface,data:PacketLogger,log:bool):
    """
    Handles the ARP scan on the specified interface.
    :param iface: CustomIface object with interface information
    :param data: PacketLogger object to store scan results
    :param log: Optional boolean to enable logging
    :return: None
    """
    ips = iface.get_ips_4()
    for ip, _,_, msk in ips:
        if log == True:
            print(f"\n🚀 Starting ARP scan over interface {iface.name} with IP {ip}...")
        arp_start = time.perf_counter()
        res = parallel_arp_scan2(iface.name,iface.mac,ip,msk,iface.max_workers,log)
        arp_end = time.perf_counter()
        data.add_arp_scan(iface.mac,res)
        if log == True:
            print(f"[*] ARP scan completed in {arp_end - arp_start:.6f} seconds.")
    return

def handle_PING_scan(iface:CustomIface,data:PacketLogger,log:bool):
    """
    Handles the PING scan on the specified interface.
    :param iface: CustomIface object with interface information
    :param data: PacketLogger object to store scan results
    :param log: Optional boolean to enable logging
    :return: None
    """
    for ip, _, _, msk in iface.get_ips_4():
        if log == True:
            print(f"\n🚀 Starting PING scan on interface {iface.name} and IP {ip}...")
        ping_start = time.perf_counter()
        res = parallel_ping_scan(ip,msk, iface.max_workers,log)
        ping_end = time.perf_counter()
        if res is None:
            continue
        data.add_ping_scan(iface.mac,res)
        if log == True:
            print(f"[*] PING scan completed in {ping_end - ping_start:.6f} seconds.")
    return
   
def handle_PORT_scan(iface:CustomIface,data:PacketLogger,ports:Union[int,list,tuple[int,int]],log:bool):
    """
    Handles the PORT scan on the specified interface.
    :param iface: CustomIface object with interface information
    :param data: PacketLogger object to store scan results
    :param ports: Ports to scan (int for single port, list for multiple ports, tuple for port range)
    :param log: Optional boolean to enable logging
    :return: None
    """
    if isinstance(ports,int):
        ports = [ports]
        output = f"\n🚀 Starting PORT scan {ports[0]} over interface {iface.name}"
    elif isinstance(ports,tuple) and len(ports) == 2 and isinstance(ports[0],int) and isinstance(ports[1],int):
        ports = list(range(ports[0], ports[1] + 1))
        output = f"\n🚀 Starting PORT scan {ports[0]}-{ports[-1]} over interface {iface.name}"
    elif isinstance(ports,list) and len(ports) > 3:
        output = f"\n🚀 Starting PORT scan [{ports[0]},...,{ports[-1]}] over interface {iface.name}"
    elif isinstance(ports,list):
        output = f"\n🚀 Starting PORT scan {ports} over interface {iface.name}"

    for ip,mac in data.get_ips_2():
        if not iface.ip_in_net(ip):
            continue
        src_ip = iface.get_net_ip_by_ip(ip)
        if src_ip == '':
            continue
        if log == True and output is not None:
            print(f"{output} on IP {ip}...")
        port_start = time.perf_counter()
        res = parallel_port_scan(src_ip,ip,ports,iface.max_workers)
        port_end = time.perf_counter()
        data.add_port_scan(iface.mac,mac,ip,res)
        if log == True:
            print(f"[*] PORT scan completed in {port_end - port_start:.6f} seconds.")

###############################################################
# x. Helpers
###############################################################
def l2_scan(packets:list,timeout:int=2,verbose=False):
    """
    Sends a list of packets on layer 2 and returns the answers.
    :param packets: List of packets to send
    :param timeout: Timeout for the scan in seconds
    :return: List of tuples with the source and response packets
    :rtype: list[tuple[Packet, Packet]]
    """
    ans,_ = srp(packets, timeout=timeout,verbose=verbose)
    return ans

def l3_scan(packets:list,timeout:int=2,verbose=False):
    """
    Sends a list of packets on layer 3 and returns the answers.
    :param packets: List of packets to send
    :param timeout: Timeout for the scan in seconds
    :return: List of tuples with the source and response packets
    :rtype: list[tuple[Packet, Packet]]
    """
    ans,_ = sr(packets, timeout=timeout,verbose=verbose)
    return ans

def parallel_port_scan(src_ip:str,dst_ip:str,port_range:List[int],max_worker:int):
    data = {}
    if ipaddress.ip_address(src_ip).version == 6:
        ip_pkt=IPv6(src=src_ip,dst=dst_ip)
    else:
        ip_pkt=IP(src=src_ip,dst=dst_ip)
    packets = [ip_pkt/TCP(dport=p, flags="S") for p in port_range]
    packets = random.sample(packets,len(packets))

    ans = l3_scan(packets)
    for s,r in ans:
        if r is not None and r.haslayer(TCP):
            data[str(s[TCP].dport)]= (str(r[TCP].flags),raw(r).hex())
    
    return dict(sorted(data.items(), key=lambda item: int(item[0])))

def ping_scan(ips:tuple[str,str],timeout:int=2) -> tuple[str,int,int,str]:
    if ipaddress.ip_address(ips[0]).version == 6:
        ans = sr1(IPv6(src=ips[0],dst=ips[1])/ICMP(), timeout=timeout,verbose=False)
    else:
        ans = sr1(IP(src=ips[0],dst=ips[1])/ICMP(), timeout=timeout,verbose=False)
    res = (ips[1],ans[0][ICMP].type,ans[0][ICMP].code,raw(ans[0]).hex()) if ans is not None else (ips[1],-1,-1,None)
    return res

def parallel_ping_scan(src_ip:str,src_msk:str,max_workers:int,log:Optional[bool]=None, timeout:int=2) -> dict[str,tuple[int,int,str]]:
    """
    """
    data = {}
    if ipaddress.ip_address(src_ip).version == 6:
        network = ipaddress.IPv6Network(f"{src_ip}/{src_msk}", strict=False)
        if network.num_addresses > MAX_IPS:
            print(f"Warning: Network {src_ip}/{src_msk} has more than {MAX_IPS} hosts. Skipping PING scan to avoid performance issues.")
            return
        # Use NDP for IPv6
    else:
        network = ipaddress.IPv4Network(f"{src_ip}/{src_msk}", strict=False)
        if network.num_addresses > MAX_IPS:
            print(f"Warning: Network {src_ip}/{src_msk} has more than {MAX_IPS} hosts. Skipping PING scan to avoid performance issues.")
            return
        ips = [(str(src_ip),str(ip)) for ip in network.hosts()]
        ips = random.sample(ips,len(ips))               # Randomize order
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(ping_scan,ip) for ip in ips]
            for future in as_completed(futures):
                ip, icmp_type, icmp_code, raw = future.result()
                data[ip] = (icmp_type, icmp_code, raw)
    
    return dict(sorted(data.items(), key=lambda item: ipaddress.ip_address(item[0])))

def arp_scan(info:tuple[str,str,str],timeout:int=2):
    ans = srp1(Ether(src=info[0],dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=info[2]),iface=info[1],timeout=timeout,verbose=0)
    return (ans[0][ARP].psrc,ans[0][ARP].hwsrc,raw(ans[0]).hex()) if ans is not None else (info[2],None,None)

def parallel_arp_scan2(name:str,mac:str,ip:str,mask:str,max_worker:int,log:Optional[bool]=None):
    """
    Scans the network for MAC addresses using ARP requests.
    :param iface: CustomIface object containing interface information
    :param log: Optional boolean to enable logging
    :return: Dictionary with IP addresses as keys and tuples of (MAC address, raw packet data) as values
    :rtype: dict[str, tuple[str, str]]
    """
    data = {}
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    ips = [(mac,name,str(ip)) for ip in network.hosts()]
    
    ips = random.sample(ips,len(ips))
    with ThreadPoolExecutor(max_workers=max_worker) as executor:
        futures = [executor.submit(arp_scan, ip) for ip in ips]
        for future in as_completed(futures):
            ip,mac,raw = future.result()
            data[ip] = (mac,raw)
    return dict(sorted(data.items(), key=lambda item: ipaddress.ip_address(item[0])))