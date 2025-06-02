# probing/active.py
from typing import Optional,Union,List
from scapy.all import *
from scapy.layers import l2, inet, inet6
from scapy.interfaces import resolve_iface
from scapy.utils import ltoa
# from scapy.compat import raw
from .definitions import *
from .packet_logger import *
import ipaddress
import random
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import gc
import time

# for testting
from config import DST_MAC,DST_IP6,DST_IP4,PORTS

# TODO: Add MAC, ARP scanning
# TODO: Add logging
# TODO: Add & Config shell output
# TODO: Fix IPv6 address detection

###############################################################
# x. Helpers
###############################################################
def get_ip6(iface:str) -> Union[List[str],str,None]:
    """
    Get IPv6 address of the interface
    """
    ips = []
    lock = 128
    for net,msk,gw,ifa,addr,_ in conf.route6.routes:
        if ifa == iface and msk == lock:
            ips.append(addr)


    # print(f"IPv6 addresses on {iface}: {ips}")
    if len(ips) == 0:
        return None
    if len(ips) == 1 and isinstance(ips[0],str):
        return ips[0]
    if len(ips) == 1 and isinstance(ips[0],list) and len(ips[0]) == 1:
        return ips[0][0]
    if len(ips) == 1 and isinstance(ips[0],list):
        return ips[0]
    return ips

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################

def active_probing(iface:CustomIfaces, scan_type:Optional[list]=None, data:Optional[PacketLogger]=None, log:Optional[bool]=None):
    """
    """
    if 'ALL' in scan_type:
        scan_type.extend(['ARP','PING','PORT'])      # Add all scan types if 'ALL' is selected

    output = "\n[*] Active Probing: "

    if isinstance(data,PacketLogger) and data != None:
        output = output + "logging, "
        # data.__context.dtype = 'active'
    
    if isinstance(log,bool) and log == True:
        output = output + "displaying, "

    # if isinstance(scan_type,list) and scan_type != None:
    #     for t in scan_type:
    #         if t == 'passive' or t == SCAN_TYPES['passive']: 
    #             continue
    #         if isinstance(t,int):
    #             output = output + SCAN_TYPES[t] +", "    
    #         else:
    #             output = output + t +", "
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
    
#     # Get IPv4 interface infos
#     if_mac = get_if_hwaddr(iface)
#     if_ip4 = get_if_addr(iface)
#     if_gw4 = conf.route.route(if_ip4)[2]
#     if_msk4 = 0xffffffff
#     if_net4 = 0
# 
#     for net,msk,gw,ifa,addr,_ in conf.route.routes:
#         # print(f"Net: {net}; MSK: {msk}; GW: {gw}; IFACE: {ifa}; Addr: {addr}")
#         if gw == if_gw4 and ifa == iface and msk > 4026531840 and msk < if_msk4:       # 4026531840 = F0000000 -> 240.0.0.0 reserved
#             if_msk4 = msk
#             if_net4 = net
# 
#     if_msk4 = ltoa(if_msk4)
#     if_net4 = ltoa(if_net4)
#     
#     # Get IPv6 interface infos
#     if_ip6 = get_ip6(iface) # because get_if_addr6() from scpay is not working
#     if_gw6 = conf.route6.route(if_ip6)[2]
#     if_net6 = if_ip6.split(':',1)[0] + "::" if if_ip6 != None else "::"
#     if_msk6 = 128       # 128 -> 128 bits are locked
#     for net,msk,gw,ifa,addr,_ in conf.route6.routes:
#         if gw == if_gw6 and ifa == iface and net == if_net6 and if_ip6 in addr and msk < if_msk6:       # 0 = ::/0
#             if_msk6 = msk
# 
#     ciface = CustomIfaces(if_mac,if_ip4,if_gw4,if_msk4,if_net4,if_ip6,if_gw6,if_msk6,if_net6,iface)

    # print(output + f"packets on interface {iface}: {if_mac}; {if_ip}; {if_net}/{if_msk}...\n")
    print(output + f"on interface: \n{iface}\n")
    # handle_TCP_active(iface,data,log)
    
    handle_IFACE_scan(iface,data,scan_type,log)

    if 'ARP' in scan_type:
        handle_ARP_scan(iface,data,log)
    if 'PING' in scan_type:
        handle_PING_scan(iface,data,log)
    if 'PORT' in scan_type:
        handle_PORT_scan(iface,PORTS,data,log)


    # TODO: Add MAC, ARP scanning
    # Info: First determine MAC addresses, then IPs of each MAC address and finally scan ports of each IP address

    

###############################################################
# x. Layer 2 (Ether, Dot3, ...)
###############################################################


###############################################################
# x. Layer 4 (UDP, TCP, ...)
###############################################################
def handle_TCP_active(iface:CustomIfaces,data:Optional[PacketLogger]=None,log:Optional[bool]=None):
    """
    """
    dst_mac = DST_MAC
    dst_ip = DST_IP4
    port_range = PORTS
    # res = ports_scan(ciface,dst_mac,dst_ip,port_range,log)
    # res4 = ping_scan(ciface.ip4,ciface.msk4)
    # res4 = parallel_ping_scan2(ciface.ip4,ciface.msk4,ciface.max_workers)
    # data.add_ping_scan(ciface.mac,dst_mac,res4)
    # gc.collect()            # TODO: Fix with multiprocessing
    # time.sleep(2)
    # res = parallel_port_scan(ciface.ip4,dst_ip,port_range,ciface.max_workers,log)
    # data.add_port_scan(ciface.mac,dst_mac,dst_ip,res)
    # res6 = ping_scan(ciface.ip6,ciface.msk6)
    # res6 = parallel_ping_scan(ciface.ip6,ciface.msk6)
    # data.add_ping_scan(ciface.ip6,dst_mac,res6)
    # res = parallel_arp_scan(iface)
    # print(data)
    # data.add_arp_scan(ciface.mac,res)

def handle_IFACE_scan(iface:CustomIfaces, data:PacketLogger, scan_type:Optional[list]=None, log:Optional[bool]=None):



def handle_ARP_scan(iface:CustomIfaces,data:Optional[PacketLogger]=None,log:Optional[bool]=None):
    """"""
    ifaces = iface.get_ifaces()
    # print(f"Scanning ARP on interfaces: {ifaces}")
    jobs = []
    for name in ifaces:
        mac = ifaces[name]['mac']
        for ip, _, _, msk in ifaces[name]['ipv4']:
            print(f"ARP scan on interface {name} with MAC {mac} and IP {ip}...")
            infos = (name, mac, ip, msk)
            jobs.append((parallel_arp_scan, mac, (infos,iface.max_workers,log)))
            # res = parallel_arp_scan(infos,iface.max_workers,log)
            # # print(f"ARP scan results on {name}: {res}")
            # data.add_arp_scan(ifaces[name]['mac'],res)

        # if log:
        #     print(f"ARP scan results on {name}: {res}")
        
    with multiprocessing.Pool(processes=iface.max_workers) as pool:
        results = list(tqdm(pool.imap_unordered(scan_job, jobs),total=len(jobs), desc="Running ARP scan jobs..."))
    
    for mac,res in results:
        print(f"ARP scan results for MAC {mac}: {res}")
        data.add_arp_scan(mac,res)

# def scan_job(func, id:str, args):
def scan_job(args):
    """
    Helper function to run a scan job in a separate process.
    :param func: Function to run the scan job
    :param id: ID of the scan job, used to identify the result
    :param args: Arguments to pass to the function
    :return: Tuple with the ID and the result of the scan job, or None if an error occurs.
    :rtype: tuple[str, Any] | None
    :raises Exception: If an error occurs during the scan job.
    """
    try:
        func, id, args = args
        res =  func(*args)
        return (id, res)
    except Exception as e:
        print(f"Error in scan job: {e}")
        return (None,None)

def handle_PING_scan(iface:CustomIfaces,data:Optional[PacketLogger]=None,log:Optional[bool]=None):
    """
    """
    ifaces = iface.get_ifaces()
    for name in ifaces:
        for ip, _, _, msk in ifaces[name]['ipv4']:
            print(f"PING sacn on interface {name} with MAC {ifaces[name]['mac']} and IP {ip}...")
            res = parallel_ping_scan2(ip,msk,iface.max_workers,log)
            # print(f"PING scan results on {name}: {res}")
            if res is None:
                continue
            data.add_ping_scan(ifaces[name]['mac'],res)
   
def handle_PORT_scan(iface:CustomIfaces,ports:Union[int,list,tuple[int,int]],data:Optional[PacketLogger]=None,log:Optional[bool]=None):
    """
    """
    ips = iface.check_networks_list(data.get_ips_2())
    for name in ips:
        iface.resync_conf()
        iface.keep_iface(name)
        src_mac = iface.get_mac(name)
        if isinstance(ports,int):
            print(f"Scanning port {ports} on interface {name} with MAC {src_mac}...")
        elif isinstance(ports,tuple) and len(ports) == 2:
            print(f"Scanning ports {ports[0]}-{ports[1]} on interface {name} with MAC {src_mac}...")
        elif isinstance(ports,list) and len(ports) > 3:
            print(f"Scanning ports [{ports[0]},...,{ports[len(ports)-1]}] on interface {name} with MAC {src_mac}...")
        elif isinstance(ports,list):
            print(f"Scanning ports {ports} on interface {name} with MAC {src_mac}...")


        for src_ip, ip, dst_mac in ips[name]:
            res = parallel_port_scan(src_ip,ip,ports,iface.max_workers,name,log)
            print(f"Port scan results on {ip} with MAC {dst_mac}: {res}")
            data.add_port_scan(src_mac,dst_mac,ip,res)

###############################################################
# x. Helpers
###############################################################
def port_scan(ciface:list[str],dst_mac:str,dst_ip:str,port:int,log:Optional[bool]=None,timeout:int=2):
    """
    Runs a TCP SYN scan on the given IP and port.
    Returns a tuple with the TCP flags and raw packet data.

    :param ciface: CustomIfaces object containing interface information (mac, ip4, ip6, name)
    :param dst_mac: Destination MAC address
    :param dst_ip: Destination IP address
    :param port: Port to scan
    :param log: Optional boolean to enable logging
    :param timeout: Timeout for the scan in seconds
    :return: Tuple containing TCP flags and raw packet data in hex format
    :rtype: tuple[str, str]
    """
    if isinstance(ciface,list) and len(ciface) != 4:
        raise ValueError("ciface must be a list with 4 elements: [mac, ip4, ip6, name]")
    if port < 0 or port > 65535:
        raise ValueError("Port must be between 0 and 65535")
    
    eth = Ether(src=ciface[0],dst=dst_mac)
    if ipaddress.ip_address(dst_ip).version == 6:
        ip = IPv6(src=ciface[2],dst=dst_ip)
    else:
        ip = IP(src=ciface[1],dst=dst_ip)
    tcp = TCP(sport=RandShort(),dport=port,flags="S")
    ans = srp1(eth/ip/tcp,iface=ciface[3], timeout=timeout,verbose=log)
    if ans is None: 
        return ('',None)
    return (str(ans[TCP].flags), raw(ans[0]).hex())

def port_scan2(info:tuple[str,str,int,str],timeout:int=2)-> tuple[int,str,str]:
    """
    Runs a TCP SYN scan on the given IP and port.   
    Returns a tuple with the IP, port, TCP flags and raw packet data.

    :param info: Tuple containing necessary information:
                  - src_ip: Source IP address
                  - dst_ip: Destination IP address
                  - dst_port: Destination port
                  - iface: Interface name (optional, used for IPv6)
    :param timeout: Timeout for the scan in seconds
    :return: Tuple containing the port, TCP flags and raw packet data in hex format
    :rtype: tuple[int, str, str]
    """
    if len(info) != 4:
        raise ValueError("info must be a tuple with 4 elements: (src_ip, dst_ip, dst_port)")
    if info[2] < 0 or info[2] > 65535:
        raise ValueError("Port must be between 0 and 65535")
    if ipaddress.ip_address(info[0]).version == 6:
        ans = srp1(IPv6(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False)
        # ans = srp1(IPv6(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False, threaded=False)
        # ans = srp1flood(IPv6(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False,iface=info[3])
        # ans = sendp1
        # ans = sendp(Ether()/IPv6(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"),verbose=False,iface=info[3])
    else:
        ans = srp1(IP(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False)
        # ans = srp1(IP(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False, threaded=False)
        # ans = srp1flood(IP(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False,iface=info[3])
        # ans = sendp(Ether()/IP(src=info[0],dst=info[1])/TCP(sport=RandShort(),dport=info[2],flags="S"), timeout=timeout,verbose=False,iface=info[3])

    # print(f"Ans: {ans}")
    return (info[2],str(ans[TCP].flags), raw(ans[0]).hex()) if ans is not None else (info[2],'',None)

def parallel_port_scan(src_ip:str,dst_ip:str,port_range:Union[int|list|tuple],max_workers:int,iface:str,log:Optional[bool]=None):
    """
    """
    data = {}
    if isinstance(port_range,int):
        # port,flags,raw = port_scan2((src_ip,dst_ip,port_range))
        port,flags,raw = port_scan2((src_ip,dst_ip,port_range,iface))
        data = {str(port):(flags,raw)}
    
    if isinstance(port_range,tuple) and len(port_range) == 2:
        start,end = port_range
        if isinstance(start,int) and isinstance(end,int):
            port_range = list(range(start,end+1))
            # print(port_range)
        else:
            raise ValueError("Both elements in the tuple must be integers.")

    if isinstance(port_range,list):
        # ports = [(src_ip,dst_ip,p) for p in port_range]
        ports = [(src_ip,dst_ip,p,iface) for p in port_range]
        
        ports = random.sample(ports,len(ports))           # Randomize order of ports
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            for port, flags, raw in tqdm(executor.map(port_scan2,ports),total=len(ports), desc=f"Scanning on {dst_ip}"):
                data[port] = (flags,raw)
                # print(f"Host {ip}: icmp type={data[ip][0]}, code={data[ip][1]}")
    return dict(sorted(data.items(), key=lambda item: int(item[0])))

def ports_scan(ciface:CustomIfaces,dst_mac:str,dst_ip:str,port_range:Optional[int|list|tuple]=None,log:Optional[bool]=None):
    """
    """
    data = {}
    if isinstance(port_range,int):
        ans = port_scan(ciface,dst_mac,dst_ip,port_range,log)
        data = {str(port_range):ans}
    
    if isinstance(port_range,tuple) and len(port_range) == 2:
        start,end = port_range
        if isinstance(start,int) and isinstance(end,int):
            port_range = list(range(start,end+1))
            # print(port_range)
        else:
            raise ValueError("Both elements in the tuple must be integers.")

    if isinstance(port_range,list):
        ports = random.sample(port_range,len(port_range))           # Randomize order of ports
        for port in tqdm(ports, desc="Scanning ports"):
            ans = port_scan(ciface,dst_mac,dst_ip,port,log=False)
            if str(port) not in data:
                data[str(port)] = ans

    return dict(sorted(data.items(), key=lambda item: int(item[0])))

def ping_scan(src_ip:str,src_msk:str,log:Optional[bool]=None, timeout:int=5):
    """
    """
    data = {}
    if ipaddress.ip_address(src_ip).version == 6:
        ip_pkt = IPv6(src=src_ip)
        network = ipaddress.IPv6Network(f"{src_ip}/{src_msk}", strict=False)
    else:
        ip_pkt = IP(src=src_ip)
        network = ipaddress.IPv4Network(f"{src_ip}/{29}", strict=False)
    print(f"Scanning hosts on {network}...")
    # for ip in network.hosts():
    #     ip = str(ip)
    #     print(f"Scanning {ip}")
    #     ip_pkt.dst = ip
    #     ans = sr1(ip_pkt/ICMP(), timeout=timeout,verbose=False)
    #     data[ip] = ans[0] if ans is not None else None
    ips = []
    for ip in network.hosts():
        ips.append(str(ip))
    for ip in tqdm(ips, desc=f"Scanning IPs on {network}"):
        ip = str(ip)
        # print(f"Scanning {ip}")
        ip_pkt.dst = ip
        ans = sr1(ip_pkt/ICMP(), timeout=timeout,verbose=False)
        data[ip] = (ans[0][ICMP].type,ans[0][ICMP].code,raw(ans[0]).hex()) if ans is not None else (-1,-1,None)
        # print(f"Host {ip}: icmp type={data[ip][0]}, code={data[ip][1]}")
    return data

def ping_scan2(ips:tuple[str,str],timeout:int=2) -> tuple[str,int,int,str]:
    if ipaddress.ip_address(ips[0]).version == 6:
        ans = sr1(IPv6(src=ips[0],dst=ips[1])/ICMP(), timeout=timeout,verbose=False)
    else:
        ans = sr1(IP(src=ips[0],dst=ips[1])/ICMP(), timeout=timeout,verbose=False)
    # return (ips[1],ans[0][ICMP].type,ans[0][ICMP].code,raw(ans[0]).hex()) if ans is not None else (ips[1],-1,-1,None)
    # print(ans)
    # if ans is None:
    #     return (ips[1],-1,-1,None)
    res = (ips[1],ans[0][ICMP].type,ans[0][ICMP].code,raw(ans[0]).hex()) if ans is not None else (ips[1],-1,-1,None)
    # print(res)
    return res

def parallel_ping_scan(src_ip:str,src_msk:str,max_workers:int,log:Optional[bool]=None, timeout:int=2):
    """
    """
    data = {}
    if ipaddress.ip_address(src_ip).version == 6:
        network = ipaddress.IPv6Network(f"{src_ip}/{src_msk}", strict=False)
        # Use NDP for IPv6
    else:
        network = ipaddress.IPv4Network(f"{src_ip}/{src_msk}", strict=False)
        ips = [(str(src_ip),str(ip)) for ip in network.hosts()]
        ips = random.sample(ips,len(ips))               # Randomize order of IPs
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # with ThreadPoolExecutor(max_workers=len(ips)) as executor:
            # for ip, icmp_type, icmp_code, raw in tqdm(executor.map(ping_scan2,ips),total=len(ips), desc=f"Scanning IPs on {network}"):
            for ip, icmp_type, icmp_code, raw in executor.map(ping_scan2,ips):
                data[ip] = (icmp_type, icmp_code, raw)
    
    return dict(sorted(data.items(), key=lambda item: ipaddress.ip_address(item[0])))

def parallel_ping_scan2(src_ip:str,src_msk:str,max_workers:int,log:Optional[bool]=None, timeout:int=2) -> dict[str,tuple[int,int,str]]:
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
        # network = ipaddress.IPv4Network(f"{src_ip}/{src_msk}", strict=False)
        network = ipaddress.IPv4Network(f"{src_ip}/{src_msk}", strict=False)
        if network.num_addresses > MAX_IPS:
            print(f"Warning: Network {src_ip}/{src_msk} has more than {MAX_IPS} hosts. Skipping PING scan to avoid performance issues.")
            return
        ips = [(str(src_ip),str(ip)) for ip in network.hosts()]
        ips = random.sample(ips,len(ips))               # Randomize order of IPs
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # with ThreadPoolExecutor(max_workers=len(ips)) as executor:
            futures = [executor.submit(ping_scan2,ip) for ip in ips]
            # for future in as_completed(futures):
            for future in tqdm(as_completed(futures), total=len(futures), desc=f"Scanning IPs on {network}..."):
                ip, icmp_type, icmp_code, raw = future.result()
                data[ip] = (icmp_type, icmp_code, raw)
    
    return dict(sorted(data.items(), key=lambda item: ipaddress.ip_address(item[0])))

def arp_scan(info:tuple[str,str,str],timeout:int=2):
    ans = srp1(Ether(src=info[0],dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=info[2]),iface=info[1],timeout=timeout,verbose=0)
    return (ans[0][ARP].psrc,ans[0][ARP].hwsrc,raw(ans[0]).hex()) if ans is not None else (info[2],None,None)

def parallel_arp_scan(ciface:tuple[str,str,str,int],max_worker:int,log:Optional[bool]=None):
    """
    Scans the network for MAC addresses using ARP requests.
    :param ciface: CustomIfaces object containing interface information (name, mac, ip4, mask, max_workers)
    :param log: Optional boolean to enable logging
    :return: Dictionary with IP addresses as keys and tuples of (MAC address, raw packet data) as values
    :rtype: dict[str, tuple[str, str]]
    """
    data = {}
    # network = ipaddress.IPv4Network(f"{ciface[2]}/{ciface[3]}", strict=False)
    network = ipaddress.IPv4Network(f"{ciface[2]}/24", strict=False)
    # print(f"Creating ip list")
    ips = [(ciface[1],ciface[0],str(ip)) for ip in network.hosts()]
    # print(f"Scanning MACs of {ips}...")
    ips = random.sample(ips,len(ips))
    with ThreadPoolExecutor(max_workers=max_worker) as executor:
        for ip,mac,raw in tqdm(executor.map(arp_scan,ips), total=len(ips),desc=f"Scanning MACs on {network}..."):
            data[ip] = (mac,raw)
    return dict(sorted(data.items(), key=lambda item: ipaddress.ip_address(item[0])))
