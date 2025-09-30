# probing/packet_logger.py
import json
import ipaddress
import threading
from multiprocessing.managers import BaseManager
from typing import Optional, Tuple, Union
from .definitions import *
from scapy.all import *

class PacketLogger:
    """
    A class to log packets and save them to a JSON file.
    """
    ###############################################################
    # 1. Initializer and save functions
    ###############################################################
    def __init__(self,filename:Optional[str]=None, log:Optional[bool]=None):
        self.log = log if log is not None else False
        self.filename = filename if filename is not None else 'inventory.json'
        self.__data = {'active': {}, 'passive': {}}
        self.__dtype = 'passive'
        self.__lock = {
            'active': threading.Lock(),
            'passive': threading.Lock()
        }
        self.__context = threading.local()
        self.__context.dtype = self.__dtype

    def __init_new_mac(self, mac: str) -> None:
        """
        Initialize a new MAC address entry in the data dictionary.
        """
        if mac not in self.__data[self.__dtype]:
            self.__data[self.__dtype][mac] = {}
    
    def __init_new_sum(self, mac: str) -> None:
        """
        Initialize a new summary entry for a given MAC address.
        """
        self.__init_new_mac(mac)
        if 'summary' not in self.__data[self.__dtype][mac]:
            self.__data[self.__dtype][mac]['summary'] = {}
    
    def __init_new_sum_list(self, mac: str, item: str) -> None:
        """
        Initialize a new summary list for a given MAC address and item.
        """
        self.__init_new_sum(mac)
        if item not in self.__data[self.__dtype][mac]['summary']:
            self.__data[self.__dtype][mac]['summary'][item] = []

    def __get_dtype(self) -> str:
        """
        Get the current data type (active or passive).
        """
        return getattr(self.__context, 'dtype', self.__dtype)

    def __check_ip_version(self, ip:str) -> str:
        """
        Check the IP version of a given IP address.
        """
        try:
            v = ipaddress.ip_address(ip).version
            if v == 4:
                return 'IPv4'
            elif v == 6:
                return 'IPv6'
            else:
                return 'unknown'
        except ValueError:
            return 'unknown'
        
    def __check_protocol(self, ip_version: str, prtcl: int) -> str:
        """
        Check the protocol based on the IP version.
        """
        if ip_version == 'IPv6':
            return IPV6NH[prtcl] if prtcl in IPV6NH else str(prtcl)
        elif ip_version == 'IPv4':
            return IP_PROTOCOLS[prtcl] if prtcl in IP_PROTOCOLS else str(prtcl)
        else:
            return 'unknown'
    def __extend_unique(self, lst: list, item: Union[str, list,Tuple[str,str]]) -> None:
        """
        Extend a list with unique items.
        """
        if isinstance(item, list):
            for i in item:
                if i not in lst:
                    lst.append(i)
        elif isinstance(item, tuple):
            if item not in lst:
                lst.append(item)
        else:
            if item not in lst:
                lst.append(item)    

    def save_to_json(self) -> None:
        """
        Save the logged data to a JSON file.
        """
        export = json.loads(json.dumps(self.__data, default=lambda o: list(o) if isinstance(o, set) else o))
        with open(self.filename, 'w') as f:
            json.dump(export, f, indent=2)
        
        print(f"Data saved to {self.filename}")

    def __str__(self):
        return f"PacketLogger(filename={self.filename}, log={self.log})\nData: {json.dumps(self.__data, indent=2)}"

    ###############################################################
    # 2. Summary functions
    ###############################################################
    def add_sum_dst_mac(self, src_mac: str, dst_mac: str, dtype='passive') -> None:
        """
        Add a destination MAC address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_macs')
        if dst_mac not in self.__data[self.__dtype][src_mac]['summary']['dst_macs']:
            self.__data[self.__dtype][src_mac]['summary']['dst_macs'].append(dst_mac)
    
    def add_sum_ethertype(self, src_mac: str, ether_type: int, dtype='passive') -> None:
        """
        Add an EtherType to the summary.
        """
        self.__init_new_sum_list(src_mac, 'ether_types')
        if ether_type not in self.__data[self.__dtype][src_mac]['summary']['ether_types']:
            self.__data[self.__dtype][src_mac]['summary']['ether_types'].append(ether_type)
        
    def add_sum_hwtype(self, src_mac: str, hw_type: int, dtype='passive') -> None:
        """
        Add a hardware type to the summary.
        """
        self.__init_new_sum_list(src_mac, 'hw_types')
        if hw_type not in HARDWARE_TYPES:
            if hw_type not in self.__data[self.__dtype][src_mac]['summary']['hw_types']:
                self.__data[self.__dtype][src_mac]['summary']['hw_types'].append(hw_type)
        else:
            if HARDWARE_TYPES[hw_type] not in self.__data[self.__dtype][src_mac]['summary']['hw_types']:
                self.__data[self.__dtype][src_mac]['summary']['hw_types'].append(HARDWARE_TYPES[hw_type])

    def add_sum_src_ip(self, src_mac: str, ip: str, dtype='passive') -> None:
        """
        Add a source IP address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'src_ips')
        if ip not in self.__data[self.__dtype][src_mac]['summary']['src_ips']:
            self.__data[self.__dtype][src_mac]['summary']['src_ips'].append(ip)
        
    def add_sum_dst_ip(self, src_mac: str, ip: str, dtype='passive') -> None:
        """
        Add a destination IP address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_ips')
        if ip not in self.__data[self.__dtype][src_mac]['summary']['dst_ips']:
            self.__data[self.__dtype][src_mac]['summary']['dst_ips'].append(ip)
        
    def add_sum_protocol(self, src_mac: str, protocol: int, dtype='passive') -> None:
        """
        Add a protocol to the summary.
        """
        self.__init_new_sum_list(src_mac, 'protocols')
        if protocol not in self.__data[self.__dtype][src_mac]['summary']['protocols']:
            self.__data[self.__dtype][src_mac]['summary']['protocols'].append(protocol)
    
    def add_sum_src_port(self, src_mac: str, port: int, dtype='passive') -> None:
        """
        Add a source port to the summary.
        """
        self.__init_new_sum_list(src_mac, 'src_ports')
        if port not in self.__data[self.__dtype][src_mac]['summary']['src_ports']:
            self.__data[self.__dtype][src_mac]['summary']['src_ports'].append(port)
    
    def add_sum_dst_port(self, src_mac: str, port: int, dtype='passive') -> None:
        """
        Add a destination port to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_ports')
        if port not in self.__data[self.__dtype][src_mac]['summary']['dst_ports']:
            self.__data[self.__dtype][src_mac]['summary']['dst_ports'].append(port)

    def add_sum_layer(self, src_mac: str, layer: str, dtype='passive') -> None:
        """
        Add a layer to the summary.
        """
        self.__init_new_sum_list(src_mac, 'layers')
        if layer not in self.__data[self.__dtype][src_mac]['summary']['layers']:
            self.__data[self.__dtype][src_mac]['summary']['layers'].append(layer)
    
    def add_sum_vlan_id(self, src_mac: str, vlan_id: int, dtype='passive') -> None:
        """
        Add a VLAN ID to the summary.
        """
        self.__init_new_sum_list(src_mac, 'vlan_ids')
        if vlan_id not in self.__data[self.__dtype][src_mac]['summary']['vlan_ids']:
            self.__data[self.__dtype][src_mac]['summary']['vlan_ids'].append(vlan_id)

    def add_sum_scan_type(self, src_mac: str, scan_type: str) -> None:
        """
        Add a scan type to the summary.
        """
        self.__init_new_sum_list(src_mac, 'scan_types')
        if scan_type not in self.__data[self.__dtype][src_mac]['summary']['scan_types']:
            self.__data[self.__dtype][src_mac]['summary']['scan_types'].append(scan_type)

    def add_sum_scan_result(self,src_mac:str, result:str,dst_mac:Optional[str]=None) -> None:
        """
        Add a scan result to the summary.
        """
        if dst_mac is None:
            self.__init_new_mac(src_mac)
            if 'summary' not in self.__data[self.__dtype][src_mac]:
                self.__data[self.__dtype][src_mac]['summary'] = {}

            if result not in self.__data[self.__dtype][src_mac]['summary']:
                self.__data[self.__dtype][src_mac]['summary'][result] = {}
        else:
            self.__add_dst_mac(src_mac, dst_mac)

            if 'summary' not in self.__data[self.__dtype][src_mac][dst_mac]:
                self.__data[self.__dtype][src_mac][dst_mac]['summary'] = {}

            if result not in self.__data[self.__dtype][src_mac][dst_mac]['summary']:
                self.__data[self.__dtype][src_mac][dst_mac]['summary'][result] = {}

    ###############################################################
    # 3. Transport Packet functions (Ether/IP/TCP or UDP)
    ###############################################################
    def __add_dst_mac(self, src_mac: str, dst_mac: str) -> None:
        """
        Add a destination MAC address entry to the source MAC address.
        """
        self.__init_new_mac(src_mac)
        self.add_sum_dst_mac(src_mac, dst_mac)
        
        if dst_mac not in self.__data[self.__dtype][src_mac]:
            self.__data[self.__dtype][src_mac][dst_mac] = {}

    def __add_ether_type(self, src_mac: str, dst_mac: str, ether_type: int) -> None:
        """
        Add an EtherType entry to the destination MAC address dictionary.
        """
        self.__add_dst_mac(src_mac, dst_mac)
        self.add_sum_ethertype(src_mac, ether_type)
            
        if ether_type not in ETHER_TYPES:
            if str(ether_type) not in self.__data[self.__dtype][src_mac][dst_mac]:
                self.__data[self.__dtype][src_mac][dst_mac][str(ether_type)] = {}
        else:
            if str(ETHER_TYPES[ether_type]) not in self.__data[self.__dtype][src_mac][dst_mac]:
                self.__data[self.__dtype][src_mac][dst_mac][str(ETHER_TYPES[ether_type])] = {}

    def add_arp(self, src_mac:str, src_ip:str, dst_mac:str, dst_ip:str, hwtype:int, op:int, vlan:Optional[Tuple[int,int,int]]=None, raw:Optional[str]=None) -> None:
        """
        Add an ARP entry to destination MAC address dictionary.
        """
        self.__dtype = 'passive'
        self.__add_ether_type(src_mac, dst_mac, ETHER_TYPES_R['ARP'])
        self.add_sum_layer(src_mac, 'ARP')
        hw_type = HARDWARE_TYPES[hwtype] if hwtype in HARDWARE_TYPES else str(hwtype)
        op_type = ARP_OPERATIONS[op] if op in ARP_OPERATIONS else str(op)

        if hw_type not in self.__data[self.__dtype][src_mac][dst_mac]['ARP']:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type] = {}

        if op_type not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type]:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type] = {}

        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]:
                self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]['raw'] = []
            
        if raw is not None and raw not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]['raw']:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]['raw'].append(raw)

        if op == ARP_OPERATIONS['who-has']:
            self.add_sum_src_ip(src_mac, src_ip)
            self.add_sum_dst_ip(src_mac, dst_ip)
            self.add_sum_hwtype(src_mac, hwtype)
        elif op == ARP_OPERATIONS['is-at']:
            self.add_sum_src_ip(src_mac, src_ip)
            self.add_sum_src_ip(dst_mac, dst_ip)
            self.add_sum_dst_ip(src_mac, dst_ip)
            self.add_sum_dst_ip(dst_mac, src_ip)
            self.add_sum_hwtype(src_mac, hwtype)
            self.add_sum_hwtype(dst_mac, hwtype)
        else:
            return

    def add_ndp(self, src_mac:str, src_ip:str, dst_mac:str, dst_ip:str, nd_type:int,options:Optional[str]=None,vlan:Optional[Tuple[int,int,int]]=None,raw:Optional[str]=None) -> None:
        """
        Add an NDP entry to destination MAC address dictionary.
        nd_type can be 'NS', 'NA', 'RS' or 'RA'
        """
        self.__dtype = 'passive'
        self.__add_ether_type(src_mac, dst_mac, ETHER_TYPES_R['IPv6'])
        self.add_sum_layer(src_mac, 'NDP')
        if nd_type not in NDP_TYPES:
            return
        
        if options is not None and nd_type in [NDP_TYPES['RA'],NDP_TYPES['NA']]:      # Advertisment -> DstLLAddr
            self.__add_ether_type(src_mac,options,ETHER_TYPES_R['IPv6'])
            if 'NDP' not in self.__data[self.__dtype][src_mac][options]:
                self.__data[self.__dtype][src_mac][options]['NDP'] = {}

            if NDP_TYPES[nd_type] not in self.__data[self.__dtype][src_mac][options]['NDP']:
                self.__data[self.__dtype][src_mac][options]['NDP'][NDP_TYPES[nd_type]] = {}

            if 'raw' not in self.__data[self.__dtype][src_mac][options]['NDP'][NDP_TYPES[nd_type]]:
                self.__data[self.__dtype][src_mac][options]['NDP'][NDP_TYPES[nd_type]]['raw'] = []
            
            if raw is not None and raw not in self.__data[self.__dtype][src_mac][options]['NDP'][NDP_TYPES[nd_type]]['raw']:
                self.__data[self.__dtype][src_mac][options]['NDP'][NDP_TYPES[nd_type]]['raw'].append(raw)
            
            self.add_sum_src_ip(src_mac, src_ip)
            self.add_sum_dst_ip(src_mac, dst_ip)
        elif options is not None and nd_type in [NDP_TYPES['RS'],NDP_TYPES['NS']]:    # Solicitation -> SrcLLAddr
            self.__add_ether_type(options,dst_mac,ETHER_TYPES_R['IPv6'])
            if 'NDP' not in self.__data[self.__dtype][options][dst_mac]:
                self.__data[self.__dtype][options][dst_mac]['NDP'] = {}

            if NDP_TYPES[nd_type] not in self.__data[self.__dtype][options][dst_mac]['NDP']:
                self.__data[self.__dtype][options][dst_mac]['NDP'][NDP_TYPES[nd_type]] = {}

            if 'raw' not in self.__data[self.__dtype][options][dst_mac]['NDP'][NDP_TYPES[nd_type]]:
                self.__data[self.__dtype][options][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw'] = []
            
            if raw is not None and raw not in self.__data[self.__dtype][options][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw']:
                self.__data[self.__dtype][options][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw'].append(raw)
            pass

        if 'NDP' not in self.__data[self.__dtype][src_mac][dst_mac]:
            self.__data[self.__dtype][src_mac][dst_mac]['NDP'] = {}

        if NDP_TYPES[nd_type] not in self.__data[self.__dtype][src_mac][dst_mac]['NDP']:
            self.__data[self.__dtype][src_mac][dst_mac]['NDP'][NDP_TYPES[nd_type]] = {}

        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac]['NDP'][NDP_TYPES[nd_type]]:
            self.__data[self.__dtype][src_mac][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw'] = []
        
        if raw is not None and raw not in self.__data[self.__dtype][src_mac][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw']:
            self.__data[self.__dtype][src_mac][dst_mac]['NDP'][NDP_TYPES[nd_type]]['raw'].append(raw)

        if nd_type == NDP_TYPES['NS']:
            self.add_sum_src_ip(src_mac, src_ip)
            self.add_sum_dst_ip(src_mac, dst_ip)
            
        elif nd_type == NDP_TYPES['NA']:
            self.add_sum_src_ip(src_mac, src_ip)
            self.add_sum_src_ip(dst_mac, dst_ip)
            self.add_sum_dst_ip(src_mac, dst_ip)
            self.add_sum_dst_ip(dst_mac, src_ip)
        else:
            return

    def __add_ip(self, src_mac: str, dst_mac: str, dst_ip: str) -> None:
        """
        Add an IP entry to the destination MAC address dictionary.
        """
        ip_version = self.__check_ip_version(dst_ip)
        self.__add_ether_type(src_mac, dst_mac, ETHER_TYPES_R.get(ip_version,0))
        
        self.add_sum_layer(src_mac, ip_version)
        self.add_sum_dst_ip(src_mac, dst_ip)

        if dst_ip not in self.__data[self.__dtype][src_mac][dst_mac][ip_version]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip] = {}

    def __add_ip_protocol(self, src_mac: str, dst_mac: str, dst_ip: str, protocol: int) -> None:
        """
        Add an IP protocol entry to the destination IP address dictionary.
        """
        self.__add_ip(src_mac, dst_mac, dst_ip)
        self.add_sum_protocol(src_mac, protocol)
        ip_version = self.__check_ip_version(dst_ip)
        proto = self.__check_protocol(ip_version, protocol)
        
        if proto not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto] = {}

    def add_icmp(self, src_mac: str, dst_mac: str, dst_ip: str, icmp_type: int, icmp_code: int, vlan:Optional[Tuple[int,int,int]]=None, raw:Optional[str]=None) -> None:
        """
        Add an ICMP entry to the destination IP address dictionary.
        """
        self.__dtype = 'passive'
        ip_version = self.__check_ip_version(dst_ip)
        if ip_version == 'IPv4':
            protocol = IP_PROTOCOLS['icmp']
            types = ICMP_TYPES[icmp_type] if icmp_type in ICMP_TYPES else str(icmp_type)
            codes = ICMP_CODES[icmp_type][icmp_code] if icmp_type in ICMP_CODES and icmp_code in ICMP_CODES[icmp_type] else str(icmp_code)
        elif ip_version == 'IPv6':
            protocol = IPV6NH['ICMPv6']
            types = ICMPV6_TYPES[icmp_type] if icmp_type in ICMPV6_TYPES else str(icmp_type)
            codes = ICMPV6_CODES[icmp_type][icmp_code] if icmp_type in ICMPV6_CODES and icmp_code in ICMPV6_CODES[icmp_type] else str(icmp_code)
        else:
            return
        
        self.__add_ip_protocol(src_mac, dst_mac, dst_ip, protocol)
        self.add_sum_layer(src_mac, f'ICMPv{ip_version[-1]}')
        self.add_sum_protocol(src_mac, protocol)
        proto = self.__check_protocol(ip_version, protocol)
        
        if types not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types] = {}
        
        if codes not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes] = {}

        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes]['raw'] = []
        
        if raw is not None and raw not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes]['raw']:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes]['raw'].append(raw)

    def __add_dst_port(self, src_mac: str, dst_mac: str, dst_ip: str, protocol: int, port: int) -> None:
        """
        Add a destination port entry to the IP protocol dictionary.
        """
        self.__add_ip_protocol(src_mac, dst_mac, dst_ip, protocol)
        self.add_sum_dst_port(src_mac, port)
        ip_version = self.__check_ip_version(dst_ip)
        proto = self.__check_protocol(ip_version, protocol)

        if str(port) not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)] = {}

    def add_raw_data(self, src_mac: str, dst_mac: str, dst_ip: str, protocol: int, port: int, vlan:Optional[Tuple[int,int,int]]=None, raw:Optional[str]=None) -> None:
        """
        Add raw data to the destination port entry.
        """
        self.__dtype = 'passive'
        self.__add_dst_port(src_mac, dst_mac, dst_ip, protocol, port)
        ip_version = self.__check_ip_version(dst_ip)
        proto = self.__check_protocol(ip_version, protocol)

        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw'] = []
        
        if raw is not None and raw not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw']:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw'].append(raw)

    ###############################################################
    # 4. Active probing functions
    ###############################################################
    def __get_dst_mac_by_ip(self, dst_ip: str) -> str:
        """
        Get the destination MAC address by IP address.
        """
        for src_mac in self.__data['passive']:
            if self.__data['passive'][src_mac]['summary']['src_ips'] is not None and dst_ip in self.__data['passive'][src_mac]['summary']['src_ips']:
                return src_mac
            for dst_mac in self.__data['passive'][src_mac]:
                if dst_mac == 'summary':
                    continue
                for protocol in self.__data['passive'][src_mac][dst_mac]:
                    if dst_ip in self.__data['passive'][src_mac][dst_mac][protocol]:
                        return dst_mac
        for src_mac in self.__data['active']:
            if src_mac =='unknown':
                continue
            for dst_mac in self.__data['active'][src_mac]:
                if dst_mac == 'summary':
                    continue
                if dst_ip in self.__data['active'][src_mac][dst_mac]:
                    return dst_mac
        return None

    def get_macs(self) -> list:
        """
        Get a list of MAC addresses from the data dictionary.
        """
        macs = []
        with self.__lock['active']:
            macs.extend(list(self.__data['active'].keys()))
        with self.__lock['passive']:
            macs.extend(list(self.__data['passive'].keys()))
        macs = list(set(macs))
        return macs
    
    def get_ips(self,dst_mac:str) -> list:
        """
        Get a list of IP addresses for a given MAC address from the data dictionary.
        """
        ips = []
        if dst_mac in self.__data['active']:
            ips.extend(list(self.__data['active'][dst_mac].keys()))
            ips = list(set(ips))

        if dst_mac in self.__data['passive']:
            ips.extend(list(self.__data['passive'][dst_mac].keys()))
            ips = list(set(ips))
        
        return ips
    
    def __find_mac_by_ip(self, ip: str) -> Optional[str]:
        """
        Find the MAC address associated with a given IP address.
        Returns the MAC address if found, otherwise None.
        """
        for src_mac in self.__data['active']:
            for dst_mac in self.__data['active'][src_mac]:
                if dst_mac == 'summary':
                    continue
                else:
                    for protocol in self.__data['active'][src_mac][dst_mac]:
                        if protocol == 'summary':
                            continue
                        if ip in self.__data['active'][src_mac][dst_mac][protocol]:
                            return dst_mac
        
        for src_mac in self.__data['passive']:
            for dst_mac in self.__data['passive'][src_mac]:
                if dst_mac == 'summary':
                   continue
                else:
                    for protocol in self.__data['passive'][src_mac][dst_mac]:
                        if ip in self.__data['passive'][src_mac][dst_mac][protocol]:
                            return dst_mac
        
        return None
    
    def get_ips_2(self) -> list[Tuple[str, str]]:
        """
        Get a list of all IP addresses from the data dictionary.
        Returns a list of tuples (dst_ip,dst_mac).
        """
        ips = []
        for src_mac in self.__data['active']:
            for dst_mac in self.__data['active'][src_mac]:
                if dst_mac == 'summary':
                    if 'dst_ips' in self.__data['active'][src_mac]['summary']:
                        self.__extend_unique(ips, self.__data['active'][src_mac]['summary']['dst_ips'])
                else:
                    for ip in self.__data['active'][src_mac][dst_mac]:
                        try:
                            _ = ipaddress.ip_address(ip)
                            self.__extend_unique(ips, ip)
                        except ValueError:
                            pass
        
        for src_mac in self.__data['passive']:
            for dst_mac in self.__data['passive'][src_mac]:
                if dst_mac == 'summary':
                    if 'src_ips' in self.__data['passive'][src_mac]['summary']:
                        self.__extend_unique(ips, self.__data['passive'][src_mac]['summary']['src_ips'])
                    if 'dst_ips' in self.__data['passive'][src_mac]['summary']:
                        self.__extend_unique(ips, self.__data['passive'][src_mac]['summary']['dst_ips'])
                else:
                    for protocol in self.__data['passive'][src_mac][dst_mac]:
                        for ip in self.__data['passive'][src_mac][dst_mac][protocol]:
                            try:
                                _ = ipaddress.ip_address(ip)
                                self.__extend_unique(ips, ip)
                            except ValueError:
                                pass
        res = []
        for ip in ips:
            for src_mac in self.__data['active']:
                if 'summary' in self.__data['active'][src_mac] and \
                    'ping_scan' in self.__data['active'][src_mac]['summary'] and \
                    'unknown' in self.__data['active'][src_mac]['summary']['ping_scan'] and \
                    ip  not in self.__data['active'][src_mac]['summary']['ping_scan']['unknown']:
                    mac = self.__get_dst_mac_by_ip(ip)
                    if mac is not None and  mac != 'unknown' and (ip,mac) not in res:
                        res.append((ip, mac))                 
        return res

    def __interpret_port_scan(self, port:int, response:str) -> str:
        """
        Interpret the port scan result.
        """
        if response == 'SA':
            return 'open'
        elif response == 'RA':
            return 'closed'
        else:
            return 'unknown'
    
    def __interpret_icmp(self, icmp_type:int, code:int) -> str:
        """
        Interpret the ICMP type and code.
        """
        if icmp_type in ICMP_TYPES and icmp_type in ICMP_CODES and code in ICMP_CODES[icmp_type]:
            if icmp_type == 0 and code == 0:
                return 'UP'
            elif icmp_type == 3 and code == 0:
                return 'FILTERED_OR_UNREACHABLE'
            elif icmp_type == 3 and code == 1:
                return 'HOST_UNREACHABLE_OR_DOWN'
            elif icmp_type == 3 and code == 3:
                return 'PORT_UNREACHABLE'
            elif icmp_type == 3 and code == 13:
                return 'BLOCKED_BY_FIREWALL'
            elif icmp_type == 11 and code == 0 or icmp_type == 11 and code == 1:
                return 'TTL_EXPIRED__HOST_MAY_BE_UP'

        return 'unknown'
        
    def add_port_scan(self, src_mac: str, dst_mac: str, dst_ip: str, scan: dict) -> None:
        """
        Add a port scan result to the data dictionary.
        Structure of the port scan result must be: 
            {
                '<port>': (flags, raw_data),
                ...
            }
        """
        self.__dtype = 'active'
        self.__add_dst_mac(src_mac, dst_mac)
        self.add_sum_scan_result(src_mac, 'port_scan')
        self.add_sum_scan_result(src_mac, 'port_scan', dst_mac)
        self.add_sum_dst_ip(src_mac, dst_ip,self.__dtype)
        self.add_sum_dst_mac(src_mac, dst_mac,self.__dtype)
        self.add_sum_src_ip(dst_mac, dst_ip,self.__dtype)

        if dst_mac not in self.__data[self.__dtype][src_mac]['summary']['port_scan']:
            self.__data[self.__dtype][src_mac]['summary']['port_scan'][dst_mac] = {}
        if dst_ip not in self.__data[self.__dtype][src_mac]['summary']['port_scan'][dst_mac]:
            self.__data[self.__dtype][src_mac]['summary']['port_scan'][dst_mac][dst_ip] = {'open': [], 'closed': [], 'filtered': [], 'unknown': []}

        if dst_ip not in self.__data[self.__dtype][src_mac][dst_mac]['summary']['port_scan']:
            self.__data[self.__dtype][src_mac][dst_mac]['summary']['port_scan'][dst_ip] = {'open': [], 'closed': [], 'filtered': [], 'unknown': []}

        if dst_ip not in self.__data[self.__dtype][src_mac][dst_mac]:
            self.__data[self.__dtype][src_mac][dst_mac][dst_ip] = {}

        if 'tcp' not in self.__data[self.__dtype][src_mac][dst_mac][dst_ip]:
            self.__data[self.__dtype][src_mac][dst_mac][dst_ip]['tcp'] = {}

        for port in scan:
            flags, raw_data = scan[port]
            res = self.__interpret_port_scan(int(port),flags)
            self.__data[self.__dtype][src_mac]['summary']['port_scan'][dst_mac][dst_ip][res].append(int(port))
            self.__data[self.__dtype][src_mac][dst_mac]['summary']['port_scan'][dst_ip][res].append(int(port))
            if port not in self.__data[self.__dtype][src_mac][dst_mac][dst_ip]['tcp']:
                self.__data[self.__dtype][src_mac][dst_mac][dst_ip]['tcp'][port] = {'flags': flags, 'interpretation': res, 'raw': raw_data}

    def add_ping_scan(self,src_mac:str,scan:dict) -> None:
        """
        Add a ping scan result to the data dictionary.
        Structure of the ping scan result must be: 
            {
                '<ip>': (icmp_type, code, raw),
                ...
            }
        """
        self.__dtype = 'active'
        self.add_sum_scan_result(src_mac, 'ping_scan')
        
        if not self.__data[self.__dtype][src_mac]['summary']['ping_scan']:
            self.__data[self.__dtype][src_mac]['summary']['ping_scan'] = {'UP': [], 'FILTERED_OR_UNREACHABLE': [], 'HOST_UNREACHABLE_OR_DOWN': [], 'PORT_UNREACHABLE': [], 'BLOCKED_BY_FIREWALL': [], 'TTL_EXPIRED__HOST_MAY_BE_UP': [], 'unknown': []}

        for ip in scan:
            dst_mac = self.__get_dst_mac_by_ip(ip)
            self.__add_dst_mac(src_mac, dst_mac)
            self.add_sum_dst_mac(src_mac, dst_mac,self.__dtype)
            self.add_sum_dst_ip(src_mac, ip,self.__dtype)
            icmp_type, code, raw = scan[ip]
            res = self.__interpret_icmp(icmp_type, code)
            if ip not in self.__data[self.__dtype][src_mac]['summary']['ping_scan'][res]:
                    self.__data[self.__dtype][src_mac]['summary']['ping_scan'][res].append(ip)

            if dst_mac is not None:
                if dst_mac not in self.__data[self.__dtype][src_mac]['summary']['ping_scan']:
                    self.__data[self.__dtype][src_mac]['summary']['ping_scan'][dst_mac] = {'UP': [], 'FILTERED_OR_UNREACHABLE': [], 'HOST_UNREACHABLE_OR_DOWN': [], 'PORT_UNREACHABLE': [], 'BLOCKED_BY_FIREWALL': [], 'TTL_EXPIRED__HOST_MAY_BE_UP': [], 'unknown': []}
                if res not in self.__data[self.__dtype][src_mac]['summary']['ping_scan'][dst_mac]:
                    self.__data[self.__dtype][src_mac]['summary']['ping_scan'][dst_mac][res] = []
                if ip not in self.__data[self.__dtype][src_mac]['summary']['ping_scan'][dst_mac][res]:
                    self.__data[self.__dtype][src_mac]['summary']['ping_scan'][dst_mac][res].append(ip)
                
                if dst_mac not in self.__data[self.__dtype][src_mac]:
                    self.__data[self.__dtype][src_mac][dst_mac]= {}

                if ip not in self.__data[self.__dtype][src_mac][dst_mac]:
                    self.__data[self.__dtype][src_mac][dst_mac][ip] = {}

                if 'icmp' not in self.__data[self.__dtype][src_mac][dst_mac][ip]:
                    self.__data[self.__dtype][src_mac][dst_mac][ip]['icmp'] = {'type': icmp_type, 'code': code, 'interpretation': res,'raw': raw}
            else:
                if 'unknown' not in self.__data[self.__dtype][src_mac]:
                    self.__data[self.__dtype][src_mac]['unknown'] = {}
                if ip not in self.__data[self.__dtype][src_mac]['unknown']:
                    self.__data[self.__dtype][src_mac]['unknown'][ip] = {}
                if 'icmp' not in self.__data[self.__dtype][src_mac]['unknown'][ip]:
                    self.__data[self.__dtype][src_mac]['unknown'][ip]['icmp'] = {'type': icmp_type, 'code': code, 'interpretation': res,'raw': raw}

    def add_arp_scan(self,src_mac:str,scan:dict) -> None:
        """
        Add a ARP scan result to the data dictionary.
        Structure of the ARP scan result must be:
            {
                '<ip>': (mac,raw),
                ...
            }
        """
        self.__dtype = 'active'
        self.add_sum_scan_result(src_mac, 'arp_scan')

        for ip in scan:
            mac,raw = scan[ip]
            if mac == None and raw == None:
                continue
            self.add_sum_dst_mac(src_mac,mac,'active')
            self.add_sum_dst_ip(src_mac,ip,'active')

            if mac not in self.__data[self.__dtype][src_mac]:
                self.__data[self.__dtype][src_mac][mac] = {}
            if ip not in self.__data[self.__dtype][src_mac][mac]:
                self.__data[self.__dtype][src_mac][mac][ip] = {}
            if 'arp' not in self.__data[self.__dtype][src_mac][mac][ip]:
                self.__data[self.__dtype][src_mac][mac][ip]['arp'] = {}
            if 'raw' not in self.__data[self.__dtype][src_mac][mac][ip]['arp']:
                self.__data[self.__dtype][src_mac][mac][ip]['arp']['raw'] = []
            if raw not in self.__data[self.__dtype][src_mac][mac][ip]['arp']['raw']:
                self.__data[self.__dtype][src_mac][mac][ip]['arp']['raw'].append(raw)

            if 'arp_scan' not in self.__data[self.__dtype][src_mac]['summary']:
                self.__data[self.__dtype][src_mac]['summary']['arp_scan'] = {}

            if mac not in self.__data[self.__dtype][src_mac]['summary']['arp_scan']:
                self.__data[self.__dtype][src_mac]['summary']['arp_scan'][mac] = {}
            
            if ip not in self.__data[self.__dtype][src_mac]['summary']['arp_scan'][mac]:
                self.__data[self.__dtype][src_mac]['summary']['arp_scan'][mac] = {ip:raw}

class SharedPacketLogger(BaseManager): pass
SharedPacketLogger.register('PacketLogger',PacketLogger)

class CustomIface:
    """
    Custom Interface class containing all interfaces, IPv4/6s with corresponding newtork, gateway and mask.
    This class is used to handle the interfaces in a more flexible way, allowing to add and remove interfaces dynamically.
    """
    def __init__(self, name:str, mac:str=None, ip4:list[Tuple[str,str,str,str]]=None, ip6:list[Tuple[str,str,str,str]]=None,max_workers:int=None):
        """
        Custom Interface class containing all interfaces, IPv4/6s with corresponding newtork, gateway and mask.
        :param name: Name of the interface
        :param mac: MAC address of the interface
        :param ip4: List of IPv4 addresses, gateways, networks and masks
        :param ip6: List of IPv6 addresses, gateways, networks and masks
        :param max_workers: Maximum number of workers for the interface, if None, it will be set to the default value.
        """
        self.name = name                            # type: str
        self.mac = mac                              # type: str
        self.ip4 = ip4 if ip4 is not None else []   # type: list[Tuple[str,str,str,str]]
        self.ip6 = ip6 if ip6 is not None else []   # type: list[Tuple[str,str,str,str]]
        self.max_workers = max_workers if max_workers is not None else WIN_MAX_WORKERS # type: int
    
    def __str__(self) -> str:
        output += f"{self.name} - MAC: {self.mac}\n"
        if self.ip4 is not None:
            for ip,gw,net,msk in self.ip4:
                output += f"\tIPv4: {ip}, GW: {gw}, NET: {net}, MSK: {msk}\n"
            for ip in self.ip6:
                output += f"\tIPv6: {ip}\n"
        return output
    
    def add_ipv4(self, ip:str, gw:str, net:str, msk:str) -> None:
        """
        Add an IPv4 address to the interface.
        :param ip: IPv4 address
        :param gw: Gateway of the IPv4 address
        :param net: Network of the IPv4 address
        :param msk: Mask of the IPv4 address
        """
        if (ip, gw, net, msk) not in self.ip4:
            self.ip4.append((ip, gw, net, msk))
    
    def add_ipv6(self, ip:str, gw:str, net:str, msk:str) -> None:
        """
        Add an IPv6 address to the interface.
        :param ip: IPv6 address
        :param gw: Gateway of the IPv6 address
        :param net: Network of the IPv6 address
        :param msk: Mask of the IPv6 address
        """
        if (ip, gw, net, msk) not in self.ip6:
            self.ip6.append((ip, gw, net, msk))

    def get_ips(self) -> list[Tuple[str,str,str,str]]:
        """
        Get all IP addresses of the interface, both IPv4 and IPv6.
        :return: List of IP addresses
        """
        ips = []
        ips.extend(self.ip4)
        ips.extend(self.ip6)
        return ips
    
    def get_ips_4(self) -> list[Tuple[str,str,str,str]]:
        """
        Get all IPv4 addresses of the interface.
        :return: List of IPv4 addresses
        """
        return self.ip4
    
    def get_ips_6(self) -> list[Tuple[str,str,str,str]]:
        """
        Get all IPv6 addresses of the interface.
        :return: List of IPv6 addresses
        """
        return self.ip6

    def ip_in_net(self,ip:str) -> bool:
        """
        Check if the given IP address is in the network of the interface.
        :param ip: IP address to check
        :return: True if the IP address is in the network, False otherwise
        """
        for ip4, _, _, msk4 in self.ip4:
            if ip == ip4:
                return False
            if ipaddress.ip_address(ip) in ipaddress.ip_interface(f"{ip4}/{msk4}").network:
                return True
        for ip6, _, _, msk6 in self.ip6:
            if ip == ip6:
                return False
            if ipaddress.ip_address(ip) in ipaddress.ip_interface(f"{ip6}/{msk6}").network:
                return True
        return False
    
    def get_net_ip_by_ip(self,ip:str) -> str:
        """"""
        for ip4, _,_,msk4 in self.ip4:
            if ip == ip4:
                return ''
            if ipaddress.ip_address(ip) in ipaddress.ip_interface(f"{ip4}/{msk4}").network:
                return ip4
        for ip6, _,_,msk6 in self.ip4:
            if ip == ip6:
                return ''
            if ipaddress.ip_address(ip) in ipaddress.ip_interface(f"{ip6}/{msk6}").network:
                return ip6
        return ''

    def delt_ip(self,ip:str) -> None:
        """
        Delete the given IP address from the interface.
        :param ip: IP address to delete
        """
        for i in range(len(self.ip4)):
            if self.ip4[i][0] == ip:
                del self.ip4[i]
                return
        for i in range(len(self.ip6)):
            if self.ip6[i][0] == ip:
                del self.ip6[i]
                return
        return
    
    def remove_route(self,conf) -> None:
        """
        Remove the interface from the Scapy conf routes.
        :param conf: Scapy conf object
        """
        try:
            conf.route.ifdel(self.name)
        except Exception as e:
            print(f"CustomIface: Problem removing route for interface {self.name}.\nError: {e}")
        return
    
    def add_route(self,conf) -> None:
        """
        Add the interface to the Scapy conf routes.
        :param conf: Scapy conf object
        """
        try:
            for ip, gw, net, msk in self.ip4:
                network = f"{net}/{msk}"
                conf.route.add(dev=self.name, host=ip, gw=gw, net=network)
            for ip, gw, net, msk in self.ip6:
                network = f"{net}/{msk}"
                conf.route6.add(dev=self.name, host=ip, gw=gw, net=network)
        except Exception as e:
            print(f"CustomIface: Problem adding route for interface {self.name}.\nError: {e}")
        return

    def check_id(self,id:str) -> bool:
        """
        Check if the interface ID matches the given ID.
        :param id: ID to check
        :return: True if the ID matches, False otherwise
        """
        return self.name == id or self.mac == id or id in self.ip4 or id in self.ip6
    

class CustomIfacesManager:
    """
    Custom Ifaces Manager class to handle multiple interfaces.
    This class is used to handle the interfaces in a more flexible way, allowing to add and remove interfaces dynamically.
    """
    def __init__(self,conf:scapy.config.conf,whitelist:Union[str,list[str]]=None,blacklist:Union[str,list[str]]=None):
        """
        Custom Ifaces Manager class to handle multiple interfaces.
        :param conf: Scapy conf object
        :param whitelist: Either a string or a list of strings, containing the interfaces or ips to include in the probing. Complete interface name or with '*' for a group can be included. If None, all interfaces are included.
        :param blacklist: Either a string or a list of strings, containing the interfaces or ips not to include in the probing. Complete interface name or with '*' for a group can be included. If None, the default is: 'lo', 'docker*', 'vibr*' and 'br-*'.
        """
        self.conf = conf
        self.__routes = None        # type: scapy.config.Route
        self.__ifaces = None        # type: dict[str,CustomIface]
        self.__whitelist = None     # type: dict[list[str],list[str]]
        self.__blacklist = None     # type: dict[list[str],list[str]]
        self.max_workers = None     # type: int

        if whitelist is None and blacklist is None:
            self.__blacklist = {'name':['lo'],'regex':['docker','virbr','br-']}
            self.__whitelist = None
        elif whitelist is None and blacklist is not None:
            self.__blacklist = self.__init_watchlist(blacklist)
            self.__whitelist = None
        elif whitelist is not None:
            self.__whitelist = self.__init_watchlist(whitelist)
            self.__blacklist = None

        self.__init_max_workers()
        self.__init_ifaces()
        
    def __str__(self):

        return ""
    
    def __init_watchlist(self,watchlist:Union[str,list[str]]) -> dict[str,list[str]]:
        """
        Initialize the watchlist.
        :param final_list: Dictionary to store the final watchlist (either self.__whitelist or self.__blacklist).
        :param watchlist: Either a string or a list of strings, containing the interfaces or ips to include or exclude in the probing. Complete interface name or with '*' for a group can be included.
        """
        final_list = {'name':[],'regex':[]}
        if watchlist is not None:
            if isinstance(watchlist,str) and '*' in watchlist:
                final_list['regex'].append(watchlist.split('*',1)[0])
            elif isinstance(watchlist,str) and '*' not in watchlist:
                final_list['name'].append(watchlist)
            elif isinstance(watchlist,list):
                for item in watchlist:
                    if '*' in item:
                        final_list['regex'].append(item.split('*',1)[0])
                    else:
                        final_list['name'].append(item)
        return final_list
    
    def __init_ifaces(self) -> None:
        """
        Initialize the interfaces.
        This method fetches the interfaces from the Scapy conf and creates a CustomIface object for each interface.
        """
        self.__ifaces = {}
        if self.__whitelist is not None:
            for iface in self.conf.ifaces.values():
                if self.__check_watchlist(iface.name, self.__whitelist):    
                    mac = iface.mac
                    ipv4s = self.__init_ipv4((iface.name, iface.ips[4]))
                    ipv6s = self.__init_ipv6((iface.name, iface.ips[6]))
                    self.__ifaces[iface.name] = CustomIface(name=iface.name, mac=mac, ip4=ipv4s, ip6=ipv6s, max_workers=self.max_workers)
        elif self.__blacklist is not None:
            for iface in self.conf.ifaces.values():
                if not self.__check_watchlist(iface.name, self.__blacklist):
                    mac = iface.mac
                    ipv4s = self.__init_ipv4((iface.name, iface.ips[4]))
                    ipv6s = self.__init_ipv6((iface.name, iface.ips[6]))
                    self.__ifaces[iface.name] = CustomIface(name=iface.name, mac=mac, ip4=ipv4s, ip6=ipv6s, max_workers=self.max_workers)
        return
        
    def __check_watchlist(self,iface:str,watchlist:dict[str,list[str]]) -> bool:
        """
        Check if the interface is in the watchlist.
        :param iface: Interface name to check
        :param watchlist: Watchlist to check against (either self.__whitelist or self.__blacklist).
        :return: True if the interface is in the watchlist, False otherwise.
        """
        if iface in watchlist['name']:
            return True
        for regex in watchlist['regex']:
            if regex in iface:
                return True
        return False

    def __init_max_workers(self) -> None:
        """
        Initialize the maximum number of workers for the probing.
        This method sets the maximum number of workers to 10% of the soft limit of open files, or to a predefined constant if the system does not support it.
        """
        try:
            soft_limit, self.max_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            self.max_workers = min(int(soft_limit * 0.1), MAX_WORKERS)
        except Exception as e:
            print(e)
            self.max_workers = WIN_MAX_WORKERS

    def __init_ipv4(self,info:tuple[str,list[str]]) -> list[tuple[str,str,str,str]]:
        """
        Initialize the IPv4 addresses, gateways, networks and masks.
        :param ips: List of IPv4 addresses to initialize
        :return: List of tuples containing the IPv4 address, gateway, network and mask
        """
        res = []
        name, ips = info
        for ip in ips:
            _,_,gw = self.conf.route.route(ip)
            msk4 = 0xffffffff
            net4 = 0
            for net, msk,gw, ifa,addr,_ in self.conf.route.routes:
                if ifa == name and addr == ip and msk > 4026531840 and msk < msk4:       # 4026531840 = F0000000 ->
                    net4 = net
                    msk4 = msk
                    continue
            msk4 = scapy.utils.ltoa(msk4)
            net4 = scapy.utils.ltoa(net4)
            res.append((ip, gw, net4, msk4))
        return res
    
    def __init_ipv6(self,info:tuple[str,list[str]]) -> list[tuple[str,str,str,str]]:
        """
        Initialize the IPv6 addresses, gateways, networks and masks.
        :param ips: List of IPv6 addresses to initialize
        :return: List of tuples containing the IPv6 address, gateway, network and mask
        """
        # TODO: Implement IPv6 initialization
        return
    
    def get_ifaces(self) -> list[Tuple[str,CustomIface]]:
        """
        Get the interfaces dictionary.
        :return: Dictionary with interface names as keys and CustomIface objects as values.
        """
        res = []
        for name in self.__ifaces:
            res.append((name,self.__ifaces[name]))
        return res
    
    def get_iface(self,id:str) -> Union[CustomIface,None]:
        """
        Get the interface by name, MAC or IPv4/6.
        :param id: Interface name, mac, or IP to get
        :return: CustomIface object if the interface exists, None otherwise.
        """
        for name in self.__ifaces:
            if self.__ifaces[name].check_id(id):
                return self.__ifaces[name]
        return None
    
    def get_ifaces_names(self) -> list[str]:
        """
        Get the list of interface names.
        :return: List of interface names.
        """
        res = []
        for name in self.__ifaces:
            res.append(name)
        return res