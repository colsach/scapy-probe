# probing/packet_logger.py
import json
import ipaddress
import threading
from typing import Optional
from .definitions import *

class PacketLogger:
    """
    A class to log packets and save them to a JSON file.
    """
    ###############################################################
    # 1. Initializer and save functions
    ###############################################################
    def __init__(self,filename:Optional[str]=None, log:Optional[bool]=None):
        self.log = log if log is not None else False
        self.filename = filename if filename is not None else 'packet_log.json'
        self.__data = {'active': {}, 'passive': {}}
        self.__dtype = 'passive'
        self.__lock = threading.Lock()

    def __init_new_mac(self, mac: str) -> None:
        """
        Initialize a new MAC address entry in the data dictionary.
        """
        if mac not in self.__data:
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

    def __check_ip_version(self, ip:str) -> str:
        """
        Check the IP version of a given IP address.
        """
        try:
            v = str(ipaddress.ip_address(ip).version)
            return f'IPv{v}'
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
        
    def save_to_json(self) -> None:
        """
        Save the logged data to a JSON file.
        """
        export = json.loads(json.dumps(self.__data, default=lambda o: list(o) if isinstance(o, set) else o))
        with open(self.filename, 'w') as f:
            json.dump(export, f, indent=2)
        
        print(f"Data saved to {self.filename}")

    ###############################################################
    # 2. Summary functions
    ###############################################################

    def add_sum_dst_mac(self, src_mac: str, dst_mac: str) -> None:
        """
        Add a destination MAC address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_macs')
        if dst_mac not in self.__data[self.__dtype][src_mac]['summary']['dst_macs']:
            self.__data[self.__dtype][src_mac]['summary']['dst_macs'].append(dst_mac)
    
    def add_sum_ethertype(self, src_mac: str, ether_type: int) -> None:
        """
        Add an EtherType to the summary.
        """
        self.__init_new_sum_list(src_mac, 'ether_types')
        if ether_type not in self.__data[self.__dtype][src_mac]['summary']['ether_types']:
            self.__data[self.__dtype][src_mac]['summary']['ether_types'].append(ether_type)
        
    def add_sum_hwtype(self, src_mac: str, hw_type: int) -> None:
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

    def add_sum_src_ip(self, src_mac: str, ip: str) -> None:
        """
        Add a source IP address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'src_ips')
        if ip not in self.__data[self.__dtype][src_mac]['summary']['src_ips']:
            self.__data[self.__dtype][src_mac]['summary']['src_ips'].append(ip)
        
    def add_sum_dst_ip(self, src_mac: str, ip: str) -> None:
        """
        Add a destination IP address to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_ips')
        if ip not in self.__data[self.__dtype][src_mac]['summary']['dst_ips']:
            self.__data[self.__dtype][src_mac]['summary']['dst_ips'].append(ip)
        
    def add_sum_protocol(self, src_mac: str, protocol: int) -> None:
        """
        Add a protocol to the summary.
        """
        self.__init_new_sum_list(src_mac, 'protocols')
        if protocol not in self.__data[self.__dtype][src_mac]['summary']['protocols']:
            self.__data[self.__dtype][src_mac]['summary']['protocols'].append(protocol)
    
    def add_sum_src_port(self, src_mac: str, port: int) -> None:
        """
        Add a source port to the summary.
        """
        self.__init_new_sum_list(src_mac, 'src_ports')
        if port not in self.__data[self.__dtype][src_mac]['summary']['src_ports']:
            self.__data[self.__dtype][src_mac]['summary']['src_ports'].append(port)
    
    def add_sum_dst_port(self, src_mac: str, port: int) -> None:
        """
        Add a destination port to the summary.
        """
        self.__init_new_sum_list(src_mac, 'dst_ports')
        if port not in self.__data[self.__dtype][src_mac]['summary']['dst_ports']:
            self.__data[self.__dtype][src_mac]['summary']['dst_ports'].append(port)

    def add_sum_layer(self, src_mac: str, layer: str) -> None:
        """
        Add a layer to the summary.
        """
        self.__init_new_sum_list(src_mac, 'layers')
        if layer not in self.__data[self.__dtype][src_mac]['summary']['layers']:
            self.__data[self.__dtype][src_mac]['summary']['layers'].append(layer)
    
    def add_sum_vlan_id(self, src_mac: str, vlan_id: int) -> None:
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
        self.__add_dst_mac(src_mac, ether_type)
        self.add_sum_ethertype(src_mac, ether_type)
        
        if ether_type not in ETHER_TYPES:
            if str(ether_type) not in self.__data[self.__dtype][src_mac][dst_mac]:
                self.__data[self.__dtype][src_mac][dst_mac][str(ether_type)] = {}
        else:
            if ETHER_TYPES[ether_type] not in self.__data[self.__dtype][src_mac][dst_mac]:
                self.__data[self.__dtype][src_mac][dst_mac][ETHER_TYPES[ether_type]] = {}

    def add_arp(self, src_mac:str, src_ip:str, dst_mac:str, dst_ip:str, hwtype:int, op:int, raw:str) -> None:
        """
        Add an ARP entry to destination MAC address dictionary.
        """
        self.__add_ether_type(src_mac, dst_mac, ETHER_TYPES['ARP'])
        self.add_sum_layer(src_mac, 'ARP')
        hw_type = HARDWARE_TYPES[hwtype] if hwtype in HARDWARE_TYPES else str(hwtype)
        op_type = ARP_OPERATIONS[op] if op in ARP_OPERATIONS else str(op)
        
        if hw_type not in self.__data[self.__dtype][src_mac][dst_mac]['ARP']:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type] = {}

        if op_type not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type]:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]

        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]:
            self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]['raw'] = []
        
        if raw not in self.__data[self.__dtype][src_mac][dst_mac]['ARP'][hw_type][op_type]['raw']:
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
        
    def __add_ip(self, src_mac: str, dst_mac: str, dst_ip: str) -> None:
        """
        Add an IP entry to the destination MAC address dictionary.
        """
        ip_version = self.__check_ip_version(dst_ip)
        self.__add_ether_type(src_mac, dst_mac, ETHER_TYPES[ip_version])
        self.add_sum_layer(src_mac, ip_version)
        self.add_sum_dst_ip(src_mac, dst_ip)

        if dst_ip not in self.__data[self.__dtype][src_mac][dst_mac][ip_version]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version] = {}

    def __add_ip_protocol(self, src_mac: str, dst_mac: str, dst_ip: str, protocol: int) -> None:
        """
        Add an IP protocol entry to the destination IP address dictionary.
        """
        self.__add_ip(src_mac, dst_mac, dst_ip)
        self.add_sum_protocol(src_mac, protocol)
        ip_version = self.__check_ip_version(dst_ip)
        proto = self.__check_protocol(ip_version, protocol)
        
        if proto not in self.__data[self.__dtype][src_mac][dst_mac][dst_ip][ip_version]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto] = {}

    def add_icmp(self, src_mac: str, dst_mac: str, dst_ip: str, icmp_type: int, icmp_code: int,raw:str) -> None:
        """
        Add an ICMP entry to the destination IP address dictionary.
        """
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
        
        if raw not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][types][codes]['raw']:
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
    
    def add_raw_data(self, src_mac: str, dst_mac: str, dst_ip: str, protocol: int, port: int, raw: str) -> None:
        """
        Add raw data to the destination port entry.
        """
        self.__dtype = 'passive'
        self.__add_dst_port(src_mac, dst_mac, dst_ip, protocol, port)
        ip_version = self.__check_ip_version(dst_ip)
        proto = self.__check_protocol(ip_version, protocol)
        
        if 'raw' not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw'] = []
        
        if raw not in self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw']:
            self.__data[self.__dtype][src_mac][dst_mac][ip_version][dst_ip][proto][str(port)]['raw'].append(raw)

    ###############################################################
    # 4. Transport Packet functions (Ether/IP/TCP or UDP)
    ###############################################################

    def add_port_scan(self, src_mac: str, dst_mac: str, dst_ip: str, res: dict) -> None:
        """
        Add a port scan result to the data dictionary.
        """
        self.__dtype = 'active'
        self.__add_ip(src_mac,dst_mac,dst_ip)
        self.add_sum_scan_type(src_mac, 'port_scan')

        
        if dst_ip not in self.__data[self.__dtype][src_mac][dst_mac][dst_ip]['ports']:
            self.__data[self.__dtype][src_mac][dst_mac][dst_ip]['ports'] = {'open': [], 'closed': [], 'filtered': [], 'unknown': []}
        
        for port in res:
            if res[port] == 'open':
                self.add_sum_dst_port(src_mac, port)
                self.__add_dst_port(src_mac, dst_mac, dst_ip, IP_PROTOCOLS['tcp'], port)
                self.__data[self.__dtype][src_mac][dst_mac]['TCP'][dst_ip][str(port)] = {'status': 'open'}