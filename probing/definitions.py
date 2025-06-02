# probing/definitions.py
import resource
###############################################################
# x. Probing Tool Definitions
###############################################################

SCAN_TYPES = {
    -1: "all",
    0:  "passive",
    1:  "active",
    2:  "mac",
    3:  "ip",
    4:  "arp",
    5:  "icmp",
    6:  "tcp",
    7:  "udp",
}
SCAN_TYPES.update({v: k for k,v in SCAN_TYPES.items()})

MAX_WORKERS = 100
WIN_MAX_WORKERS = 64
MAX_IPS = 2000

###############################################################
# x. Protocol Definitions
###############################################################


ETHER_TYPES = {
    0x0800:"IPv4"        , # IP (IPv4)                                   
    0x0805:"X25"         , #                                             
    0x0806:"ARP"         , # Address Resolution Protocol                 
    0x0808:"FR_ARP"      , # Frame Relay ARP [RFC1701]                   
    0x08FF:"BPQ"         , # G8BPQ AX.25 over Ethernet                   
    0x22F3:"TRILL"       , # TRILL [RFC6325]                             
    0x22F4:"L2-IS-IS"    , # TRILL IS-IS [RFC6325]                       
    0x6558:"TEB"         , # Transparent Ethernet Bridging [RFC1701]     
    0x6559:"RAW_FR"      , # Raw Frame Relay [RFC1701]                   
    0x8035:"RARP"        , # Reverse ARP [RFC903]                        
    0x809B:"ATALK"       , # Appletalk                                   
    0x80F3:"AARP"        , # Appletalk Address Resolution Protocol       
    0x8100:"802_1Q"      , # VLAN tagged frame [802.1q]                  
    0x8137:"IPX"         , # Novell IPX                                  
    0x8191:"NetBEUI"     , # NetBEUI                                     
    0x86DD:"IPv6"        , # IP version 6                                
    0x880B:"PPP"         , # Point-to-Point Protocol                     
    0x8847:"MPLS"        , # MPLS [RFC5332]                              
    0x8848:"MPLS_MULTI"  , # MPLS with upstream-assigned label [RFC5332] 
    0x884C:"ATMMPOA"     , # MultiProtocol over ATM                      
    0x8863:"PPP_DISC"    , # PPP over Ethernet discovery stage           
    0x8864:"PPP_SES"     , # PPP over Ethernet session stage             
    0x8884:"ATMFATE"     , # Frame-based ATM Transport over Ethernet     
    0x888E:"EAPOL"       , # EAP over LAN [802.1x]                       
    0x88A8:"S-TAG"       , # QinQ Service VLAN tag identifier [802.1q]   
    0x88C7:"EAP_PREAUTH" , # EAPOL Pre-Authentication [802.11i]          
    0x88CC:"LLDP"        , # Link Layer Discovery Protocol [802.1ab]     
    0x88E5:"MACSEC"      , # Media Access Control Security [802.1ae]     
    0x88E7:"PBB"         , # Provider Backbone Bridging [802.1ah]        
    0x88F5:"MVRP"        , # Multiple VLAN Registration Protocol [802.1q]
    0x88F7:"PTP"         , # Precision Time Protocol                     
    0x8906:"FCOE"        , # Fibre Channel over Ethernet                 
    0x8914:"FIP"         , # FCoE Initialization Protocol                
    0x8915:"ROCE"        , # RDMA over Converged Ethernet                
    0xA0ED:"LoWPAN"      , # LoWPAN encapsulation
}
ETHER_TYPES_R = {v: k for k, v in ETHER_TYPES.items()}  # Reverse mapping for lookup

HARDWARE_TYPES = {
    1: "Ethernet (10Mb)",
    2: "Ethernet (3Mb)",
    3: "AX.25",
    4: "Proteon ProNET Token Ring",
    5: "Chaos",
    6: "IEEE 802 Networks",
    7: "ARCNET",
    8: "Hyperchannel",
    9: "Lanstar",
    10: "Autonet Short Address",
    11: "LocalTalk",
    12: "LocalNet",
    13: "Ultra link",
    14: "SMDS",
    15: "Frame relay",
    16: "ATM",
    17: "HDLC",
    18: "Fibre Channel",
    19: "ATM",
    20: "Serial Line",
    21: "ATM",
}
HARDWARE_TYPES.update({v: k for k, v in HARDWARE_TYPES.items()})  # Reverse mapping for lookup

ARP_OPERATIONS = {
    1: "who-has",
    2: "is-at",
    3: "RARP-req",
    4: "RARP-rep",
    5: "DRARP-req",
    6: "DRARP-rep",
    7: "DRARP-err",
    8: "InARP-req",
    9: "InARP-rep"
}
ARP_OPERATIONS.update({v: k for k, v in ARP_OPERATIONS.items()})  # Reverse mapping for lookup

IP_PROTOCOLS = {
    0   :"ip",
    1   :"icmp",
    2   :"igmp",
    3   :"ggp",
    4   :"ipencap",
    5   :"st",
    6   :"tcp",
    8   :"egp",
    9   :"igp",
    12  :"pup",
    17  :"udp",
    20  :"hmp",
    22  :"xns-idp",
    27  :"rdp",
    29  :"is-tp4",
    33  :"dccp",
    36  :"xtp",
    37  :"ddp",
    38  :"idpr-cmtp",
    41  :"ipv6",
    43  :"ipv6-route",
    44  :"ipv6-frag",
    45  :"idrp",
    46  :"rsvp",
    47  :"gre",
    50  :"esp",
    51  :"ah",
    57  :"skip",
    58  :"ipv6-icmp",
    59  :"ipv6-nonxt",
    60  :"ipv6-opts",
    73  :"rspf",
    81  :"vmtp",
    88  :"eigrp",
    89  :"ospf",
    93  :"ax.25",
    94  :"ipip",
    97  :"etherip",
    98  :"encap",
    103 :"pim",
    108 :"ipcomp",
    112 :"vrrp",
    115 :"l2tp",
    124 :"isis",
    132 :"sctp",
    133 :"fc",
    135 :"mobility-header",
    136 :"udplite",
    137 :"mpls-in-ip",
    138 :"manet",
    139 :"hip",
    140 :"shim6",
    141 :"wesp",
    142 :"rohc",
    143 :"ethernet",
    262 :"mptcp",
}
IP_PROTOCOLS.update({v: k for k, v in IP_PROTOCOLS.items()})  # Reverse mapping for lookup

IPV6NH = {
    0: "Hop-by-Hop Option Header",
    4: "IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    43: "Routing Header",
    44: "Fragment Header",
    47: "GRE",
    50: "ESP Header",
    51: "AH Header",
    58: "ICMPv6",
    59: "No Next Header",
    60: "Destination Option Header",
    112: "VRRP",
    132: "SCTP",
    135: "Mobility Header"
}
IPV6NH.update({v: k for k, v in IPV6NH.items()})  # Reverse mapping for lookup

IPV6NHCLS = {
    0: "IPv6ExtHdrHopByHop",
    4: "IP",
    6: "TCP",
    17: "UDP",
    43: "IPv6ExtHdrRouting",
    44: "IPv6ExtHdrFragment",
    50: "ESP",
    51: "AH",
    58: "ICMPv6Unknown",
    59: "Raw",
    60: "IPv6ExtHdrDestOpt"
}
IPV6NHCLS.update({v: k for k, v in IPV6NHCLS.items()})  # Reverse mapping for lookup

ICMP_TYPES = {
    0: "echo-reply",
    3: "dest-unreach",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
    15: "information-request",
    16: "information-response",
    17: "address-mask-request",
    18: "address-mask-reply",
    30: "traceroute",
    31: "datagram-conversion-error",
    32: "mobile-host-redirect",
    33: "ipv6-where-are-you",
    34: "ipv6-i-am-here",
    35: "mobile-registration-request",
    36: "mobile-registration-reply",
    37: "domain-name-request",
    38: "domain-name-reply",
    39: "skip",
    40: "photuris"
}
ICMP_TYPES.update({v: k for k,v in ICMP_TYPES.items()}) # Reverse mapping for lookup

ICMP_CODES = {
    0: { 0: "echo-reply" },
    3: {
        0: "network-unreachable",
        1: "host-unreachable",
        2: "protocol-unreachable",
        3: "port-unreachable",
        4: "fragmentation-needed",
        5: "source-route-failed",
        6: "network-unknown",
        7: "host-unknown",
        9: "network-prohibited",
        10: "host-prohibited",
        11: "TOS-network-unreachable",
        12: "TOS-host-unreachable",
        13: "communication-prohibited",
        14: "host-precedence-violation",
        15: "precedence-cutoff", 
    },
    5: {
        0: "network-redirect",
        1: "host-redirect",
        2: "TOS-network-redirect",
        3: "TOS-host-redirect", 
    },
    11: {
        0: "ttl-zero-during-transit",
        1: "ttl-zero-during-reassembly", 
    },
    12: {
        0: "ip-header-bad",
        1: "required-option-missing", 
    },
    40: {
        0: "bad-spi",
        1: "authentication-failed",
        2: "decompression-failed",
        3: "decryption-failed",
        4: "need-authentification",
        5: "need-authorization", 
    },
    "_reverse": {}
}

for icmp_type, codes in ICMP_CODES.items():
    if icmp_type == "_reverse":
        continue
    for code, description in codes.items():
        ICMP_CODES["_reverse"][description] = (icmp_type, code) # Reverse mapping for lookup


ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    4: "Parameter problem",
    100: "Private Experimentation",
    101: "Private Experimentation",
    128: "Echo Request",
    129: "Echo Reply",
    130: "MLD Query",
    131: "MLD Report",
    132: "MLD Done",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect Message",
    138: "Router Renumbering",
    139: "ICMP Node Information Query",
    140: "ICMP Node Information Response",
    141: "Inverse Neighbor Discovery Solicitation Message",
    142: "Inverse Neighbor Discovery Advertisement Message",
    143: "MLD Report Version 2",
    144: "Home Agent Address Discovery Request Message",
    145: "Home Agent Address Discovery Reply Message",
    146: "Mobile Prefix Solicitation",
    147: "Mobile Prefix Advertisement",
    148: "Certification Path Solicitation",
    149: "Certification Path Advertisement",
    151: "Multicast Router Advertisement",
    152: "Multicast Router Solicitation",
    153: "Multicast Router Termination",
    155: "RPL Control Message",
    200: "Private Experimentation",
    201: "Private Experimentation"
}
ICMPV6_TYPES.update({v: k for k,v in ICMPV6_TYPES.items()}) # Reverse mapping for lookup

ICMPV6_CODES = {
    1: {
        0: "No route to destination",
        1: "Communication with destination administratively prohibited",  # noqa: E501
        2: "Beyond scope of source address",  # noqa: E501
        3: "Address unreachable",
        4: "Port unreachable"
    },
    2: {
        0: "hop limit exceeded in transit",  # noqa: E501
        1: "fragment reassembly time exceeded"
    },
    4: {
        0: "erroneous header field encountered",
        1: "unrecognized Next Header type encountered",
        2: "unrecognized IPv6 option encountered",
        3: "first fragment has incomplete header chain"
    },
    '_reverse': {},
}

for icmp_type, codes in ICMPV6_CODES.items():
    if icmp_type == "_reverse":
        continue
    for code, description in codes.items():
        ICMPV6_CODES["_reverse"][description] = (icmp_type, code) # Reverse mapping for lookup


ICMPV6_ND_OPT = {
    1: "Source Link-Layer Address",
    2: "Target Link-Layer Address",
    3: "Prefix Information",
    4: "Redirected Header",
    5: "MTU",
    6: "NBMA Shortcut Limit Option",  # RFC2491
    7: "Advertisement Interval Option",
    8: "Home Agent Information Option",
    9: "Source Address List",
    10: "Target Address List",
    11: "CGA Option",            # RFC 3971
    12: "RSA Signature Option",  # RFC 3971
    13: "Timestamp Option",      # RFC 3971
    14: "Nonce option",          # RFC 3971
    15: "Trust Anchor Option",   # RFC 3971
    16: "Certificate Option",    # RFC 3971
    17: "IP Address Option",                             # RFC 4068
    18: "New Router Prefix Information Option",          # RFC 4068
    19: "Link-layer Address Option",                     # RFC 4068
    20: "Neighbor Advertisement Acknowledgement Option",
    21: "CARD Request Option",  # RFC 4065/4066/4067
    22: "CARD Reply Option",   # RFC 4065/4066/4067
    23: "MAP Option",          # RFC 4140
    24: "Route Information Option",  # RFC 4191
    25: "Recursive DNS Server Option",
    26: "IPv6 Router Advertisement Flags Option"
}
ICMPV6_ND_OPT.update({v: k for k,v in ICMPV6_ND_OPT.items()}) # Reverse mapping for lookup


NDP_TYPES = {
    0:'RS',
    1:'RA',
    2:'NS',
    3:'NA',
}
NDP_TYPES.update({v: k for k,v in NDP_TYPES.items()}) # Reverse mapping for lookup