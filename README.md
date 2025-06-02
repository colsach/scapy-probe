# Network Exploration Tool
Network Exploration Tool is a Python-based utility that autonomously explores networks by combining [passive](#passive-probing) and [active](#active-probing) reconnaissance techniques. It passively sniffs network traffic to gather information and actively probes the network using ARP, ICMP, and TCP SYN scans. Built on the Scapy library, it allows users to analyze protocols, discover devices and services, and perform security testing and research.


## Active Probing
This tool includes the following scans for active discovery:

|Name|Description|
|----|-----------|
|ARP|This scan is used to identify MAC addresses of IPv4 hosts on the same network.|
|NDP|This scan is used to identify MAC addresses of IPv6 hosts on the same network.|
|ICMP|This scan is used to identify IPv4 hosts on the same network and their status.|
|ICMPv6|This scan is used to identify IPv6 hosts on the same network and their status.|
|TCP-SYN|This scan is used to identify open ports on IPv4 and IPv6 hosts on the same network.|



## Passive Probing
The following list presents the protocols sniffed by this tool.

|Name|Description|
|----|-----------|
|Ethernet||
|802.3||
|VLAN||
|ARP||
|NDP||
|IPv4||
|IPv6||
|ICMP||
|ICMPv6||
|TCP||
|UDP||

## TASKS

|Name|To Do|In Progress|In Review|Done|Cancelled|
|----|:---:|:---------:|:-------:|:--:|:-------:|
|Implement passive Ethernet||||X||
|Implement passive 802.3||||X||
|Implement passive VLAN||||X||
|Implement passive ARP||||X||
|Implement passive NDP||||X||
|Implement passive IPv4||||X||
|Implement passive IPv6||||X||
|Implement passive ICMP||||X||
|Implement passive ICMPv6||||X||
|Implement passive TCP||||X||
|Implement passive UDP||||X||
|Implement ARP-SCAN||||X||
|Implement NDP-SCAN||X||||
|Implement ICMP-SCAN||||X||
|Implement ICMPv6-SCAN||X||||
|Implement TCP-SYN-SCAN||||X||
|Implement Data logging|||X||
|Implement Threading| |X| | | |
|Implement Multiprocessing |X| | | | |
|Implement routing graph |X| | | | |
| | | | | | |
