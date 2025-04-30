from scapy.all import *
from collections import defaultdict
from pprint import pprint
from enum import Enum 
import json
import signal
import sys
from probing import *


def handle_exit(sig, frame):
    print(f"\n📦 Received signal {sig}. Cleaning up...")
    save_log()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

log_data = defaultdict(lambda: defaultdict(dict))
def save_log():
    # Convert sets to lists for JSON compatibility
    export = json.loads(json.dumps(log_data, default=lambda o: list(o) if isinstance(o, set) else o))
    with open("sniff_log.json", "w") as f:
        json.dump(export, f, indent=2)



def passive_probing(iface):
    """
    Passive Probing: Sniffing packets to gather information.
    """
    
    print(f"\n[*] Passive Probing: Sniffing packets on interface {iface}...\n")
    mac = get_if_hwaddr(iface)
    # Ignore packets sent by this device
    print(f"Ignoring packets sent by this device: {mac}\n")
    sniff(iface=iface, prn=lambda pkt: passive_handle(pkt,mac))


data = init_logger()

def handle_exit(sig, frame):
    print(f"\n📦 Received signal {sig}. Cleaning up...")
    packet_logger.save_to_json(data)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


if __name__ == "__main__":
    print("\n🚀 Starting Probing...\n")
    
    # Example interface, replace with your actual interface
    iface = "enxa0cec88b5c4b"
    # iface = "wlp0s20f3"
    # Call passive probing
    # passive.passive_probing(iface,data,True)
    # Call active probing (to be implemented)
    scan_type = ['active','passive','arp','icmp', 'tcp']
    active.active_probing(iface,scan_type=scan_type,data=data,log=True)

