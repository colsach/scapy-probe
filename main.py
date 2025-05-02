from scapy.all import *
import signal
import sys
from probing import *
import logging
import threading

data = init_logger()

def handle_exit(sig, frame):
    print(f"\n📦 Received signal {sig}. Cleaning up...")
    packet_logger.save_to_json(data)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


if __name__ == "__main__":
    print("\n🚀 Starting Probing...\n")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # Example interface, replace with your actual interface
    # iface = "enxa0cec88b5c4b"
    # iface = "wlp0s20f3"
    iface = "enxe88088211bed"
    # Call passive probing
    # passive.passive_probing(iface,data,True)
    # Call active probing (to be implemented)
    scan_type = ['active','passive','arp','icmp', 'tcp']
    active.active_probing(iface,scan_type=scan_type,data=data,log=True)
    # Call passive probing (to be implemented)
    # t1 = threading.Thread(target=passive.passive_probing,args=(iface,data,True))
    # t2 = threading.Thread(target=active.active_probing,args=(iface,data,True))
    # t1.start()
    # t2.start()
    # t1.join()
    # t2.join()
    print(f"\n📦 Done. Cleaning up...")
    packet_logger.save_to_json(data)

