from scapy.all import conf
import signal
import sys
from probing import *
import logging
import threading
import time

# for testting
from config import ETH_IFACE

data = PacketLogger()
stop_event = threading.Event()
def handle_exit(sig, frame):
    print(f"\n📦 Received signal {sig}. Cleaning up...")
    # packet_logger.save_to_json(data)
    data.save_to_json()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


if __name__ == "__main__":
    print("\n🚀 Starting Probing...\n")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # scan_type = ['ALL']
    scan_type = ['ARP']
    # Example interface, replace with your actual interface
    # iface = ETH_IFACE
    # Call passive probing
    blacklist = ['enx94e6ba6a3eb8', 'lo', 'docker*','virbr*','br-*']
    iface = CustomIfaces(conf,blacklist=blacklist)
    # passive.passive_probing(iface,stop_event,data,True)
    t = threading.Thread(target=passive.passive_probing,args=(iface,stop_event,data,False))
    t.start()
    time.sleep(5)
    print("\n[*] Stopping sniffing...")
    stop_event.set()
    t.join()
    # Call active probing (to be implemented)
    active.active_probing(iface,scan_type=scan_type,data=data,log=True)
    # Call passive probing (to be implemented)
    # t1 = threading.Thread(target=passive.passive_probing,args=(iface,data,True))
    # t2 = threading.Thread(target=active.active_probing,args=(iface,data,True))
    # t1.start()
    # t2.start()
    # t1.join()
    # t2.join()
    print(f"\n📦 Done. Cleaning up...")
    # packet_logger.save_to_json(data)
    data.save_to_json()

