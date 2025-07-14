from scapy.all import conf
import signal
import sys
from probing import *
import logging
import threading
import time
import multiprocessing

# for testing
from config import ETH_IFACE

if __name__ == "__main__":
    scan_type = ['ALL']
    manager = SharedPacketLogger()
    manager.start()
    data = manager.PacketLogger()
    def handle_exit(sig, frame):
        print(f"\n📦 Received signal {sig}. Cleaning up...")
        data.save_to_json()
        manager.shutdown()
        sys.exit(0)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # iface_manager = CustomIfacesManager(conf=conf, whitelist=ETH_IFACE)
    iface_manager = CustomIfacesManager(conf=conf)
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    if 'ALL' in scan_type:
        scan_type.extend(['PASSIVE', 'ACTIVE'])

    print("\n🚀 Starting Probing...")
    probe_start = time.perf_counter()
    if 'PASSIVE' in scan_type:
        print("\n🚀 Starting Sniffing...")
        p_passive = multiprocessing.Process(target=passive.passive_probing, args=(iface_manager, data, False))
        p_passive.start()
        time.sleep(2) 
    
    if 'ACTIVE' in scan_type:
        print("\n🚀 Starting Active Probing...")
        active_start = time.perf_counter()
        p_active = multiprocessing.Process(target=active.active_probing, args=(iface_manager, data, scan_type, PORTS,True))
        p_active.start()
        p_active.join()
        active_end = time.perf_counter()
        print(f"[*] Active probing completed in {active_end - active_start:.6f} seconds.")
        if 'PASSIVE' in scan_type:
            print("\n🚀 Terminating Sniffing...")
            p_passive.terminate()
            p_passive.join()
    
    probe_end = time.perf_counter()
    print(f"\n📦 Completed probing in {probe_end-probe_start:.6f}. Cleaning up...")
    data.save_to_json()
    manager.shutdown()
    print("\n📦 Cleanup done. Shutting down...")