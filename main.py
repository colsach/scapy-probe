from scapy.all import conf
import signal
import sys
from probing import *
import logging
import argparse
import time
import multiprocessing
import json
# for testing
from config import ETH_IFACE

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scapy Probing Tool CLI")
    parser.add_argument('-s','--scan-type', choices=['ALL', 'PASSIVE', 'ACTIVE'], default='ALL', help='Type of scan to run: ALL, PASSIVE, or ACTIVE')
    parser.add_argument('-i','--iface', type=str, help='Network interface/s to use. For multiple interfaces, separate them with commas (","). If not provided, "lo", "docker*", "virb*" and "br-*" will be excluded from the scan.')
    parser.add_argument('-l','--loop', type=int, default=0, help='Number of times to repeat probing with the same parameters. If set, the tool will log the time taken for each loop, the CPU and memory consumption, active-traffic volume and a fidelity score for the probing.')
    args = parser.parse_args()

    print("Arguments received:")
    print(f"  Scan Type: {args.scan_type}")
    print(f"  Interfaces: {args.iface}")
    print(f"  Loop Count: {args.loop}")

    scan_type = [args.scan_type]
    if args.iface:
        iface_list = [i.strip() for i in args.iface.split(',')]
        iface_manager = CustomIfacesManager(conf=conf, whitelist=iface_list)
    else:
        iface_manager = CustomIfacesManager(conf=conf)

    if args.loop > 0:
        LOOP = True
    else:
        LOOP = False
        args.loop = 1  # Default to 1 loop if not specified

    for l in range(args.loop):
        print(f"\n🔄 Loop {l+1}/{args.loop} started...")

        manager = SharedPacketLogger()
        manager.start()
        data = manager.PacketLogger()
        def save_data(time):
            data.save_to_json()
            manager.shutdown()
            if LOOP:
                with open('resources_log.json', 'w') as f:
                    json.dump(resources_log, f, indent=2)
                automation.save_probe(time)

        def handle_exit(sig, frame):
            print(f"\n📦 Received signal {sig}. Cleaning up...")
            save_data(time.perf_counter()-probe_start)
            sys.exit(0)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        signal.signal(signal.SIGINT, handle_exit)
        signal.signal(signal.SIGTERM, handle_exit)

        if 'ALL' in scan_type:
            if 'PASSIVE' not in scan_type:
                scan_type.append('PASSIVE')
            if 'ACTIVE' not in scan_type:
                scan_type.append('ACTIVE')

        print("\n🚀 Starting Probing...")
        resources_log = []
        processes = []
        probe_start = time.perf_counter()
        
        if 'PASSIVE' in scan_type:
            print("\n🚀 Starting Sniffing...")
            p_passive = multiprocessing.Process(target=passive.passive_probing, args=(iface_manager, data, False), name="Passive")
            p_passive.start()
            processes.append(p_passive)
            time.sleep(2) 
        
        if 'ACTIVE' in scan_type:
            print("\n🚀 Starting Active Probing...")
            active_start = time.perf_counter()
            p_active = multiprocessing.Process(target=active.active_probing, args=(iface_manager, data, scan_type, PORTS,True), name="Active")
            p_active.start()
            processes.append(p_active)

            while LOOP and any(p.is_alive() and p.name == "Active" for p in processes):
                automation.log_resources(processes, resources_log)
                time.sleep(CPU_INTERVAL)
            
            p_active.join()
            active_end = time.perf_counter()
            print(f"[*] Active probing completed in {active_end - active_start:.6f} seconds.")
            if 'PASSIVE' in scan_type:
                print("\n🚀 Terminating Sniffing...")
                p_passive.terminate()
                p_passive.join()
        
        probe_end = time.perf_counter()
        total_time = probe_end - probe_start
        print(f"\n📦 Completed probing in {total_time:.6f}. Cleaning up...")
        save_data(total_time)
        print("\n📦 Cleanup done. Shutting down...")
            


