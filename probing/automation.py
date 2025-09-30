# python3
import pathlib
import os,datetime,shutil,json,psutil, statistics
import ipaddress
from typing import Iterable, Tuple, Dict, List
from .definitions import *

def log_resources(processes, log_list):
    usage = {"timestamp": datetime.datetime.now().isoformat(), 
             "total_cpu_percent": psutil.cpu_percent(interval=CPU_INTERVAL),
             "ram_percent": psutil.virtual_memory().percent,
             "per_processes": []}
    for proc in processes:
        try:
            p = psutil.Process(proc.pid)
            usage["per_processes"].append({
                "pid": proc.pid,
                "name": proc.name,
                "cpu_percent": p.cpu_percent(interval=CPU_INTERVAL),
                "memory_mb": p.memory_info().rss / (1024 * 1024)  # in MB
            })
        except Exception as e:
            usage["per_processes"].append({
                "pid": proc.pid,
                "name": proc.name,
                "error": str(e)
            })
    log_list.append(usage)

def save_probe(total_time=None):

    timestamp_dir = datetime.datetime.now().strftime("probe_%Y%m%d_%H%M%S")
    os.makedirs(f"logs/{timestamp_dir}", exist_ok=True)
    print(f"Saving logs to logs/{timestamp_dir}...")
    for filename in os.listdir('.'):
        if filename.endswith('.pcapng') or filename.endswith('.json'):
            shutil.move(filename, f"logs/{timestamp_dir}/{filename}")
    fidelity_score(f"logs/{timestamp_dir}", total_time)

def fidelity_score(path:str, total_time:float=None):
    """
    Calculate a fidelity score based on the resources used during probing.
    This is a placeholder function and should be implemented based on specific criteria.
    
    :param path: Path to the log directory
    """
    json_file = pathlib.Path(path) / "inventory.json"
    if not json_file.exists():
        print(f"Inventory JSON file not found at {json_file}. Skipping fidelity score calculation.")
        return

    scores = main(json_file)
    scores.append({"total_time": total_time} if total_time is not None else {"total_time": False})
    output_file = pathlib.Path(path) / "fidelity_score.json"
    with open(output_file, 'w') as f:
        json.dump(scores, f, indent=2)

VLAN_KEYS = {"vlan", "vlan_id", "vlanids", "vlans"}
TCPUDP_KEYS = {"tcp", "udp"}

# ---------------------------------------------------------------------------

def has_vlan(node: dict) -> bool:
    """Return True if *any* VLAN field is non-empty somewhere in this branch."""
    for k, v in node.items():
        kl = k.lower()
        if kl in VLAN_KEYS and v:
            return True
        if isinstance(v, dict) and has_vlan(v):
            return True
    return False


def has_ports(ip_branch: dict, mac_branch: dict) -> bool:
    """True if IP branch or its parent MAC branch names ≥1 transport-layer port."""
    # direct TCP/UDP dicts under the IP
    for proto in TCPUDP_KEYS:
        # print(f"Checking for {proto} in {ip_branch}")
        if proto in ip_branch and ip_branch[proto]:
            return True
    # summary lists (dst_ports / src_ports) sometimes live one level up
    for branch in (ip_branch, mac_branch):
        summ = branch.get("summary", {})
        if summ.get("dst_ports") or summ.get("src_ports"):
            return True
    return False


# ── iterator for the fallback (json.load) case ──────────────────────────────
def iter_targets_loaded(obj):
    """
    Same yield signature as iter_targets_stream but expects a fully
    loaded dict representing the whole packet_log.json.
    """
    # Typical top-level keys are 'active' and 'passive'
    for mode_branch in obj.values():
        if not isinstance(mode_branch, dict) or mode_branch == 'active':
            continue
        for src_mac_branch in mode_branch.values():
            if not isinstance(src_mac_branch, dict):
                continue
            for tgt_mac, tgt_branch in src_mac_branch.items():
                if tgt_mac in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff','summary'] or not isinstance(tgt_branch, dict):
                    continue
                for proto, proto_branch in tgt_branch.items():
                    if not isinstance(proto_branch, dict) or proto == 'ARP':
                        continue
                    for ip_addr, ip_branch in proto_branch.items():
                        if not isinstance(ip_branch, dict):
                            continue
                        vlan_ok = has_vlan(ip_branch) or has_vlan(tgt_branch)
                        ports_ok = has_ports(ip_branch, tgt_branch)
                        ip_addr = ip_addr if _ip_is_real(ip_addr) else False
                        # print(f"Processing target: {tgt_mac}, IP: {ip_addr}, VLAN OK: {vlan_ok}, Ports OK: {ports_ok}")
                        yield tgt_mac, ip_addr, vlan_ok, ports_ok


TargetT = Tuple[str, str, bool, bool]   # (mac, ip, vlan_ok, ports_ok)

def _ip_is_real(ip: str) -> bool:
    """Reject placeholders like 'summary', 'IPv4', 'ARP'."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reduce_to_best(records: Iterable[TargetT]) -> List[TargetT]:
    """
    Return one (mac, ip, vlan_ok, ports_ok) per MAC – the one
    that captures the most attributes (score 0‒4).  Ties are
    broken by:   1) real IP address over placeholder
                 2) first seen.
    """
    best: Dict[str, TargetT] = {}

    for mac, ip, vlan_ok, ports_ok in records:
        score = 2 + int(vlan_ok) + int(ports_ok)   # MAC & IP always counted

        if mac not in best:
            best[mac] = (mac, ip, vlan_ok, ports_ok, score)  # type: ignore
            continue

        _, ip_b, vlan_b, ports_b, score_b = best[mac]

        # Prefer the higher score …
        if score > score_b:
            best[mac] = (mac, ip, vlan_ok, ports_ok, score)  # type: ignore
        # … or a valid IP instead of “summary” / “IPv4” …
        elif score == score_b and not _ip_is_real(ip_b) and _ip_is_real(ip):
            best[mac] = (mac, ip, vlan_ok, ports_ok, score)  # type: ignore

    # strip the score we kept internally
    return [(m, i, v, p) for m, i, v, p, _ in best.values()]


# ── main driver ─────────────────────────────────────────────────────────────
def main(path: pathlib.Path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    iterator = iter_targets_loaded(data)

    scores = []
    reduced = reduce_to_best(iterator)
    output = []
    for mac, ip, vlan_ok, ports_ok in reduced:
        ip_ok = _ip_is_real(ip)
        # print(f"Processing target: {mac}, IP: {ip} -> IP_OK: {ip_ok}, VLAN OK: {vlan_ok}, Ports OK: {ports_ok}")
        score = (1                              # MAC  (always present)
                 + int(ip_ok)         # IP   (present by construction)
                 + int(vlan_ok)
                 + int(ports_ok)) / 4.0
        scores.append(score)
        output.append({
            "mac": mac,
            "ip": ip if ip_ok else None,
            "vlan_ok": vlan_ok,
            "ports_ok": ports_ok,
            "score": score
        })

    if not scores:
        sys.exit("No targets found – verify JSON structure.")
    # print(scores)
    mean = statistics.mean(scores)
    median = statistics.median(scores)
    max_score = max(scores)
    min_score = min(scores)
    print(f"\nAnalysed {len(scores):,} MAC/IP targets in {path.name}")
    print(f"  Mean fidelity  : {mean:.3f}")
    print(f"  Median fidelity: {median:.3f}")
    print(f"  Max fidelity   : {max_score:.1f}")
    print(f"  Min fidelity   : {min_score:.1f}\n")
    
    output.append({
        "summary": {
            "mean_fidelity": mean,
            "median_fidelity": median,
            "max_fidelity": max_score,
            "min_fidelity": min_score
        }
    })
    return output