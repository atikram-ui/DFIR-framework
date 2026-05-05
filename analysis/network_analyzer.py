# analysis/network_analyzer.py

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from alerts.alert_manager import raise_alert
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

SEP  = "=" * 70
LINE = "-" * 70

# ─────────────────────────────────────────────
#  THRESHOLDS
# ─────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 5     # unique ports from same IP = scan
BRUTE_FORCE_THRESHOLD = 10    # TCP SYN to same port = brute force
EXFIL_BYTES_THRESHOLD = 5000  # bytes to external IP = suspicious
C2_PORTS = {4444, 1337, 31337, 6666, 9999, 8888, 2222}
SUSPICIOUS_DOMAINS = [
    "malware", "c2", "payload", "evil",
    "rat", "botnet", "shell", "hack",
    "exploit", ".ru", ".tk", ".xyz",
]

# ─────────────────────────────────────────────
#  PCAP LOADER
# ─────────────────────────────────────────────

def load_pcap(filepath):
    try:
        from scapy.all import rdpcap
        if not os.path.isfile(filepath):
            print(f"{Fore.RED}[NET] PCAP not found: {filepath}{Style.RESET_ALL}")
            return []
        pkts = rdpcap(filepath)
        print(f"{Fore.GREEN}[NET] Loaded {len(pkts)} packets "
              f"from {filepath}{Style.RESET_ALL}")
        return pkts
    except Exception as e:
        print(f"{Fore.RED}[NET] Error loading PCAP: {e}{Style.RESET_ALL}")
        return []


# ─────────────────────────────────────────────
#  ANALYZERS
# ─────────────────────────────────────────────

def detect_port_scan(packets):
    """Detect port scanning — many unique ports from same IP."""
    from scapy.all import IP, TCP
    src_ports = defaultdict(set)   # src_ip -> set of dst_ports
    src_dst   = defaultdict(set)   # src_ip -> set of dst_ips

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip  = pkt[IP]
            tcp = pkt[TCP]
            if tcp.flags == 2:   # SYN only
                src_ports[ip.src].add(tcp.dport)
                src_dst[ip.src].add(ip.dst)

    results = []
    for src_ip, ports in src_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            results.append({
                "src_ip":    src_ip,
                "dst_ips":   list(src_dst[src_ip]),
                "ports":     sorted(ports),
                "count":     len(ports),
            })
    return results


def detect_brute_force(packets):
    """Detect brute force — many SYN to same port from same IP."""
    from scapy.all import IP, TCP
    syn_count = defaultdict(int)   # (src, dst, dport) -> count

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip  = pkt[IP]
            tcp = pkt[TCP]
            if tcp.flags == 2:  # SYN
                key = (ip.src, ip.dst, tcp.dport)
                syn_count[key] += 1

    results = []
    for (src, dst, dport), count in syn_count.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            results.append({
                "src_ip":  src,
                "dst_ip":  dst,
                "port":    dport,
                "count":   count,
            })
    return results


def detect_suspicious_dns(packets):
    """Detect DNS queries to suspicious domains."""
    from scapy.all import IP, DNS, DNSQR
    results = []
    seen = set()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                src   = pkt[IP].src if pkt.haslayer(IP) else "?"

                if qname in seen:
                    continue
                seen.add(qname)

                is_suspicious = any(
                    kw in qname.lower()
                    for kw in SUSPICIOUS_DOMAINS
                )
                results.append({
                    "src_ip":       src,
                    "domain":       qname,
                    "suspicious":   is_suspicious,
                })
            except Exception:
                continue
    return results


def detect_c2_connections(packets):
    """Detect connections to known C2 ports."""
    from scapy.all import IP, TCP
    results = []
    seen = set()

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip  = pkt[IP]
            tcp = pkt[TCP]
            key = (ip.src, ip.dst, tcp.dport)
            if key in seen:
                continue

            if tcp.dport in C2_PORTS or tcp.sport in C2_PORTS:
                seen.add(key)
                port = tcp.dport if tcp.dport in C2_PORTS else tcp.sport
                results.append({
                    "src_ip":  ip.src,
                    "dst_ip":  ip.dst,
                    "port":    port,
                    "flags":   str(tcp.flags),
                })
    return results


def detect_data_exfiltration(packets):
    """Detect large outbound data transfers."""
    from scapy.all import IP, TCP, Raw
    bytes_sent = defaultdict(int)   # dst_ip -> bytes

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(Raw):
            ip = pkt[IP]
            bytes_sent[ip.dst] += len(pkt[Raw].load)

    results = []
    for dst_ip, total_bytes in bytes_sent.items():
        if total_bytes >= EXFIL_BYTES_THRESHOLD:
            results.append({
                "dst_ip":      dst_ip,
                "total_bytes": total_bytes,
                "kb":          round(total_bytes / 1024, 2),
            })
    return sorted(results, key=lambda x: x["total_bytes"], reverse=True)


def get_connection_summary(packets):
    """Build a summary of all unique IP connections."""
    from scapy.all import IP, TCP, UDP
    conns = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})

    for pkt in packets:
        if pkt.haslayer(IP):
            ip  = pkt[IP]
            key = (ip.src, ip.dst)
            conns[key]["packets"] += 1
            conns[key]["bytes"]   += len(pkt)
            if pkt.haslayer(TCP):
                conns[key]["ports"].add(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                conns[key]["ports"].add(pkt[UDP].dport)

    results = []
    for (src, dst), info in conns.items():
        results.append({
            "src_ip":  src,
            "dst_ip":  dst,
            "packets": info["packets"],
            "bytes":   info["bytes"],
            "ports":   sorted(info["ports"])[:5],
        })
    return sorted(results, key=lambda x: x["bytes"], reverse=True)


# ─────────────────────────────────────────────
#  ALERT GENERATION
# ─────────────────────────────────────────────

def generate_network_alerts(findings):
    raised = []

    # Port Scans
    for ps in findings["port_scans"]:
        raise_alert(
            title         = f"Port Scan — {ps['src_ip']}",
            description   = (
                f"IP {ps['src_ip']} scanned {ps['count']} ports.\n"
                f"Ports: {ps['ports'][:10]}"
            ),
            severity      = "HIGH",
            source_module = "network_analyzer",
            source_ip     = ps["src_ip"],
            raw_data      = f"ports={ps['count']}|targets={','.join(ps['dst_ips'])}",
        )
        raised.append({"type": "Port Scan", "ip": ps["src_ip"],
                        "detail": f"{ps['count']} ports", "severity": "HIGH"})

    # Brute Force
    for bf in findings["brute_force"]:
        sev = "CRITICAL" if bf["port"] == 22 else "HIGH"
        raise_alert(
            title         = f"Network Brute Force — {bf['src_ip']}:{bf['port']}",
            description   = (
                f"IP {bf['src_ip']} sent {bf['count']} SYN packets\n"
                f"to {bf['dst_ip']}:{bf['port']}"
            ),
            severity      = sev,
            source_module = "network_analyzer",
            source_ip     = bf["src_ip"],
            raw_data      = f"syn_count={bf['count']}|port={bf['port']}",
        )
        raised.append({"type": "Brute Force", "ip": bf["src_ip"],
                        "detail": f"port={bf['port']} x{bf['count']}",
                        "severity": sev})

    # Suspicious DNS
    for dns in findings["suspicious_dns"]:
        if dns["suspicious"]:
            raise_alert(
                title         = f"Suspicious DNS Query — {dns['domain']}",
                description   = (
                    f"Host {dns['src_ip']} queried suspicious domain:\n"
                    f"  {dns['domain']}"
                ),
                severity      = "HIGH",
                source_module = "network_analyzer",
                source_ip     = dns["src_ip"],
                raw_data      = f"domain={dns['domain']}",
            )
            raised.append({"type": "Suspicious DNS", "ip": dns["src_ip"],
                            "detail": dns["domain"], "severity": "HIGH"})

    # C2 Connections
    for c2 in findings["c2_connections"]:
        raise_alert(
            title         = f"C2 Connection — {c2['dst_ip']}:{c2['port']}",
            description   = (
                f"Host {c2['src_ip']} connected to {c2['dst_ip']}\n"
                f"on suspicious port {c2['port']} (known C2 port)."
            ),
            severity      = "CRITICAL",
            source_module = "network_analyzer",
            source_ip     = c2["src_ip"],
            raw_data      = f"dst={c2['dst_ip']}|port={c2['port']}",
        )
        raised.append({"type": "C2 Connection", "ip": c2["src_ip"],
                        "detail": f"{c2['dst_ip']}:{c2['port']}",
                        "severity": "CRITICAL"})

    # Data Exfiltration
    for ex in findings["exfiltration"]:
        raise_alert(
            title         = f"Data Exfiltration — {ex['dst_ip']}",
            description   = (
                f"Large outbound transfer detected.\n"
                f"Destination: {ex['dst_ip']}\n"
                f"Data sent: {ex['kb']} KB"
            ),
            severity      = "CRITICAL",
            source_module = "network_analyzer",
            source_ip     = "",
            raw_data      = f"dst={ex['dst_ip']}|bytes={ex['total_bytes']}",
        )
        raised.append({"type": "Exfiltration", "ip": ex["dst_ip"],
                        "detail": f"{ex['kb']} KB", "severity": "CRITICAL"})

    return raised


# ─────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────

def print_network_report(findings, alerts_raised):
    print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  NETWORK ANALYSIS REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

    # Connection Summary
    print(f"\n{Fore.YELLOW}[1] TOP CONNECTIONS{Style.RESET_ALL}")
    rows = []
    for c in findings["connections"][:8]:
        rows.append([
            c["src_ip"], c["dst_ip"],
            c["packets"], c["bytes"],
            str(c["ports"][:4]),
        ])
    print(tabulate(rows,
        headers=["Source IP", "Dest IP", "Packets", "Bytes", "Ports"],
        tablefmt="rounded_outline"))

    # Port Scans
    print(f"\n{Fore.YELLOW}[2] PORT SCANS DETECTED{Style.RESET_ALL}")
    if findings["port_scans"]:
        rows = []
        for ps in findings["port_scans"]:
            rows.append([
                ps["src_ip"],
                ps["count"],
                str(ps["ports"][:8]),
            ])
        print(tabulate(rows,
            headers=["Source IP", "Ports Scanned", "Port List"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No port scans detected.{Style.RESET_ALL}")

    # Brute Force
    print(f"\n{Fore.YELLOW}[3] BRUTE FORCE CONNECTIONS{Style.RESET_ALL}")
    if findings["brute_force"]:
        rows = []
        for bf in findings["brute_force"]:
            rows.append([bf["src_ip"], bf["dst_ip"],
                         bf["port"], bf["count"]])
        print(tabulate(rows,
            headers=["Source IP", "Target IP", "Port", "SYN Count"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No brute force detected.{Style.RESET_ALL}")

    # DNS
    print(f"\n{Fore.YELLOW}[4] DNS QUERIES{Style.RESET_ALL}")
    if findings["suspicious_dns"]:
        rows = []
        for d in findings["suspicious_dns"]:
            flag = (f"{Fore.RED}SUSPICIOUS{Style.RESET_ALL}"
                    if d["suspicious"] else
                    f"{Fore.GREEN}Normal{Style.RESET_ALL}")
            rows.append([d["src_ip"], d["domain"], flag])
        print(tabulate(rows,
            headers=["Source IP", "Domain", "Status"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No DNS queries detected.{Style.RESET_ALL}")

    # C2
    print(f"\n{Fore.YELLOW}[5] C2 CONNECTIONS{Style.RESET_ALL}")
    if findings["c2_connections"]:
        rows = []
        for c2 in findings["c2_connections"]:
            rows.append([c2["src_ip"], c2["dst_ip"],
                         c2["port"], c2["flags"]])
        print(tabulate(rows,
            headers=["Source IP", "C2 IP", "Port", "Flags"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No C2 connections detected.{Style.RESET_ALL}")

    # Exfiltration
    print(f"\n{Fore.YELLOW}[6] DATA EXFILTRATION{Style.RESET_ALL}")
    if findings["exfiltration"]:
        rows = []
        for ex in findings["exfiltration"]:
            rows.append([ex["dst_ip"], ex["total_bytes"], ex["kb"]])
        print(tabulate(rows,
            headers=["Destination IP", "Bytes", "KB"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No exfiltration detected.{Style.RESET_ALL}")

    # Alerts Summary
    print(f"\n{Fore.CYAN}{LINE}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ALERTS RAISED: {len(alerts_raised)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{LINE}{Style.RESET_ALL}")
    rows = []
    for a in alerts_raised:
        color = {
            "CRITICAL": Fore.MAGENTA,
            "HIGH":     Fore.RED,
            "MEDIUM":   Fore.YELLOW,
            "LOW":      Fore.GREEN,
        }.get(a["severity"], Fore.WHITE)
        rows.append([
            f"{color}{a['severity']}{Style.RESET_ALL}",
            a["type"], a["ip"], a["detail"],
        ])
    print(tabulate(rows,
        headers=["Severity", "Type", "IP", "Detail"],
        tablefmt="rounded_outline"))
    print()


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def run_network_analysis(pcap_path=None):
    """Main function — called from main.py option [4]."""

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if pcap_path is None:
        pcap_path = os.path.join(BASE, "sample_logs", "network.pcap")

    print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  NETWORK ANALYSIS MODULE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}\n")

    packets = load_pcap(pcap_path)
    if not packets:
        return

    print(f"{Fore.YELLOW}[*] Running detections...{Style.RESET_ALL}\n")

    findings = {
        "port_scans":    detect_port_scan(packets),
        "brute_force":   detect_brute_force(packets),
        "suspicious_dns": detect_suspicious_dns(packets),
        "c2_connections": detect_c2_connections(packets),
        "exfiltration":  detect_data_exfiltration(packets),
        "connections":   get_connection_summary(packets),
    }

    print(f"  Port Scans    : {len(findings['port_scans'])}")
    print(f"  Brute Force   : {len(findings['brute_force'])}")
    print(f"  Suspicious DNS: {len(findings['suspicious_dns'])}")
    print(f"  C2 Connections: {len(findings['c2_connections'])}")
    print(f"  Exfiltration  : {len(findings['exfiltration'])}")

    print(f"\n{Fore.YELLOW}[*] Generating alerts...{Style.RESET_ALL}\n")
    alerts_raised = generate_network_alerts(findings)

    print_network_report(findings, alerts_raised)

    print(f"{Fore.GREEN}[NET] Analysis complete. "
          f"{len(alerts_raised)} alerts raised.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    run_network_analysis()
