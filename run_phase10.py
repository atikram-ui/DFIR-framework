"""
run_phase10.py — Phase 10: Correlation Engine
Usage:
    python3 run_phase10.py              # run full correlation
    python3 run_phase10.py --summary    # show summary only
    python3 run_phase10.py --chain <ip> # show chain for one IP
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules"))

from correlation_engine import (correlate_by_ip, print_correlation_summary,
                                 print_attack_chain, ensure_tables)

args = sys.argv[1:]
print("=" * 55)
print("   DFIR Framework - Phase 10: Correlation Engine")
print("=" * 55 + "\n")

if "--summary" in args:
    ensure_tables()
    print_correlation_summary()
elif "--chain" in args:
    idx = args.index("--chain")
    ip  = args[idx + 1] if idx + 1 < len(args) else None
    if ip:
        ensure_tables()
        print_attack_chain(ip)
    else:
        print("[!] Usage: python3 run_phase10.py --chain <ip_address>")
else:
    correlate_by_ip()
