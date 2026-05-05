"""
run_phase11.py - Phase 11: Timeline Reconstruction
Usage:
    python3 run_phase11.py                        # build + print full timeline
    python3 run_phase11.py --ip 192.168.1.100     # filter by IP
    python3 run_phase11.py --severity CRITICAL    # filter by severity
    python3 run_phase11.py --export               # export to JSON
    python3 run_phase11.py --stats                # stats only
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules"))

from timeline import (build_timeline, print_timeline,
                      print_timeline_stats, export_timeline_json,
                      ensure_timeline_table)

args = sys.argv[1:]

print("=" * 55)
print("   DFIR Framework - Phase 11: Timeline Reconstruction")
print("=" * 55 + "\n")

if "--stats" in args:
    ensure_timeline_table()
    print_timeline_stats()

elif "--export" in args:
    ensure_timeline_table()
    export_timeline_json()

elif "--ip" in args:
    idx = args.index("--ip")
    ip  = args[idx + 1] if idx + 1 < len(args) else None
    ensure_timeline_table()
    print_timeline(ip_filter=ip)

elif "--severity" in args:
    idx = args.index("--severity")
    sev = args[idx + 1] if idx + 1 < len(args) else None
    ensure_timeline_table()
    print_timeline(severity_filter=sev)

else:
    build_timeline()

