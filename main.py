# main.py

import sys
import os
import db
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════╗
║     DFIR Correlation Framework for Cyber Investigation   ║
║     National Forensic Sciences University — NFSU         ║
║     Author : Atikram Das  |  Enrollment: 240103003015    ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

MENU = f"""
{Fore.YELLOW}Select Module:{Style.RESET_ALL}
  [1]  Evidence Collection
  [2]  Integrity Verification
  [3]  Log Analysis
  [4]  Network Analysis
  [5]  IOC Extraction
  [6]  Threat Intelligence Lookup
  [7]  Run Correlation Engine
  [8]  Show Timeline
  [9]  View Alerts
  [10] Launch Dashboard
  [11] Generate Report
  [0]  Exit
"""

def run_module(choice):

    if choice == "1":
        from core.collector import collect_evidence
        collect_evidence()

    elif choice == "2":
        from core.hasher import (
            verify_all_evidence,
            simulate_tamper,
            restore_tampered,
            hash_file
        )
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  INTEGRITY VERIFICATION MODULE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"""
{Fore.YELLOW}Options:{Style.RESET_ALL}
  [1] Verify all evidence
  [2] Verify single evidence item
  [3] Hash any file
  [4] Simulate tamper (demo)
  [5] Restore tampered file (demo cleanup)
  [0] Back
        """)
        sub = input(f"{Fore.CYAN}hasher >> {Style.RESET_ALL}").strip()

        if sub == "1":
            who = input("Verified by [system]: ").strip() or "system"
            verify_all_evidence(performed_by=who)

        elif sub == "2":
            eid = input("Enter Evidence ID (e.g. EVD-001): ").strip()
            who = input("Verified by [system]: ").strip() or "system"
            from core.hasher import verify_single
            result = verify_single(eid, who)
            print(f"\n  Status  : {result['status']}")
            print(f"  Message : {result['message']}")

        elif sub == "3":
            path = input("Enter file path: ").strip()
            hash_file(path)

        elif sub == "4":
            eid = input("Enter Evidence ID to tamper (e.g. EVD-001): ").strip()
            simulate_tamper(eid)

        elif sub == "5":
            eid = input("Enter Evidence ID to restore (e.g. EVD-001): ").strip()
            restore_tampered(eid)

    elif choice == "3":
        from analysis.log_analyzer import run_log_analysis
        run_log_analysis()

    elif choice == "4":
        from analysis.network_analyzer import run_network_analysis
        run_network_analysis()

    elif choice == "5":
        from analysis.ioc_extractor import run_ioc_extraction
        run_ioc_extraction()

    elif choice == "6":
        from intelligence.threat_intel import run_threat_intel
        run_threat_intel()

    elif choice == "7":
        from correlation.engine import run_correlation
        run_correlation()

    elif choice == "8":
        from correlation.timeline import show_timeline
        show_timeline()

    elif choice == "9":
        from alerts.alert_manager import show_alerts
        show_alerts()

    elif choice == "10":
        print(f"{Fore.GREEN}[*] Launching Flask Dashboard"
              f" on http://localhost:5000{Style.RESET_ALL}")
        from dashboard.app import create_app
        app = create_app()
        app.run(host="0.0.0.0", port=5000, debug=False)

    elif choice == "11":
        from core.reporter import generate_report
        generate_report()

    elif choice == "0":
        print(f"{Fore.RED}[!] Exiting DFIR Framework."
              f" Goodbye.{Style.RESET_ALL}")
        sys.exit(0)

    else:
        print(f"{Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")


def main():
    print(BANNER)
    while True:
        print(MENU)
        choice = input(f"{Fore.CYAN}dfir >> {Style.RESET_ALL}").strip()
        print()
        run_module(choice)
        print()
        input(f"{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
        print()

if __name__ == "__main__":
    main()
