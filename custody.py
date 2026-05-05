# core/custody.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from db.queries import get_custody_log, get_all_evidence
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)


def show_custody_log(evidence_id: str = None) -> None:
    """
    Print chain-of-custody log.
    If evidence_id given → show for that item only.
    If None → show all.
    """
    from db.database import fetch_all

    if evidence_id:
        rows_raw = get_custody_log(evidence_id)
    else:
        rows_raw = fetch_all(
            "SELECT * FROM custody_log ORDER BY performed_at ASC"
        )

    if not rows_raw:
        print(f"{Fore.YELLOW}[CUSTODY] No custody records found."
              f"{Style.RESET_ALL}")
        return

    rows = []
    for r in rows_raw:
        rows.append([
            r['id'],
            r['evidence_id'],
            r['action'],
            r['performed_by'],
            r['performed_at'][:19],
            (r['notes'] or "")[:50]
        ])

    headers = ["#", "Evidence ID", "Action",
               "Performed By", "Timestamp", "Notes"]

    print(f"\n{Fore.CYAN}{'─'*80}")
    print(f"  CHAIN OF CUSTODY LOG ({len(rows)} entries)")
    print(f"{'─'*80}{Style.RESET_ALL}")
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
