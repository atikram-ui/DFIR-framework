# alerts/alert_manager.py

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from db.database import fetch_all, fetch_one, execute_query
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLOR = {
    "LOW":      Fore.GREEN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

SEP  = "=" * 70
LINE = "-" * 70


def get_all_alerts(severity=None, status=None, limit=None):
    query  = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    query += " ORDER BY created_at DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    return fetch_all(query, tuple(params))


def get_alert_stats():
    severity_rows = fetch_all(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    )
    status_rows = fetch_all(
        "SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status"
    )
    total = fetch_one("SELECT COUNT(*) as cnt FROM alerts")
    return {
        "total":    total["cnt"] if total else 0,
        "severity": {r["severity"]: r["cnt"] for r in severity_rows},
        "status":   {r["status"]:   r["cnt"] for r in status_rows},
    }


def acknowledge_alert(alert_id):
    existing = fetch_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if not existing:
        print(f"{Fore.RED}[ALERT] Alert {alert_id} not found.{Style.RESET_ALL}")
        return False
    execute_query(
        "UPDATE alerts SET status = 'ACKNOWLEDGED' WHERE alert_id = ?",
        (alert_id,)
    )
    print(f"{Fore.GREEN}[ALERT] {alert_id} marked as ACKNOWLEDGED.{Style.RESET_ALL}")
    return True


def acknowledge_all():
    execute_query(
        "UPDATE alerts SET status = 'ACKNOWLEDGED' WHERE status = 'OPEN'"
    )
    print(f"{Fore.GREEN}[ALERT] All OPEN alerts acknowledged.{Style.RESET_ALL}")


def delete_alert(alert_id):
    execute_query("DELETE FROM alerts WHERE alert_id = ?", (alert_id,))
    print(f"{Fore.YELLOW}[ALERT] {alert_id} deleted.{Style.RESET_ALL}")


def raise_alert(title, description, severity="MEDIUM",
                source_module="manual", source_ip="",
                evidence_id="", raw_data=""):
    from db.queries import insert_alert
    insert_alert(
        title         = title,
        description   = description,
        severity      = severity.upper(),
        source_module = source_module,
        source_ip     = source_ip,
        evidence_id   = evidence_id,
        raw_data      = raw_data,
    )
    color = SEVERITY_COLOR.get(severity.upper(), Fore.WHITE)
    print(f"{color}[ALERT RAISED] [{severity.upper()}] {title}{Style.RESET_ALL}")


def _color_severity(sev):
    color = SEVERITY_COLOR.get(sev, Fore.WHITE)
    return f"{color}{sev}{Style.RESET_ALL}"


def _color_status(st):
    if st == "OPEN":
        return f"{Fore.RED}{st}{Style.RESET_ALL}"
    elif st == "ACKNOWLEDGED":
        return f"{Fore.GREEN}{st}{Style.RESET_ALL}"
    return f"{Fore.YELLOW}{st}{Style.RESET_ALL}"


def print_alert_table(alerts):
    if not alerts:
        print(f"{Fore.YELLOW}  No alerts found.{Style.RESET_ALL}")
        return
    rows = []
    for a in alerts:
        ts = a["created_at"][:16] if a["created_at"] else "N/A"
        rows.append([
            a["alert_id"],
            _color_severity(a["severity"]),
            _color_status(a["status"]),
            a["source_module"][:18],
            a["source_ip"] or "-",
            a["title"][:38],
            ts,
        ])
    headers = ["Alert ID", "Severity", "Status", "Module", "Source IP", "Title", "Timestamp"]
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))


def print_stats(stats):
    print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ALERT STATISTICS  -  Total: {stats['total']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"\n  Severity Breakdown")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt   = stats["severity"].get(sev, 0)
        color = SEVERITY_COLOR.get(sev, Fore.WHITE)
        bar   = "X" * cnt
        print(f"  {color}{sev:<10}{Style.RESET_ALL} {cnt:>4}  {color}{bar}{Style.RESET_ALL}")
    print(f"\n  Status Breakdown")
    for st, cnt in stats["status"].items():
        color = Fore.RED if st == "OPEN" else Fore.GREEN
        print(f"  {color}{st:<16}{Style.RESET_ALL} {cnt}")
    print()


def show_alert_detail(alert_id):
    a = fetch_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if not a:
        print(f"{Fore.RED}[ALERT] Not found: {alert_id}{Style.RESET_ALL}")
        return
    color = SEVERITY_COLOR.get(a["severity"], Fore.WHITE)
    print(f"\n{color}{SEP}{Style.RESET_ALL}")
    print(f"{color}  ALERT DETAIL - {a['alert_id']}{Style.RESET_ALL}")
    print(f"{color}{SEP}{Style.RESET_ALL}")
    print(f"  Title         : {a['title']}")
    print(f"  Severity      : {color}{a['severity']}{Style.RESET_ALL}")
    print(f"  Status        : {_color_status(a['status'])}")
    print(f"  Source Module : {a['source_module']}")
    print(f"  Source IP     : {a['source_ip'] or 'N/A'}")
    print(f"  Evidence ID   : {a['evidence_id'] or 'N/A'}")
    print(f"  Created At    : {a['created_at']}")
    print(f"\n  Description:")
    for line in (a["description"] or "").split("\n"):
        print(f"    {line}")
    if a["raw_data"]:
        print(f"\n  Raw Data:")
        for part in a["raw_data"].split("|"):
            print(f"    {part}")
    print(f"{color}{LINE}{Style.RESET_ALL}\n")


def show_alerts():
    while True:
        print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  ALERT MANAGER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

        stats = get_alert_stats()
        print_stats(stats)

        print(f"""{Fore.YELLOW}Options:{Style.RESET_ALL}
  [1] View ALL alerts
  [2] View CRITICAL alerts
  [3] View HIGH alerts
  [4] View MEDIUM alerts
  [5] View LOW alerts
  [6] View OPEN alerts only
  [7] View ACKNOWLEDGED alerts
  [8] View alert detail (by ID)
  [9] Acknowledge single alert
  [A] Acknowledge ALL open alerts
  [R] Raise manual test alert
  [D] Delete alert by ID
  [0] Back to main menu
""")
        choice = input(f"{Fore.CYAN}alerts >> {Style.RESET_ALL}").strip().upper()

        if choice == "1":
            alerts = get_all_alerts()
            print(f"\n{Fore.CYAN}  ALL ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "2":
            alerts = get_all_alerts(severity="CRITICAL")
            print(f"\n{Fore.MAGENTA}  CRITICAL ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "3":
            alerts = get_all_alerts(severity="HIGH")
            print(f"\n{Fore.RED}  HIGH ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "4":
            alerts = get_all_alerts(severity="MEDIUM")
            print(f"\n{Fore.YELLOW}  MEDIUM ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "5":
            alerts = get_all_alerts(severity="LOW")
            print(f"\n{Fore.GREEN}  LOW ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "6":
            alerts = get_all_alerts(status="OPEN")
            print(f"\n{Fore.RED}  OPEN ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "7":
            alerts = get_all_alerts(status="ACKNOWLEDGED")
            print(f"\n{Fore.GREEN}  ACKNOWLEDGED ALERTS ({len(alerts)}){Style.RESET_ALL}")
            print_alert_table(alerts)

        elif choice == "8":
            aid = input("  Enter Alert ID (e.g. ALT-001): ").strip()
            show_alert_detail(aid)

        elif choice == "9":
            aid = input("  Enter Alert ID to acknowledge: ").strip()
            acknowledge_alert(aid)

        elif choice == "A":
            confirm = input("  Acknowledge ALL open alerts? [y/N]: ").strip().lower()
            if confirm == "y":
                acknowledge_all()

        elif choice == "R":
            print(f"\n{Fore.YELLOW}  Raise a manual test alert{Style.RESET_ALL}")
            title  = input("  Title      : ").strip() or "Test Alert"
            desc   = input("  Description: ").strip() or "Manual test alert"
            sev    = input("  Severity [LOW/MEDIUM/HIGH/CRITICAL]: ").strip() or "MEDIUM"
            src_ip = input("  Source IP  : ").strip()
            raise_alert(
                title         = title,
                description   = desc,
                severity      = sev,
                source_module = "manual",
                source_ip     = src_ip,
            )

        elif choice == "D":
            aid = input("  Enter Alert ID to DELETE: ").strip()
            confirm = input(f"  Delete {aid}? [y/N]: ").strip().lower()
            if confirm == "y":
                delete_alert(aid)

        elif choice == "0":
            break

        else:
            print(f"{Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")

        input(f"\n{Fore.YELLOW}  Press Enter to continue...{Style.RESET_ALL}")


if __name__ == "__main__":
    print(f"\n{Fore.CYAN}[*] Seeding test alerts...{Style.RESET_ALL}\n")

    raise_alert("Brute Force Detected",
                "192.168.1.105 failed SSH login 47 times in 60 seconds.",
                "CRITICAL", "log_analyzer", "192.168.1.105",
                raw_data="attempts=47|window=60s|target=ssh")

    raise_alert("Suspicious Outbound Connection",
                "Host contacted known C2 domain malware-c2.ru on port 4444.",
                "HIGH", "network_analyzer", "10.0.0.55",
                raw_data="domain=malware-c2.ru|port=4444|proto=TCP")

    raise_alert("Port Scan Detected",
                "192.168.1.200 scanned 1024 ports in under 10 seconds.",
                "MEDIUM", "network_analyzer", "192.168.1.200",
                raw_data="ports_scanned=1024|duration=9.8s")

    raise_alert("Large File Exfiltration",
                "Unusual outbound data transfer of 2.3 GB to external IP.",
                "HIGH", "network_analyzer", "45.33.32.156",
                raw_data="bytes=2469606195|direction=outbound")

    raise_alert("New Admin Account Created",
                "User backdoor_admin created outside business hours.",
                "HIGH", "log_analyzer", "192.168.1.101",
                raw_data="user=backdoor_admin|time=02:34:17")

    raise_alert("Repeated Auth Failure",
                "3 failed login attempts from 10.0.0.22.",
                "LOW", "log_analyzer", "10.0.0.22",
                raw_data="attempts=3")

    print(f"\n{Fore.GREEN}[*] Done. Launching alert manager...{Style.RESET_ALL}\n")
    show_alerts()
