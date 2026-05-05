# analysis/log_analyzer.py

import os
import sys
import re
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from alerts.alert_manager import raise_alert
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

SEP  = "=" * 70
LINE = "-" * 70

# ─────────────────────────────────────────────
#  DETECTION RULES
# ─────────────────────────────────────────────

# Failed login pattern
RE_FAILED   = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
)
# Successful login
RE_SUCCESS  = re.compile(
    r"Accepted password for (\S+) from ([\d.]+) port (\d+)"
)
# Sudo usage
RE_SUDO     = re.compile(
    r"sudo\[.*\].*USER=(\S+).*COMMAND=(.*)"
)
# New user created
RE_USERADD  = re.compile(
    r"useradd\[.*\].*name=(\S+)"
)
# UFW block
RE_UFW      = re.compile(
    r"UFW BLOCK.*SRC=([\d.]+).*DST=([\d.]+).*DPT=(\d+)"
)
# Suspicious commands
SUSPICIOUS_CMDS = [
    "wget", "curl", "nc ", "netcat", "ncat",
    "/bin/bash", "/bin/sh", "chmod +x",
    "base64", "python -c", "perl -e",
    "scp ", "rsync ", ".sh",
    "/tmp/", "crontab", "/etc/crontab",
    "reverse-shell", "payload",
    "cat /etc/passwd", "cat /etc/shadow",
]

BRUTE_THRESHOLD = 5   # failed attempts = brute force


# ─────────────────────────────────────────────
#  PARSER
# ─────────────────────────────────────────────

def parse_log_file(filepath):
    """Read a log file and return list of raw lines."""
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[LOG] File not found: {filepath}{Style.RESET_ALL}")
        return []
    with open(filepath, "r", errors="ignore") as f:
        return f.readlines()


def analyze_auth_log(lines):
    """
    Parse auth.log lines.
    Returns dict with findings.
    """
    failed_logins   = defaultdict(list)   # ip -> [user, ...]
    success_logins  = []
    sudo_events     = []
    new_users       = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Failed login
        m = RE_FAILED.search(line)
        if m:
            user, ip, port = m.group(1), m.group(2), m.group(3)
            failed_logins[ip].append({
                "user": user, "port": port, "line": line
            })
            continue

        # Successful login
        m = RE_SUCCESS.search(line)
        if m:
            user, ip, port = m.group(1), m.group(2), m.group(3)
            success_logins.append({
                "user": user, "ip": ip, "port": port, "line": line
            })
            continue

        # Sudo
        m = RE_SUDO.search(line)
        if m:
            user, cmd = m.group(1), m.group(2).strip()
            sudo_events.append({
                "user": user, "command": cmd, "line": line
            })
            continue

        # New user
        m = RE_USERADD.search(line)
        if m:
            new_users.append({
                "user": m.group(1), "line": line
            })

    return {
        "failed_logins":  dict(failed_logins),
        "success_logins": success_logins,
        "sudo_events":    sudo_events,
        "new_users":      new_users,
    }


def analyze_syslog(lines):
    """
    Parse syslog lines.
    Returns dict with findings.
    """
    ufw_blocks      = []
    suspicious_cmds = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # UFW blocks
        m = RE_UFW.search(line)
        if m:
            src, dst, dpt = m.group(1), m.group(2), m.group(3)
            ufw_blocks.append({
                "src": src, "dst": dst, "dpt": dpt, "line": line
            })
            continue

        # Suspicious commands
        for cmd in SUSPICIOUS_CMDS:
            if cmd.lower() in line.lower():
                suspicious_cmds.append({
                    "keyword": cmd, "line": line
                })
                break

    return {
        "ufw_blocks":      ufw_blocks,
        "suspicious_cmds": suspicious_cmds,
    }


# ─────────────────────────────────────────────
#  ALERT GENERATION
# ─────────────────────────────────────────────

def generate_alerts(auth_findings, sys_findings):
    """
    Evaluate findings and raise alerts.
    Returns list of raised alert summaries.
    """
    raised = []

    # ── Brute Force ──
    for ip, attempts in auth_findings["failed_logins"].items():
        count = len(attempts)
        if count >= BRUTE_THRESHOLD:
            users = list(set(a["user"] for a in attempts))
            raise_alert(
                title         = f"Brute Force SSH — {ip}",
                description   = (
                    f"IP {ip} made {count} failed SSH login attempts.\n"
                    f"Targeted users: {', '.join(users)}"
                ),
                severity      = "CRITICAL" if count >= 10 else "HIGH",
                source_module = "log_analyzer",
                source_ip     = ip,
                raw_data      = f"attempts={count}|users={','.join(users)}",
            )
            raised.append({
                "type": "Brute Force", "ip": ip,
                "detail": f"{count} attempts", "severity": "CRITICAL"
            })
        else:
            # Still record low-count failures
            raise_alert(
                title         = f"Failed Login Attempts — {ip}",
                description   = f"IP {ip} had {count} failed SSH login(s).",
                severity      = "LOW",
                source_module = "log_analyzer",
                source_ip     = ip,
                raw_data      = f"attempts={count}",
            )
            raised.append({
                "type": "Failed Login", "ip": ip,
                "detail": f"{count} attempts", "severity": "LOW"
            })

    # ── Successful Login After Failures ──
    fail_ips = set(auth_findings["failed_logins"].keys())
    for s in auth_findings["success_logins"]:
        ip = s["ip"]
        if ip in fail_ips:
            raise_alert(
                title         = f"Successful Login After Failures — {ip}",
                description   = (
                    f"User '{s['user']}' logged in successfully from {ip}\n"
                    f"after multiple failed attempts — possible brute force success."
                ),
                severity      = "CRITICAL",
                source_module = "log_analyzer",
                source_ip     = ip,
                raw_data      = f"user={s['user']}|port={s['port']}",
            )
            raised.append({
                "type": "Login After BruteForce", "ip": ip,
                "detail": f"user={s['user']}", "severity": "CRITICAL"
            })
        else:
            raise_alert(
                title         = f"Successful SSH Login — {ip}",
                description   = f"User '{s['user']}' logged in from {ip}.",
                severity      = "LOW",
                source_module = "log_analyzer",
                source_ip     = ip,
                raw_data      = f"user={s['user']}|port={s['port']}",
            )

    # ── Sudo / Privilege Escalation ──
    for ev in auth_findings["sudo_events"]:
        severity = "HIGH" if "/bin/bash" in ev["command"] or "/bin/sh" in ev["command"] else "MEDIUM"
        raise_alert(
            title         = f"Privilege Escalation — {ev['user']}",
            description   = (
                f"User '{ev['user']}' ran sudo command:\n"
                f"  {ev['command']}"
            ),
            severity      = severity,
            source_module = "log_analyzer",
            source_ip     = "",
            raw_data      = f"user={ev['user']}|cmd={ev['command'][:80]}",
        )
        raised.append({
            "type": "Privilege Escalation", "ip": "-",
            "detail": ev["user"], "severity": severity
        })

    # ── New User Created ──
    for nu in auth_findings["new_users"]:
        raise_alert(
            title         = f"New User Account Created — {nu['user']}",
            description   = f"A new system user '{nu['user']}' was created.",
            severity      = "HIGH",
            source_module = "log_analyzer",
            source_ip     = "",
            raw_data      = f"user={nu['user']}",
        )
        raised.append({
            "type": "New User", "ip": "-",
            "detail": nu["user"], "severity": "HIGH"
        })

    # ── UFW Blocks (port scan if same IP blocks > 3) ──
    ufw_by_ip = defaultdict(list)
    for b in sys_findings["ufw_blocks"]:
        ufw_by_ip[b["src"]].append(b)

    for ip, blocks in ufw_by_ip.items():
        if len(blocks) >= 3:
            ports = [b["dpt"] for b in blocks]
            raise_alert(
                title         = f"Port Scan Detected — {ip}",
                description   = (
                    f"IP {ip} triggered {len(blocks)} UFW blocks.\n"
                    f"Ports targeted: {', '.join(ports)}"
                ),
                severity      = "HIGH",
                source_module = "log_analyzer",
                source_ip     = ip,
                raw_data      = f"blocks={len(blocks)}|ports={','.join(ports)}",
            )
            raised.append({
                "type": "Port Scan", "ip": ip,
                "detail": f"{len(blocks)} ports", "severity": "HIGH"
            })

    # ── Suspicious Commands ──
    seen_lines = set()
    for sc in sys_findings["suspicious_cmds"]:
        line_key = sc["line"][:60]
        if line_key in seen_lines:
            continue
        seen_lines.add(line_key)

        severity = "CRITICAL" if any(
            k in sc["line"].lower()
            for k in ["nc ", "netcat", "reverse-shell", "/bin/bash", "payload"]
        ) else "HIGH"

        raise_alert(
            title         = f"Suspicious Command — {sc['keyword']}",
            description   = (
                f"Suspicious activity detected in syslog.\n"
                f"Keyword: {sc['keyword']}\n"
                f"Line: {sc['line'][:120]}"
            ),
            severity      = severity,
            source_module = "log_analyzer",
            source_ip     = "",
            raw_data      = f"keyword={sc['keyword']}",
        )
        raised.append({
            "type": "Suspicious Command", "ip": "-",
            "detail": sc["keyword"], "severity": severity
        })

    return raised


# ─────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────

def print_analysis_report(auth_findings, sys_findings, alerts_raised):
    """Print full formatted analysis report to terminal."""

    print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LOG ANALYSIS REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

    # ── Failed Logins ──
    print(f"\n{Fore.YELLOW}[1] FAILED LOGIN ATTEMPTS{Style.RESET_ALL}")
    rows = []
    for ip, attempts in auth_findings["failed_logins"].items():
        count = len(attempts)
        users = list(set(a["user"] for a in attempts))
        flag  = f"{Fore.RED}BRUTE FORCE{Style.RESET_ALL}" if count >= BRUTE_THRESHOLD else "Normal"
        rows.append([ip, count, ", ".join(users), flag])
    if rows:
        print(tabulate(rows,
            headers=["Source IP", "Count", "Users Targeted", "Status"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No failed logins detected.{Style.RESET_ALL}")

    # ── Successful Logins ──
    print(f"\n{Fore.YELLOW}[2] SUCCESSFUL LOGINS{Style.RESET_ALL}")
    rows = []
    fail_ips = set(auth_findings["failed_logins"].keys())
    for s in auth_findings["success_logins"]:
        flag = f"{Fore.RED}AFTER FAILURES{Style.RESET_ALL}" if s["ip"] in fail_ips else "Normal"
        rows.append([s["user"], s["ip"], s["port"], flag])
    if rows:
        print(tabulate(rows,
            headers=["User", "Source IP", "Port", "Note"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No successful logins detected.{Style.RESET_ALL}")

    # ── Sudo / Privilege Escalation ──
    print(f"\n{Fore.YELLOW}[3] PRIVILEGE ESCALATION (sudo){Style.RESET_ALL}")
    rows = []
    for ev in auth_findings["sudo_events"]:
        rows.append([ev["user"], ev["command"][:55]])
    if rows:
        print(tabulate(rows,
            headers=["User", "Command"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No sudo events detected.{Style.RESET_ALL}")

    # ── New Users ──
    print(f"\n{Fore.YELLOW}[4] NEW USER ACCOUNTS CREATED{Style.RESET_ALL}")
    if auth_findings["new_users"]:
        for nu in auth_findings["new_users"]:
            print(f"  {Fore.RED}[!] New user: {nu['user']}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}No new users detected.{Style.RESET_ALL}")

    # ── UFW Blocks ──
    print(f"\n{Fore.YELLOW}[5] FIREWALL BLOCKS (UFW){Style.RESET_ALL}")
    rows = []
    for b in sys_findings["ufw_blocks"]:
        rows.append([b["src"], b["dst"], b["dpt"]])
    if rows:
        print(tabulate(rows,
            headers=["Source IP", "Destination", "Port"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No UFW blocks detected.{Style.RESET_ALL}")

    # ── Suspicious Commands ──
    print(f"\n{Fore.YELLOW}[6] SUSPICIOUS COMMANDS DETECTED{Style.RESET_ALL}")
    seen = set()
    rows = []
    for sc in sys_findings["suspicious_cmds"]:
        key = sc["line"][:60]
        if key in seen:
            continue
        seen.add(key)
        rows.append([sc["keyword"], sc["line"][:60]])
    if rows:
        print(tabulate(rows,
            headers=["Keyword", "Log Line"],
            tablefmt="rounded_outline"))
    else:
        print(f"  {Fore.GREEN}No suspicious commands detected.{Style.RESET_ALL}")

    # ── Alerts Summary ──
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
            a["type"],
            a["ip"],
            a["detail"],
        ])
    print(tabulate(rows,
        headers=["Severity", "Type", "IP", "Detail"],
        tablefmt="rounded_outline"))
    print()


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def run_log_analysis(
    auth_log_path = None,
    syslog_path   = None
):
    """Main function — called from main.py option [3]."""

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if auth_log_path is None:
        auth_log_path = os.path.join(BASE, "sample_logs", "auth.log")
    if syslog_path is None:
        syslog_path = os.path.join(BASE, "sample_logs", "syslog.log")

    print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LOG ANALYSIS MODULE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}[*] Parsing auth log : {auth_log_path}{Style.RESET_ALL}")
    auth_lines    = parse_log_file(auth_log_path)
    auth_findings = analyze_auth_log(auth_lines)

    print(f"{Fore.YELLOW}[*] Parsing syslog   : {syslog_path}{Style.RESET_ALL}")
    sys_lines     = parse_log_file(syslog_path)
    sys_findings  = analyze_syslog(sys_lines)

    print(f"{Fore.YELLOW}[*] Generating alerts...{Style.RESET_ALL}\n")
    alerts_raised = generate_alerts(auth_findings, sys_findings)

    print_analysis_report(auth_findings, sys_findings, alerts_raised)

    print(f"{Fore.GREEN}[LOG] Analysis complete. "
          f"{len(alerts_raised)} alerts raised.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    run_log_analysis()
