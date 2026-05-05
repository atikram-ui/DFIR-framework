# core/collector.py

import os
import sys
import shutil
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from config import EVIDENCE_DIR, LOG_DIR, PCAP_DIR
from db.queries import (
    insert_evidence,
    insert_hash,
    log_custody,
    get_all_evidence
)
from colorama import Fore, Style, init

init(autoreset=True)


def now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    except PermissionError:
        return "PERMISSION_DENIED"


def detect_file_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    type_map = {
        ".log":    "log",
        ".txt":    "log",
        ".pcap":   "pcap",
        ".cap":    "pcap",
        ".pcapng": "pcap",
        ".img":    "disk",
        ".dd":     "disk",
        ".raw":    "disk",
        ".mem":    "memory",
        ".dmp":    "memory",
        ".vmem":   "memory",
        ".zip":    "archive",
        ".tar":    "archive",
        ".gz":     "archive",
    }
    return type_map.get(ext, "unknown")


def get_file_size(filepath):
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0


def collect_single_file(source_path, acquired_by="investigator", description=""):
    result = {
        "success":     False,
        "evidence_id": None,
        "sha256":      None,
        "message":     ""
    }

    if not os.path.isfile(source_path):
        result["message"] = f"File not found: {source_path}"
        print(f"{Fore.RED}[COLLECTOR] {result['message']}{Style.RESET_ALL}")
        return result

    filename  = os.path.basename(source_path)
    file_type = detect_file_type(filename)
    file_size = get_file_size(source_path)

    dest_path = os.path.join(EVIDENCE_DIR, filename)

    if os.path.exists(dest_path):
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(filename)
        filename  = f"{name}_{ts}{ext}"
        dest_path = os.path.join(EVIDENCE_DIR, filename)

    try:
        shutil.copy2(source_path, dest_path)
        print(f"{Fore.GREEN}[COLLECTOR] Copied to {dest_path}{Style.RESET_ALL}")
    except Exception as e:
        result["message"] = f"Copy failed: {e}"
        print(f"{Fore.RED}[COLLECTOR] {result['message']}{Style.RESET_ALL}")
        return result

    evidence_id = insert_evidence(
        filename    = filename,
        filepath    = dest_path,
        file_type   = file_type,
        file_size   = file_size,
        acquired_by = acquired_by,
        description = description or f"Collected from {source_path}"
    )
    print(f"{Fore.CYAN}[COLLECTOR] Registered as {evidence_id}{Style.RESET_ALL}")

    sha256 = compute_sha256(dest_path)
    insert_hash(
        evidence_id = evidence_id,
        sha256      = sha256,
        verified_by = acquired_by,
        is_valid    = 1,
        notes       = "Initial acquisition hash"
    )
    print(f"{Fore.CYAN}[COLLECTOR] SHA256: {sha256[:32]}...{Style.RESET_ALL}")

    log_custody(
        evidence_id  = evidence_id,
        action       = "ACQUIRED",
        performed_by = acquired_by,
        notes        = f"Original: {source_path} | SHA256: {sha256}"
    )
    log_custody(
        evidence_id  = evidence_id,
        action       = "HASHED",
        performed_by = "system",
        notes        = "SHA256 fingerprint generated at acquisition"
    )

    result.update({
        "success":     True,
        "evidence_id": evidence_id,
        "sha256":      sha256,
        "dest_path":   dest_path,
        "message":     f"Successfully collected {filename}"
    })

    print(f"{Fore.GREEN}[COLLECTOR] Done: {filename} -> {evidence_id}{Style.RESET_ALL}")
    return result


def collect_multiple_files(file_paths, acquired_by="investigator"):
    results = []
    print(f"\n{Fore.YELLOW}[COLLECTOR] Collecting {len(file_paths)} file(s)...{Style.RESET_ALL}\n")

    for path in file_paths:
        res = collect_single_file(path, acquired_by)
        results.append(res)
        print()

    success = sum(1 for r in results if r["success"])
    print(f"{Fore.GREEN}[COLLECTOR] Done: {success}/{len(file_paths)} succeeded{Style.RESET_ALL}")
    return results


def collect_from_default_dirs(acquired_by="investigator"):
    all_files = []

    for directory in [LOG_DIR, PCAP_DIR]:
        if os.path.isdir(directory):
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath):
                    all_files.append(fpath)

    if not all_files:
        print(f"{Fore.YELLOW}[COLLECTOR] No files found in data/logs/ or data/pcap/{Style.RESET_ALL}")
        return []

    return collect_multiple_files(all_files, acquired_by)


def show_evidence_table():
    from tabulate import tabulate
    evidence = get_all_evidence()

    if not evidence:
        print(f"{Fore.YELLOW}[COLLECTOR] No evidence collected yet.{Style.RESET_ALL}")
        return

    rows = []
    for e in evidence:
        size_kb = f"{e['file_size'] // 1024} KB" if e['file_size'] else "?"
        rows.append([
            e['evidence_id'],
            e['filename'][:30],
            e['file_type'],
            size_kb,
            e['acquired_by'],
            e['acquired_at'][:19],
            e['status']
        ])

    headers = ["ID", "Filename", "Type", "Size", "Acquired By", "Timestamp", "Status"]
    print(f"\n{Fore.CYAN}{'─'*75}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  COLLECTED EVIDENCE ({len(evidence)} items){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*75}{Style.RESET_ALL}")
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))


def collect_evidence():
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  EVIDENCE COLLECTION MODULE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    print(f"""
{Fore.YELLOW}Options:{Style.RESET_ALL}
  [1] Auto-collect from data/logs/ and data/pcap/
  [2] Collect a specific file
  [3] Show collected evidence
  [0] Back
    """)

    choice = input(f"{Fore.CYAN}collector >> {Style.RESET_ALL}").strip()

    if choice == "1":
        who = input("Acquired by [investigator]: ").strip() or "investigator"
        collect_from_default_dirs(acquired_by=who)
        show_evidence_table()

    elif choice == "2":
        path = input("Enter full file path: ").strip()
        who  = input("Acquired by [investigator]: ").strip() or "investigator"
        desc = input("Description: ").strip()
        collect_single_file(path, acquired_by=who, description=desc)
        show_evidence_table()

    elif choice == "3":
        show_evidence_table()

    elif choice == "0":
        return

    else:
        print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
