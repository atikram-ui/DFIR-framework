# core/collector.py

import os
import sys
import shutil
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from config import EVIDENCE_DIR
from db.queries import (
    insert_evidence,
    insert_hash,
    log_custody,
    get_all_evidence
)
from colorama import Fore, Style, init

init(autoreset=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def compute_sha256(filepath: str) -> str:
    """Compute SHA256 of a file in chunks (memory safe)."""
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


def detect_file_type(filename: str) -> str:
    """Guess evidence type from file extension."""
    ext = os.path.splitext(filename)[1].lower()
    type_map = {
        ".log":  "log",
        ".txt":  "log",
        ".pcap": "pcap",
        ".cap":  "pcap",
        ".pcapng": "pcap",
        ".img":  "disk",
        ".dd":   "disk",
        ".raw":  "disk",
        ".mem":  "memory",
        ".dmp":  "memory",
        ".vmem": "memory",
        ".zip":  "archive",
        ".tar":  "archive",
        ".gz":   "archive",
    }
    return type_map.get(ext, "unknown")


def get_file_size(filepath: str) -> int:
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0


# ─── Core Collection Function ─────────────────────────────────────────────────

def collect_single_file(
    source_path: str,
    acquired_by: str = "investigator",
    description: str = ""
) -> dict:
    """
    Collect a single file:
    1. Validate it exists
    2. Copy to evidence store
    3. Record metadata in DB
    4. Hash it + store hash
    5. Write custody log entry
    Returns a result dict.
    """
    result = {
        "success": False,
        "evidence_id": None,
        "sha256": None,
        "message": ""
    }

    # ── Step 1: Validate source ───────────────────────────────────────────────
    if not os.path.isfile(source_path):
        result["message"] = f"File not found: {source_path}"
        print(f"{Fore.RED}[COLLECTOR] {result['message']}{Style.RESET_ALL}")
        return result

    filename  = os.path.basename(source_path)
    file_type = detect_file_type(filename)
    file_size = get_file_size(source_path)

    # ── Step 2: Copy to evidence store ────────────────────────────────────────
    dest_path = os.path.join(EVIDENCE_DIR, filename)

    # If file already exists in store, version it
    if os.path.exists(dest_path):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(filename)
        filename  = f"{name}_{ts}{ext}"
        dest_path = os.path.join(EVIDENCE_DIR, filename)

    try:
        shutil.copy2(source_path, dest_path)
        print(f"{Fore.GREEN}[COLLECTOR] Copied → {dest_path}{Style.RESET_ALL}")
    except Exception as e:
        result["message"] = f"Copy failed: {e}"
        print(f"{Fore.RED}[COLLECTOR] {result['message']}{Style.RESET_ALL}")
        return result

    # ── Step 3: Record metadata in DB ─────────────────────────────────────────
    evidence_id = insert_evidence(
        filename    = filename,
        filepath    = dest_path,
        file_type   = file_type,
        file_size   = file_size,
        acquired_by = acquired_by,
        description = description or f"Collected from {source_path}"
    )
    print(f"{Fore.CYAN}[COLLECTOR] Registered as {evidence_id}{Style.RESET_ALL}")

    # ── Step 4: Compute and store SHA256 ──────────────────────────────────────
    sha256 = compute_sha256(dest_path)
    insert_hash(
        evidence_id  = evidence_id,
        sha256       = sha256,
        verified_by  = acquired_by,
        is_valid     = 1,
        notes        = "Initial acquisition hash"
    )
    print(f"{Fore.CYAN}[COLLECTOR] SHA256: {sha256[:32]}...{Style.RESET_ALL}")

    # ── Step 5: Custody log ───────────────────────────────────────────────────
    log_custody(
        evidence_id  = evidence_id,
        action       = "ACQUIRED",
        performed_by = acquired_by,
        notes        = f"Original path: {source_path} | SHA256: {sha256}"
    )
    log_custody(
        evidence_id  = evidence_id,
        action       = "HASHED",
        performed_by = "system",
        notes        = f"SHA256 fingerprint generated at acquisition"
    )

    result.update({
        "success":     True,
        "evidence_id": evidence_id,
        "sha256":      sha256,
        "dest_path":   dest_path,
        "message":     f"Successfully collected {filename}"
    })

    print(f"{Fore.GREEN}[COLLECTOR] ✓ {filename} → {evidence_id}{Style.RESET_ALL}")
    return result


# ─── Collect Multiple Files ────────────────────────────────────────────────────

def collect_multiple_files(
    file_paths: list,
    acquired_by: str = "investigator"
) -> list:
    """Collect a list of files. Returns list of result dicts."""
    results = []
    print(f"\n{Fore.YELLOW}[COLLECTOR] Starting collection of "
          f"{len(file_paths)} file(s)...{Style.RESET_ALL}\n")

    for path in file_paths:
        res = collect_single_file(path, acquired_by)
        results.append(res)
        print()

    success = sum(1 for r in results if r["success"])
    print(f"{Fore.GREEN}[COLLECTOR] Collection complete: "
          f"{success}/{len(file_paths)} succeeded{Style.RESET_ALL}")
    return results


# ─── Auto-collect from data/logs/ and data/pcap/ ──────────────────────────────

def collect_from_default_dirs(acquired_by: str = "investigator") -> list:
    """
    Scan data/logs/ and data/pcap/ and collect everything found.
    This is the default action when called from the menu.
    """
    from config import LOG_DIR, PCAP_DIR

    all_files = []

    for directory in [LOG_DIR, PCAP_DIR]:
        if os.path.isdir(directory):
            for fname in os.listdir(directory):
                fpath = os.path.join(directory, fname)
                if os.path.isfile(fpath):
                    all_files.append(fpath)

    if not all_files:
        print(f"{Fore.YELLOW}[COLLECTOR] No files found in "
              f"data/logs/ or data/pcap/{Style.RESET_ALL}")
        return []

    return collect_multiple_files(all_files, acquired_by)


# ─── Show Collected Evidence Table ────────────────────────────────────────────

def show_evidence_table() -> None:
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

    headers = ["ID", "Filename", "Type", "Size",
               "Acquired By", "Timestamp", "Status"]
    print(f"\n{Fore.CYAN}{'─'*80}")
    print(f"  COLLECTED EVIDENCE ({len(evidence)} items)")
    print(f"{'─'*80}{Style.RESET_ALL}")
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))


# ─── Interactive Menu Entry Point ─────────────────────────────────────────────

def collect_evidence() -> None:
    """Called from main.py menu option [1]."""

    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  EVIDENCE COLLECTION MODULE")
    print(f"{'═'*60}{Style.RESET_ALL}")

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
