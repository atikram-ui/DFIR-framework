# core/hasher.py

import os
import sys
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
from config import EVIDENCE_DIR
from db.queries import (
    get_all_evidence,
    get_hash_by_evidence,
    insert_hash,
    log_custody,
    insert_alert,
    update_evidence_status
)
from db.database import fetch_all, fetch_one
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

BANG = "!" * 60
DASH = "=" * 60
LINE = "-" * 60
LONG = "-" * 80


def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "ERROR:FILE_NOT_FOUND"
    except PermissionError:
        return "ERROR:PERMISSION_DENIED"
    except Exception as e:
        return f"ERROR:{str(e)}"


def verify_single(evidence_id, performed_by="system"):
    ev = fetch_one(
        "SELECT * FROM evidence WHERE evidence_id=?",
        (evidence_id,)
    )
    if not ev:
        return {
            "evidence_id": evidence_id,
            "status":      "ERROR",
            "message":     "Evidence record not found in database"
        }

    filepath = ev["filepath"]

    stored = get_hash_by_evidence(evidence_id)
    if not stored:
        return {
            "evidence_id": evidence_id,
            "status":      "ERROR",
            "message":     "No hash record found"
        }

    stored_sha256 = stored["sha256"]

    if not os.path.isfile(filepath):
        log_custody(
            evidence_id  = evidence_id,
            action       = "VERIFY_FAILED",
            performed_by = performed_by,
            notes        = f"File missing from disk: {filepath}"
        )
        update_evidence_status(evidence_id, "MISSING")
        return {
            "evidence_id": evidence_id,
            "status":      "MISSING",
            "message":     f"File not found on disk: {filepath}"
        }

    current_sha256 = compute_sha256(filepath)

    if current_sha256.startswith("ERROR:"):
        return {
            "evidence_id": evidence_id,
            "status":      "ERROR",
            "message":     current_sha256
        }

    if current_sha256 == stored_sha256:
        insert_hash(
            evidence_id = evidence_id,
            sha256      = current_sha256,
            verified_by = performed_by,
            is_valid    = 1,
            notes       = "Re-verification PASSED"
        )
        log_custody(
            evidence_id  = evidence_id,
            action       = "VERIFIED",
            performed_by = performed_by,
            notes        = f"Hash match confirmed | SHA256: {current_sha256[:20]}..."
        )
        update_evidence_status(evidence_id, "VERIFIED")
        return {
            "evidence_id":  evidence_id,
            "filename":     ev["filename"],
            "status":       "PASS",
            "stored_hash":  stored_sha256,
            "current_hash": current_sha256,
            "message":      "Integrity verified — no tampering detected"
        }

    else:
        insert_hash(
            evidence_id = evidence_id,
            sha256      = current_sha256,
            verified_by = performed_by,
            is_valid    = 0,
            notes       = f"TAMPER DETECTED | Original: {stored_sha256[:20]}..."
        )
        log_custody(
            evidence_id  = evidence_id,
            action       = "TAMPERED",
            performed_by = performed_by,
            notes        = (
                f"INTEGRITY VIOLATION | "
                f"Stored: {stored_sha256[:20]}... | "
                f"Current: {current_sha256[:20]}..."
            )
        )
        update_evidence_status(evidence_id, "COMPROMISED")

        insert_alert(
            title        = f"INTEGRITY VIOLATION — {ev['filename']}",
            description  = (
                f"Evidence file {ev['filename']} ({evidence_id}) has been tampered.\n"
                f"Stored SHA256  : {stored_sha256}\n"
                f"Current SHA256 : {current_sha256}"
            ),
            severity     = "CRITICAL",
            source_module= "integrity_verifier",
            source_ip    = "",
            evidence_id  = evidence_id,
            raw_data     = f"stored={stored_sha256}|current={current_sha256}"
        )

        print(f"\n{Fore.RED}{BANG}")
        print(f"  CRITICAL: TAMPERING DETECTED — {ev['filename']}")
        print(f"  Evidence ID : {evidence_id}")
        print(f"  Stored Hash : {stored_sha256[:40]}...")
        print(f"  Current Hash: {current_sha256[:40]}...")
        print(f"{BANG}{Style.RESET_ALL}\n")

        return {
            "evidence_id":  evidence_id,
            "filename":     ev["filename"],
            "status":       "FAIL",
            "stored_hash":  stored_sha256,
            "current_hash": current_sha256,
            "message":      "TAMPERING DETECTED — evidence integrity compromised"
        }


def verify_all_evidence(performed_by="system"):
    print(f"\n{Fore.CYAN}{DASH}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  INTEGRITY VERIFICATION MODULE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{DASH}{Style.RESET_ALL}\n")

    evidence_list = get_all_evidence()

    if not evidence_list:
        print(f"{Fore.YELLOW}[HASHER] No evidence found. Run Evidence Collection first.{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}[HASHER] Verifying {len(evidence_list)} evidence item(s)...{Style.RESET_ALL}\n")

    results = []
    passed  = 0
    failed  = 0
    errors  = 0

    for ev in evidence_list:
        eid = ev["evidence_id"]
        print(f"  Checking {eid} — {ev['filename'][:35]}...", end=" ", flush=True)

        result = verify_single(eid, performed_by)
        results.append(result)

        if result["status"] == "PASS":
            passed += 1
            print(f"{Fore.GREEN}PASS ✓{Style.RESET_ALL}")
        elif result["status"] == "FAIL":
            failed += 1
            print(f"{Fore.RED}FAIL ✗ — TAMPERED{Style.RESET_ALL}")
        else:
            errors += 1
            print(f"{Fore.YELLOW}ERROR — {result['message']}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{LINE}{Style.RESET_ALL}")
    print(f"  Verification Summary")
    print(f"{Fore.CYAN}{LINE}{Style.RESET_ALL}")
    print(f"  Total Checked : {len(results)}")
    print(f"  {Fore.GREEN}Passed        : {passed}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Failed        : {failed}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Errors        : {errors}{Style.RESET_ALL}")

    if failed > 0:
        print(f"\n{Fore.RED}  [!] CRITICAL ALERTS RAISED FOR {failed} TAMPERED FILE(S){Style.RESET_ALL}")

    show_integrity_report(results)
    return results


def show_integrity_report(results=None):
    if results is None:
        evidence_list = get_all_evidence()
        results = []
        for ev in evidence_list:
            stored = get_hash_by_evidence(ev["evidence_id"])
            results.append({
                "evidence_id":  ev["evidence_id"],
                "filename":     ev["filename"],
                "status":       ev["status"],
                "stored_hash":  stored["sha256"] if stored else "N/A",
                "current_hash": "N/A",
                "message":      ev["status"]
            })

    rows = []
    for r in results:
        if r["status"] == "PASS":
            status_str = "PASS"
        elif r["status"] == "FAIL":
            status_str = "FAIL - TAMPERED"
        else:
            status_str = r["status"]

        stored  = r.get("stored_hash",  "N/A")
        current = r.get("current_hash", "N/A")

        rows.append([
            r.get("evidence_id", "?"),
            r.get("filename", "?")[:25],
            status_str,
            stored[:22]  + "..." if len(stored)  > 22 else stored,
            current[:22] + "..." if len(current) > 22 else current,
        ])

    headers = ["Evidence ID", "Filename", "Status", "Stored SHA256", "Current SHA256"]
    print(f"\n{Fore.CYAN}{LONG}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  INTEGRITY REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{LONG}{Style.RESET_ALL}")
    print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))


def hash_file(filepath):
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[HASHER] File not found: {filepath}{Style.RESET_ALL}")
        return None
    h = compute_sha256(filepath)
    print(f"{Fore.CYAN}[HASHER] SHA256({os.path.basename(filepath)}):{Style.RESET_ALL}")
    print(f"  {h}")
    return h


def simulate_tamper(evidence_id):
    ev = fetch_one(
        "SELECT * FROM evidence WHERE evidence_id=?",
        (evidence_id,)
    )
    if not ev:
        print(f"{Fore.RED}[TAMPER-SIM] Evidence {evidence_id} not found.{Style.RESET_ALL}")
        return

    filepath = ev["filepath"]
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[TAMPER-SIM] File not on disk: {filepath}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.YELLOW}[TAMPER-SIM] Simulating tampering on {ev['filename']}...{Style.RESET_ALL}")

    with open(filepath, "ab") as f:
        f.write(b"\x00")

    print(f"{Fore.RED}[TAMPER-SIM] File modified on disk.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[TAMPER-SIM] Running verification...{Style.RESET_ALL}\n")

    result = verify_single(evidence_id, performed_by="tamper_test")

    if result["status"] == "FAIL":
        print(f"{Fore.GREEN}[TAMPER-SIM] Detection SUCCESSFUL — tampering caught!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[TAMPER-SIM] Detection FAILED — review logic.{Style.RESET_ALL}")

    return result


def restore_tampered(evidence_id):
    ev = fetch_one(
        "SELECT * FROM evidence WHERE evidence_id=?",
        (evidence_id,)
    )
    if not ev:
        print(f"{Fore.RED}[RESTORE] Evidence not found.{Style.RESET_ALL}")
        return

    filepath = ev["filepath"]
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[RESTORE] File not on disk.{Style.RESET_ALL}")
        return

    with open(filepath, "rb") as f:
        content = f.read()
    with open(filepath, "wb") as f:
        f.write(content[:-1])

    print(f"{Fore.GREEN}[RESTORE] File restored: {ev['filename']}{Style.RESET_ALL}")

    update_evidence_status(evidence_id, "ACQUIRED")

    new_hash = compute_sha256(filepath)
    insert_hash(
        evidence_id = evidence_id,
        sha256      = new_hash,
        verified_by = "restore_system",
        is_valid    = 1,
        notes       = "Hash restored after tamper simulation"
    )
    log_custody(
        evidence_id  = evidence_id,
        action       = "RESTORED",
        performed_by = "restore_system",
        notes        = "File restored after demo tamper simulation"
    )
    print(f"{Fore.GREEN}[RESTORE] New hash recorded: {new_hash[:30]}...{Style.RESET_ALL}")
