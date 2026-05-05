#!/usr/bin/env python3
"""
DFIR Framework — Quick Start Runner
Runs everything in correct order for demo
"""
import os, subprocess, sys, time

BASE = os.path.expanduser("~/dfir_framework")
VENV = os.path.join(BASE, "venv/bin/python")
PY   = VENV if os.path.exists(VENV) else sys.executable

CYAN  = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
RED   = "\033[91m"; BOLD  = "\033[1m";  RESET  = "\033[0m"

def run(cmd, cwd=BASE):
    print(f"  {YELLOW}$ {cmd}{RESET}")
    r = subprocess.run(cmd, shell=True, cwd=cwd)
    if r.returncode != 0:
        print(f"  {RED}[ERROR] Command failed{RESET}")
    else:
        print(f"  {GREEN}[OK]{RESET}")
    time.sleep(0.5)

print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║         DFIR FRAMEWORK — FULL SYSTEM STARTUP                 ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

steps = [
    ("Reset Database",        f"rm -f dfir.db && {PY} database/db_manager.py"),
    ("Seed Demo Data",        f"{PY} seed_demo_data.py"),
    ("Run Attack Simulation", f"{PY} simulate_attack.py"),
    ("Run System Tests",      f"{PY} test_system.py"),
]

for label, cmd in steps[:-1]:  # skip simulation (interactive)
    print(f"\n{BOLD}[{label}]{RESET}")
    run(cmd)

print(f"""
{GREEN}{BOLD}
All modules ready!

To start the dashboard, run:
  cd ~/dfir_framework/dashboard
  python app.py

Then open: http://127.0.0.1:5000
{RESET}

{YELLOW}File locations:{RESET}
  simulate_attack.py  →  ~/dfir_framework/simulate_attack.py
  test_system.py      →  ~/dfir_framework/test_system.py
  viva_prep.py        →  ~/dfir_framework/viva_prep.py
  dashboard           →  ~/dfir_framework/dashboard/app.py
""")
