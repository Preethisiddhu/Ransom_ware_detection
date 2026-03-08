"""
Simulate ransomware-like operations in a SAFE sandbox folder.
Generates labeled training data WITHOUT real malware.

Usage:
  python -m scripts.simulate_ransomware --type mass_encrypt --count 100
  python -m scripts.simulate_ransomware --type mass_delete  --count 80
  python -m scripts.simulate_ransomware --type rename_burst --count 60
  python -m scripts.simulate_ransomware --type all
"""

import os
import sys
import time
import random
import string
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import SANDBOX, API_BASE

import requests


def _rname(ext=".txt"):
    return "".join(random.choices(string.ascii_lowercase, k=8)) + ext


def _post_label(label: int, session: str):
    try:
        requests.post(f"{API_BASE}/label-session", json={
            "session_id": session, "label": label
        }, timeout=3)
    except Exception:
        pass


def simulate_mass_encrypt(count: int = 100, delay: float = 0.03):
    """
    Step 1: Create normal-looking files
    Step 2: Rename them to .locked extension (simulates encryption)
    Step 3: Delete originals
    """
    session = f"ransom_encrypt_{int(time.time())}"
    print(f"\n[sim] ══ MASS ENCRYPT SIMULATION ══")
    print(f"[sim] count={count}  session={session}")
    os.makedirs(SANDBOX, exist_ok=True)

    # Step 1: create
    files = []
    print(f"[sim] Step 1: Creating {count} files...")
    for i in range(count):
        path = os.path.join(SANDBOX, _rname(".docx"))
        with open(path, "wb") as f:
            f.write(os.urandom(4096 + random.randint(0, 4096)))
        files.append(path)
        if i % 10 == 0:
            print(f"  created {i+1}/{count}")
        time.sleep(delay)

    # Step 2: rename to encrypted ext
    renamed = []
    print(f"[sim] Step 2: Renaming to .locked ...")
    for path in files:
        new = path + ".locked"
        try:
            os.rename(path, new)
            renamed.append(new)
        except Exception:
            pass
        time.sleep(delay)

    # Step 3: delete
    print(f"[sim] Step 3: Deleting encrypted files ...")
    for path in renamed:
        try:
            os.remove(path)
        except Exception:
            pass
        time.sleep(delay * 0.5)

    _post_label(1, session)
    print(f"[sim] ✅ Mass encrypt done. {count} files. Label=1 posted.")


def simulate_mass_delete(count: int = 80, delay: float = 0.04):
    """Creates files then rapidly deletes them (shadow volume delete simulation)"""
    session = f"ransom_delete_{int(time.time())}"
    print(f"\n[sim] ══ MASS DELETE SIMULATION ══")
    print(f"[sim] count={count}  session={session}")
    os.makedirs(SANDBOX, exist_ok=True)

    files = []
    print(f"[sim] Creating {count} files...")
    for i in range(count):
        path = os.path.join(SANDBOX, _rname(".txt"))
        with open(path, "w") as f:
            f.write("important document content\n" * 50)
        files.append(path)

    time.sleep(1.5)

    print(f"[sim] Deleting all {count} files rapidly...")
    for i, path in enumerate(files):
        try:
            os.remove(path)
        except Exception:
            pass
        if i % 10 == 0:
            print(f"  deleted {i+1}/{count}")
        time.sleep(delay)

    _post_label(1, session)
    print(f"[sim] ✅ Mass delete done. Label=1 posted.")


def simulate_rename_burst(count: int = 60, delay: float = 0.04):
    """Creates normal files then renames all to ransomware extensions"""
    session = f"ransom_rename_{int(time.time())}"
    exts    = [".wcry", ".wncry", ".locked", ".encrypted", ".crypt"]
    print(f"\n[sim] ══ RENAME BURST SIMULATION ══")
    print(f"[sim] count={count}  session={session}")
    os.makedirs(SANDBOX, exist_ok=True)

    files = []
    for i in range(count):
        path = os.path.join(SANDBOX, _rname(random.choice([".jpg",".pdf",".xlsx",".doc"])))
        with open(path, "wb") as f:
            f.write(os.urandom(2048))
        files.append(path)

    time.sleep(1)

    print(f"[sim] Renaming {count} files to ransomware extensions...")
    for i, path in enumerate(files):
        new = path + random.choice(exts)
        try:
            os.rename(path, new)
        except Exception:
            pass
        if i % 10 == 0:
            print(f"  renamed {i+1}/{count}")
        time.sleep(delay)

    _post_label(1, session)
    print(f"[sim] ✅ Rename burst done. Label=1 posted.")


def simulate_mass_modify(count: int = 60, delay: float = 0.03):
    """Rapidly modifies files (overwrites with encrypted-looking content)"""
    session = f"ransom_modify_{int(time.time())}"
    print(f"\n[sim] ══ MASS MODIFY SIMULATION ══")
    print(f"[sim] count={count}  session={session}")
    os.makedirs(SANDBOX, exist_ok=True)

    files = []
    for i in range(count):
        path = os.path.join(SANDBOX, _rname(".txt"))
        with open(path, "w") as f:
            f.write("original content " * 100)
        files.append(path)

    time.sleep(1)

    print(f"[sim] Overwriting {count} files with random (encrypted-like) bytes...")
    for i, path in enumerate(files):
        try:
            with open(path, "wb") as f:
                f.write(os.urandom(4096))
        except Exception:
            pass
        if i % 10 == 0:
            print(f"  modified {i+1}/{count}")
        time.sleep(delay)

    _post_label(1, session)
    print(f"[sim] ✅ Mass modify done. Label=1 posted.")


def run_all():
    simulate_mass_encrypt(80)
    time.sleep(5)
    simulate_mass_delete(60)
    time.sleep(5)
    simulate_rename_burst(50)
    time.sleep(5)
    simulate_mass_modify(50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ransomware behavior simulator")
    parser.add_argument("--type",  choices=["mass_encrypt","mass_delete","rename_burst","mass_modify","all"],
                        default="mass_encrypt")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--delay", type=float, default=0.03)
    args = parser.parse_args()

    if   args.type == "mass_encrypt":  simulate_mass_encrypt(args.count, args.delay)
    elif args.type == "mass_delete":   simulate_mass_delete(args.count,  args.delay)
    elif args.type == "rename_burst":  simulate_rename_burst(args.count, args.delay)
    elif args.type == "mass_modify":   simulate_mass_modify(args.count,  args.delay)
    elif args.type == "all":           run_all()