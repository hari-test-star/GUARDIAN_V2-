#!/usr/bin/env python3
"""
Guardian v2 - Final single-scan script (one scan per run, manual rescan option)
Requirements: pip install psutil dnspython
"""

import os
import sys#for fun
import time
import random
import hashlib
import dns.resolver
import psutil
import atexit
import signal
import uuid
import json
from datetime import datetime

# ---------------- CONFIG ----------------
SUSPICIOUS_EXTENSIONS = ('.exe', '.scr', '.bat', '.vbs')
MAX_SCOUTS = 100
EXCLUDE_DIR_NAMES = {"Windows", "Program Files", "Program Files (x86)", "ProgramData", "AppData", "$Recycle.Bin"}
BASE_DIRS = [os.path.expanduser("~"), "C:\\"]     # adjust if not Windows
MARKER_PREFIX = ".guardian_scout_"
TRIAL_STORE = os.path.join(os.path.expanduser("~"), ".guardian_trials.json")
FREE_TRIALS = 3
ACTIVE_APPS_SAMPLE = 12  # how many running apps to show

# ---------------- DISCLAIMER ----------------
DISCLAIMER_TEXT = """
========================================================
                  ⚠  DISCLAIMER  ⚠
========================================================
Guardian is a code by Guardian v2 service, not to be
copied or sold without permission.

Guardian may slow down your PC while scanning — no worries,
performance will recover after scanning.

You only get three free trials; after that, sign in to get
infinite scans.

You should manually choose which file to delete as Guardian
cannot differentiate between good and bad files.

Guardian may get flagged for deploying its scouts on your PC —
no worries, it will auto-delete once you close this program.
========================================================
"""
print(DISCLAIMER_TEXT)
input("Press ENTER to continue...")

# ---------------- Trial store helpers ----------------
def load_trial_data():
    try:
        if os.path.exists(TRIAL_STORE):
            with open(TRIAL_STORE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    d = {"trials": 0, "signed_in": False}
    try:
        with open(TRIAL_STORE, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass
    return d

def save_trial_data(d):
    try:
        with open(TRIAL_STORE, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:
        pass

# ---------------- Utils ----------------
def email_domain_has_mx(email: str) -> bool:
    try:
        if "@" not in email or "." not in email.split("@")[-1]:
            return False
        domain = email.split('@', 1)[1]
        dns.resolver.resolve(domain, 'MX')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except Exception:
        return False

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "<unreadable>"

# ---------------- Guardian core ----------------
class Guardian:
    def __init__(self, base_dirs):
        self.base_dirs = base_dirs
        self.folder_cache = self._cache_folders()         # cached accessible folders
        self.scouts = {}                                 # folder -> scout_count
        self.reinforcement = {}                          # folder -> reinforcement level
        self.scan_count = 0
        self.created_markers_by_folder = {}              # folder -> [marker_paths]

    def _cache_folders(self):
        folders = []
        for base in self.base_dirs:
            if not os.path.exists(base):
                continue
            for root, dirs, files in os.walk(base, topdown=True):
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIR_NAMES]
                if os.access(root, os.R_OK):
                    folders.append(root)
        return sorted(set(folders))

    def show_folder_count(self):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Accessible folders found: {len(self.folder_cache)}")

    def list_sample_folders(self, limit=6):
        print("Sample folders (first few):")
        for f in self.folder_cache[:min(limit, len(self.folder_cache))]:
            print(" -", f)

    def _create_marker(self, folder: str) -> str | None:
        fname = MARKER_PREFIX + uuid.uuid4().hex[:8]
        path = os.path.join(folder, fname)
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(f"Guardian scout marker created at {datetime.now().isoformat()}\n")
            # mark hidden on Windows if possible
            if os.name == 'nt':
                try:
                    import ctypes
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)
                except Exception:
                    pass
            self.created_markers_by_folder.setdefault(folder, []).append(path)
            return path
        except Exception:
            return None

    def _remove_markers_for_folder(self, folder: str):
        paths = self.created_markers_by_folder.get(folder, [])
        for p in paths:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        self.created_markers_by_folder.pop(folder, None)

    def deploy_scouts_auto(self, num_scouts: int):
        if num_scouts > MAX_SCOUTS:
            num_scouts = MAX_SCOUTS
        num = min(num_scouts, len(self.folder_cache))
        chosen = random.sample(self.folder_cache, num) if num > 0 else []
        self.scouts.clear()
        for f in chosen:
            self.reinforcement.setdefault(f, 1)
            self._create_marker(f)
            self.scouts[f] = 1
        print(f"[INFO] Deployed {len(chosen)} scouts (auto).")

    def deploy_scouts_manual(self, indices):
        chosen = []
        for i in indices:
            if 0 <= i < len(self.folder_cache):
                chosen.append(self.folder_cache[i])
        chosen = list(dict.fromkeys(chosen))[:MAX_SCOUTS]
        self.scouts.clear()
        for f in chosen:
            self.reinforcement.setdefault(f, 1)
            self._create_marker(f)
            self.scouts[f] = 1
        print(f"[INFO] Deployed {len(chosen)} scouts (manual).")

    def scan_once(self):
        """Scan only scout folders (top-level files). Return suspicious dict (name->path)."""
        self.scan_count += 1
        suspicious = {}
        scanned_folders = list(self.scouts.keys())

        # only show running apps once per scan (concise)
        self.show_active_apps_sample()

        for folder in scanned_folders:
            try:
                names = os.listdir(folder)
            except Exception:
                # folder inaccessible now -> remove scout + markers
                print(f"[WARN] Folder became inaccessible; removing scouts for: {os.path.basename(folder)}")
                self.scouts.pop(folder, None)
                self._remove_markers_for_folder(folder)
                continue

            for name in names:
                full = os.path.join(folder, name)
                if os.path.isfile(full) and name.lower().endswith(SUSPICIOUS_EXTENSIONS):
                    suspicious.setdefault(name, full)

        # adjust scouts based on findings
        self._adjust_scouts_after_scan(suspicious)
        return suspicious

    def _adjust_scouts_after_scan(self, suspicious_dict):
        infected = {os.path.dirname(p) for p in suspicious_dict.values()}

        # Remove scouts from clean folders ONLY if there is at least one infected folder
        if infected:
            for folder in list(self.scouts.keys()):
                if folder not in infected:
                    self.scouts.pop(folder, None)
                    self._remove_markers_for_folder(folder)
                    print(f"[INFO] Removed scouts from clean folder: {os.path.basename(folder)}")

        # Reinforce infected folders (increase level each recurrence)
        for folder in infected:
            prev = self.reinforcement.get(folder, 0)
            new_level = prev + 1
            self.reinforcement[folder] = new_level
            self.scouts[folder] = new_level
            # create extra markers matching reinforcement (best-effort)
            created = len(self.created_markers_by_folder.get(folder, []))
            required = max(1, new_level)
            for _ in range(required - created):
                self._create_marker(folder)
            print(f"[ALERT] Reinforced folder {os.path.basename(folder)} -> level {new_level}")

    def show_active_apps_sample(self):
        procs = []
        try:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    procs.append((p.info.get('name') or "<unnamed>", p.info.get('pid')))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            procs = []

        print("\n[Active Applications (sample)]:")
        for name, pid in procs[:ACTIVE_APPS_SAMPLE]:
            print(f" - {name} (PID {pid})")
        if len(procs) > ACTIVE_APPS_SAMPLE:
            print(f" ... and {len(procs)-ACTIVE_APPS_SAMPLE} more running processes")

    def search_files(self, query):
        q = query.lower()
        results = []
        for folder in self.folder_cache:
            try:
                for name in os.listdir(folder):
                    if q in name.lower():
                        full = os.path.join(folder, name)
                        if os.path.isfile(full):
                            try:
                                size = os.path.getsize(full)
                            except Exception:
                                size = -1
                            results.append((name, folder, full, size))
            except Exception:
                continue
        return results

    def remove_file_safe(self, fullpath: str):
        try:
            os.remove(fullpath)
            return True, None
        except Exception as e:
            return False, str(e)

    def cleanup_all_markers(self):
        count = 0
        for folder, paths in list(self.created_markers_by_folder.items()):
            for p in paths:
                try:
                    if os.path.exists(p):
                        os.remove(p)
                        count += 1
                except Exception:
                    pass
        self.created_markers_by_folder.clear()
        return count

# ---------------- Program-level cleanup ----------------
guardian_instance = None

def cleanup_and_exit_now(sig=None, frame=None):
    global guardian_instance
    try:
        if guardian_instance:
            removed = guardian_instance.cleanup_all_markers()
            print(f"\n[Guardian] Cleanup: removed {removed} scout marker files.")
    except Exception:
        pass
    try:
        sys.stdout.flush()
    except Exception:
        pass
    # immediate exit
    try:
        os._exit(0)
    except Exception:
        sys.exit(0)

# register cleanup handlers
atexit.register(lambda: cleanup_and_exit_now())
signal.signal(signal.SIGINT, cleanup_and_exit_now)
try:
    signal.signal(signal.SIGTERM, cleanup_and_exit_now)
except Exception:
    pass

# ---------------- Trial / sign-in flow ----------------
def prompt_for_email_signin_flow(trial_data):
    if trial_data.get("signed_in"):
        print("[INFO] Signed in previously. Continuing without prompt.")
        return True
    if trial_data.get("trials", 0) < FREE_TRIALS:
        trial_data["trials"] = trial_data.get("trials", 0) + 1
        save_trial_data(trial_data)
        remaining = FREE_TRIALS - trial_data["trials"]
        print(f"[INFO] Free trial recorded. Trials left without sign-in: {remaining}")
        return True
    # trials exhausted -> require sign-in
    print("\n[TRIALS EXHAUSTED] Please sign in to continue.")
    while True:
        email = input("Enter email to sign in (leave blank to exit): ").strip()
        if not email:
            print("[INFO] Sign-in cancelled. Exiting.")
            return False
        if email_domain_has_mx(email):
            trial_data["signed_in"] = True
            save_trial_data(trial_data)
            print("[INFO] Email verified. Signed in.")
            return True
        else:
            print("[ERROR] MX check failed. Try again or leave blank to exit.")

# ---------------- Main CLI flow ----------------
def main():
    global guardian_instance
    print("\n=== Guardian v2 (single-scan) ===")
    trial_data = load_trial_data()
    ok = prompt_for_email_signin_flow(trial_data)
    if not ok:
        return

    guardian = Guardian(BASE_DIRS)
    guardian_instance = guardian

    guardian.show_folder_count()
    if not guardian.folder_cache:
        print("[ERROR] No accessible folders available. Exiting.")
        return

    guardian.list_sample_folders(limit=6)
    max_deploy = min(len(guardian.folder_cache), MAX_SCOUTS)
    print(f"\nYou may deploy up to {max_deploy} scouts (hard cap {MAX_SCOUTS}).")
    mode = input("Deploy mode - (a)uto random or (m)anual select? [a/m]: ").strip().lower() or 'a'

    if mode == 'm':
        top_n = min(40, len(guardian.folder_cache))
        for i, f in enumerate(guardian.folder_cache[:top_n]):
            print(f"{i:3d}: {f}")
        raw = input(f"Enter indices separated by spaces (0-based), up to {max_deploy}: ").strip()
        try:
            indices = [int(x) for x in raw.split() if x.strip().isdigit()]
            indices = indices[:max_deploy]
            guardian.deploy_scouts_manual(indices)
        except Exception:
            print("[WARN] Invalid selection. Falling back to auto-deploy.")
            num = int(input(f"How many scouts to deploy? (1-{max_deploy}): ") or "0")
            num = max(1, min(num, max_deploy))
            guardian.deploy_scouts_auto(num)
    else:
        num = int(input(f"How many scouts to deploy? (1-{max_deploy}): ") or "0")
        num = max(1, min(num, max_deploy))
        guardian.deploy_scouts_auto(num)
#pen test
    # ---- single scan execution ----
    print("\nScanning... (this is a one-time scan; you'll get menu afterwards)")
    start_time = time.time()
    suspicious = guardian.scan_once()
    elapsed = round(time.time() - start_time, 2)
    print(f"\n[Scan Complete] Took {elapsed} seconds.")

    if suspicious:
        print("\n[!] Threats found:")
        for i, (name, path) in enumerate(suspicious.items(), start=1):
            print(f" {i}. {name} -> {path}")
        # interactive choices for found items
        while True:
            choice = input("\nOptions: [d <n>] delete by number, [s] search another file, [exit] leave: ").strip()
            if not choice:
                continue
            if choice.lower().startswith('d '):
                try:
                    n = int(choice.split()[1])
                    if 1 <= n <= len(suspicious):
                        filename = list(suspicious.keys())[n-1]
                        full = suspicious[filename]
                        confirm = input(f"Confirm delete {filename}? [y/N]: ").strip().lower()
                        if confirm == 'y':
                            ok, err = guardian.remove_file_safe(full)
                            if ok:
                                print(f"[DELETED] {filename}")
                                suspicious.pop(filename, None)
                            else:
                                print(f"[ERROR] Could not delete {filename}: {err}")
                        else:
                            print("[INFO] Delete canceled.")
                    else:
                        print("[WARN] Invalid index.")
                except Exception:
                    print("[WARN] Invalid command.")
                continue
            elif choice.lower().startswith('s'):
                q = input("Enter filename or partial name to search for: ").strip()
                if not q:
                    print("[WARN] Empty query.")
                    continue
                results = guardian.search_files(q)
                if not results:
                    print("[INFO] No results found.")
                else:
                    for i, (name, folder, full, size) in enumerate(results[:20], start=1):
                        print(f"{i}. {name} | {folder} | {size if size>=0 else 'unknown'} bytes")
                    pick = input("Enter result number to view details or 'back': ").strip()
                    if pick.isdigit():
                        p = int(pick)
                        if 1 <= p <= min(20, len(results)):
                            name, folder, full, size = results[p-1]
                            h = sha256_of_file(full)
                            print(f"\nDETAILS:\n - Name: {name}\n - Path: {full}\n - Size: {size} bytes\n - SHA256: {h}")
                            action = input("Delete this file? [y/N]: ").strip().lower()
                            if action == 'y':
                                ok, err = guardian.remove_file_safe(full)
                                if ok:
                                    print("[DELETED] File removed.")
                                else:
                                    print(f"[ERROR] Could not delete: {err}")
                            else:
                                print("No action taken.")
                continue
            elif choice.lower() == 'exit':
                break
            else:
                print("[WARN] Unknown option.")
                continue
    else:
        # no threats found -> show concise message and ask menu
        print("\n[OK] No threats found during the scan.")
        while True:
            print("\nChoose next action:")
            print(" 1) Leave (exit program)")
            print(" 2) Attack — enter a file name to search & remove")
            print(" 3) Rescan now")
            pick = input("Enter 1, 2 or 3: ").strip()
            if pick == '1':
                print("[INFO] Exiting per user request.")
                break
            elif pick == '2':
                q = input("Enter exact filename or partial name to search for: ").strip()
                if not q:
                    print("[WARN] Empty query.")
                    continue
                results = guardian.search_files(q)
                if not results:
                    print("[INFO] No file matched your query.")
                    continue
                print(f"[FOUND {len(results)} matches] (showing up to 20):")
                for i, (name, folder, full, size) in enumerate(results[:20], start=1):
                    print(f"{i}. {name} | {folder} | {size if size>=0 else 'unknown'} bytes")
                pick2 = input("Enter result number to view details or 'back': ").strip()
                if pick2.isdigit():
                    idx = int(pick2)
                    if 1 <= idx <= min(20, len(results)):
                        name, folder, full, size = results[idx-1]
                        h = sha256_of_file(full)
                        print(f"\nDETAILS:\n - Name: {name}\n - Path: {full}\n - Size: {size} bytes\n - SHA256: {h}")
                        confirm = input("Delete this file? [y/N]: ").strip().lower()
                        if confirm == 'y':
                            ok, err = guardian.remove_file_safe(full)
                            if ok:
                                print("[DELETED] File removed.")
                            else:
                                print(f"[ERROR] Could not delete: {err}")
                        else:
                            print("[INFO] No action taken.")
                    else:
                        print("[WARN] Invalid index.")
                else:
                    continue
            elif pick == '3':
                # manual rescan: perform exactly one more scan and return to same menu afterwards
                print("\n[INFO] Performing manual rescan...")
                start = time.time()
                suspicious = guardian.scan_once()
                elapsed = round(time.time() - start, 2)
                print(f"[Scan Complete] Took {elapsed} seconds.")
                if suspicious:
                    # jump into same 'threats found' handling by restarting main flow
                    print("\nThreats found on rescan — re-running main flow to handle them.")
                    # simple approach: call main again will run new flow (scoped)
                    # but to keep single-file behavior, we'll handle found items inline:
                    for i, (name, path) in enumerate(suspicious.items(), start=1):
                        print(f"{i}. {name} -> {path}")
                    # then allow same deletion options:
                    while True:
                        choice = input("\nOptions: [d <n>] delete by number, [exit] continue: ").strip()
                        if not choice:
                            continue
                        if choice.lower().startswith('d '):
                            try:
                                n = int(choice.split()[1])
                                if 1 <= n <= len(suspicious):
                                    filename = list(suspicious.keys())[n-1]
                                    full = suspicious[filename]
                                    confirm = input(f"Confirm delete {filename}? [y/N]: ").strip().lower()
                                    if confirm == 'y':
                                        ok, err = guardian.remove_file_safe(full)
                                        if ok:
                                            print(f"[DELETED] {filename}")
                                            suspicious.pop(filename, None)
                                        else:
                                            print(f"[ERROR] Could not delete {filename}: {err}")
                                    else:
                                        print("[INFO] Delete canceled.")
                                else:
                                    print("[WARN] Invalid index.")
                            except Exception:
                                print("[WARN] Invalid command.")
                            continue
                        elif choice.lower() == 'exit':
                            break
                        else:
                            print("[WARN] Unknown option.")
                    # after handling, return to main 'no threat' menu
                    continue
                else:
                    print("[OK] No threats found on rescan.")
                    continue
            else:
                print("[WARN] Enter 1, 2 or 3.")
                continue

    # final cleanup and exit
    cleanup_and_exit_now()

if __name__ == "__main__":
    main()
#this code run successfully
