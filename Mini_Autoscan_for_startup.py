import os
import sys
import time
import shutil
import json
import threading
import tkinter as tk
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# SETTINGS
STARTUP_FOLDER = os.path.expanduser(
    r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
)

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".py"}
WHITELIST             = {"StartupMonitor.exe"}
SCAN_INTERVAL         = 30  # seconds between startup folder scans

BASE_DIR = os.path.dirname(
    sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
)
LOG_FILE       = os.path.join(BASE_DIR, "monitor_log.txt")
KEPT_FILES_LOG = os.path.join(BASE_DIR, "kept_files.json")

USER_HOME = os.path.expanduser("~")
WATCH_DIRS = [
    os.path.join(USER_HOME, "Desktop"),
    os.path.join(USER_HOME, "Documents"),
    os.path.join(USER_HOME, "Downloads"),
    STARTUP_FOLDER,
]

IGNORE_EXTENSIONS = {".tmp", ".etl", ".cache"}

IGNORE_PATH_FRAGMENTS = (
    r"\microsoft\edge\user data",
    r"\google\chrome\user data",
    r"\packages\\",
    r"\code\user\workspacestorage\\",
)

_file_event_times     = {}
_skipped_this_session = set()
FILE_EVENT_COOLDOWN   = 3

# LOGGING
def log(msg):
    entry = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(entry)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass

# HELPERS
def norm(path):
    return os.path.normcase(os.path.normpath(path))


def should_ignore(path):
    p = norm(path)
    if os.path.splitext(p)[1] in IGNORE_EXTENSIONS:
        return True
    return any(frag in p for frag in IGNORE_PATH_FRAGMENTS)


def cooldown_ok(path):
    now = time.time()
    if now - _file_event_times.get(path, 0) < FILE_EVENT_COOLDOWN:
        return False
    _file_event_times[path] = now
    return True

# KEPT FILES
def load_kept():
    try:
        with open(KEPT_FILES_LOG, "r", encoding="utf-8") as f:
            data = json.load(f)
            return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_kept(path):
    kept = load_kept()
    kept.add(path)
    with open(KEPT_FILES_LOG, "w", encoding="utf-8") as f:
        json.dump(sorted(kept), f, indent=2)
    log(f"Marked as kept: {path}")

# AUTO-COPY TO STARTUP
def add_to_startup():
    dest = os.path.join(STARTUP_FOLDER, "StartupMonitor.exe")
    if os.path.exists(dest):
        return
    src = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    try:
        shutil.copy2(src, dest)
        log(f"Copied self to startup: {dest}")
    except Exception as e:
        log(f"Could not copy to startup: {e}")

# DIALOG
def ask_user(exe_path):
    root = tk.Tk()
    root.withdraw()

    dlg = tk.Toplevel(root)
    dlg.title("Startup Security Alert")
    dlg.attributes("-topmost", True)
    dlg.resizable(False, False)
    dlg.grab_set()

    sw, sh = dlg.winfo_screenwidth(), dlg.winfo_screenheight()
    dlg.geometry(f"420x200+{(sw - 420) // 2}+{(sh - 200) // 2}")

    tk.Label(dlg,
             text="Suspicious file in Startup folder:",
             font=("Segoe UI", 9, "bold"),
             pady=6).pack()
    tk.Label(dlg,
             text=os.path.basename(exe_path),
             font=("Segoe UI", 9),
             fg="red").pack()
    tk.Label(dlg,
             text=exe_path,
             font=("Segoe UI", 8),
             fg="gray",
             wraplength=390).pack(pady=(0, 10))

    tk.Label(dlg,
             text="What do you want to do?",
             font=("Segoe UI", 9)).pack(pady=(10, 0))

    choice = tk.StringVar(value="skip")
    bf = tk.Frame(dlg)
    bf.pack(pady=8)

    tk.Button(bf, text="Delete",      width=10,
              command=lambda: [choice.set("delete"), dlg.destroy()]).grid(row=0, column=0, padx=4)
    tk.Button(bf, text="Keep Always", width=12,
              command=lambda: [choice.set("keep"),   dlg.destroy()]).grid(row=0, column=1, padx=4)
    tk.Button(bf, text="Skip",        width=10,
              command=lambda: [choice.set("skip"),   dlg.destroy()]).grid(row=0, column=2, padx=4)

    root.wait_window(dlg)
    root.destroy()
    return choice.get()

# FILE WATCHER
class FileWatcher(FileSystemEventHandler):
    def _handle(self, path, label):
        if not cooldown_ok(path) or should_ignore(path):
            return
        ext = os.path.splitext(path)[1].lower() or "[none]"
        log(f"[{label}] ext={ext}  {path}")

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "FILE CREATED")

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path, "FILE MOVED")


def start_watchers():
    observer = Observer()
    handler  = FileWatcher()
    for folder in WATCH_DIRS:
        if os.path.exists(folder):
            observer.schedule(handler, folder, recursive=True)
            log(f"Watching: {folder}")
        else:
            log(f"Skipping (not found): {folder}")
    observer.start()
    return observer

# SCAN LOOP
def scan_loop():
    while True:
        kept = load_kept()
        try:
            entries = os.listdir(STARTUP_FOLDER)
        except Exception as e:
            log(f"Cannot read startup folder: {e}")
            entries = []

        suspects = [
            os.path.join(STARTUP_FOLDER, f)
            for f in entries
            if f not in WHITELIST
            and os.path.splitext(f)[1].lower() in SUSPICIOUS_EXTENSIONS
            and os.path.join(STARTUP_FOLDER, f) not in kept
            and os.path.join(STARTUP_FOLDER, f) not in _skipped_this_session
        ]

        if suspects:
            log(f"Found {len(suspects)} suspicious file(s)")
            for exe_path in suspects:
                action = ask_user(exe_path)
                if action == "delete":
                    try:
                        os.remove(exe_path)
                        log(f"Deleted: {exe_path}")
                    except Exception as e:
                        log(f"Delete failed: {e}")
                elif action == "keep":
                    save_kept(exe_path)
                elif action == "skip":
                    _skipped_this_session.add(exe_path)
                    log(f"Skipped: {exe_path}")
        else:
            log("Startup folder clean.")

        time.sleep(SCAN_INTERVAL)

# ENTRY POINT
if __name__ == "__main__":
    add_to_startup()
    log("Startup Monitor started")

    observer = start_watchers()
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Shutting down...")
    finally:
        observer.stop()
        observer.join()
