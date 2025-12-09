import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import hash_file, restore_canary

CANARY_DIR = "canary/"


def load_canary_hashes():
    """Load baseline hashes of all .txt canary files."""
    hashes = {}
    for file in os.listdir(CANARY_DIR):
        path = os.path.join(CANARY_DIR, file)
        if file.endswith(".txt"):
            hashes[file] = hash_file(path)
    return hashes


class CanaryEventHandler(FileSystemEventHandler):
    """
    Handles filesystem events for canary files.
    Detects and responds to suspicious file activity.
    """

    def __init__(self, baseline_hashes):
        self.baseline = baseline_hashes

    def _is_canary(self, path):
        """Return True if the file is one of the baseline canary files."""
        filename = os.path.basename(path)
        return filename in self.baseline, filename

    # 1. Detect true modifications
    def on_modified(self, event):
        if event.is_directory:
            return
        
        is_canary, filename = self._is_canary(event.src_path)
        if is_canary:
            print(f"\n[ALERT] Canary file modified: {filename}")
            restore_canary(filename)
            print(f"[INFO] Restored {filename} from backup.\n")

    # 2. Detect VS Code/macOS atomic save behavior (temp file rename)
    def on_moved(self, event):
        if event.is_directory:
            return

        # event.dest_path is the actual new location
        is_canary, filename = self._is_canary(event.dest_path)
        if is_canary:
            print(f"\n[ALERT] Canary file replaced (atomic save detected): {filename}")
            restore_canary(filename)
            print(f"[INFO] Restored {filename} from backup.\n")

    # 3. Detect file recreation (common ransomware behavior)
    def on_created(self, event):
        if event.is_directory:
            return

        is_canary, filename = self._is_canary(event.src_path)
        if is_canary:
            print(f"\n[ALERT] Canary file recreated: {filename}")
            restore_canary(filename)
            print(f"[INFO] Restored {filename} from backup.\n")


def start_monitor():
    """
    Initialize file monitoring and begin watching the canary directory.
    """
    baseline_hashes = load_canary_hashes()

    event_handler = CanaryEventHandler(baseline_hashes)
    observer = Observer()
    observer.schedule(event_handler, CANARY_DIR, recursive=False)
    observer.start()

    print("[*] Anti-Ransomware Canary Monitor Running...")
    print(f"[*] Watching directory: {CANARY_DIR}\n")
    print("[*] Press CTRL+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    start_monitor()
