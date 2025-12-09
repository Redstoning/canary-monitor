import hashlib
import shutil
import os

CANARY_DIR = "canary/"
BACKUP_DIR = "canary/backup/"


def hash_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        sha.update(f.read())
    return sha.hexdigest()


def restore_canary(filename):
    src = os.path.join(BACKUP_DIR, filename.replace(".txt", ".bak"))
    dst = os.path.join(CANARY_DIR, filename)
    shutil.copy(src, dst)

