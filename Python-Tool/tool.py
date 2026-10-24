#!/usr/bin/env python3
"""
File Integrity Checker - SHA-256
Modes:
  scan  : print the SHA-256 hash of every file in a directory
  save  : store those hashes in a baseline file (JSON)
  check : compare the directory with a saved baseline and report
          modified, new and deleted files
"""

import os
import sys
import json
import hashlib
from datetime import datetime


def usage():
    """Display help/usage information."""
    print("""
File Integrity Checker - SHA-256

Usage:
  python3 integrity_checker.py scan  <directory>
  python3 integrity_checker.py save  <directory> <baseline.json>
  python3 integrity_checker.py check <directory> <baseline.json>
  python3 integrity_checker.py -h | --help

Modes:
  scan    Print the SHA-256 hash of every file (subdirectories included)
  save    Save the current hashes in a baseline file (JSON)
  check   Compare the directory with a baseline and report changes

Examples:
  python3 integrity_checker.py scan ./project
  python3 integrity_checker.py save ./project baseline.json
  python3 integrity_checker.py check ./project baseline.json

Exit codes (check mode): 0 = no change, 1 = changes detected, 2 = error
""")


def calculate_sha256(file_path):
    """Return the SHA-256 hash of a file, read in 64 KB chunks."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()


def scan_directory(directory_path):
    """
    Walk through a directory and return (hashes, errors).
      hashes : dict {relative_path: sha256}
      errors : list of error messages for unreadable files
    Relative paths are used so the baseline still works if the
    folder is moved or renamed.
    """
    hashes = {}
    errors = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, directory_path)
            try:
                hashes[rel_path] = calculate_sha256(file_path)
            except PermissionError:
                errors.append(f"Permission denied: {file_path}")
            except OSError as e:
                errors.append(f"Cannot read {file_path}: {e}")

    return hashes, errors


def save_baseline(hashes, baseline_path):
    """Write the hashes and a timestamp to a JSON baseline file."""
    data = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "files": hashes,
    }
    try:
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        print(f"[ERROR] Cannot write baseline '{baseline_path}': {e}")
        return False
    return True


def load_baseline(baseline_path):
    """Read a baseline file. Return the dict of hashes, or None on error."""
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["files"]
    except FileNotFoundError:
        print(f"[ERROR] Baseline file '{baseline_path}' not found.")
    except (json.JSONDecodeError, KeyError):
        print(f"[ERROR] '{baseline_path}' is not a valid baseline file.")
    except OSError as e:
        print(f"[ERROR] Cannot read '{baseline_path}': {e}")
    return None


def compare(baseline, current):
    """
    Compare two {path: hash} dictionaries.
    Return three sorted lists: modified, new, deleted.
    """
    modified = sorted(p for p in current if p in baseline and current[p] != baseline[p])
    new = sorted(p for p in current if p not in baseline)
    deleted = sorted(p for p in baseline if p not in current)
    return modified, new, deleted


def cmd_scan(directory):
    """scan mode: print every file with its hash."""
    hashes, errors = scan_directory(directory)
    for path, h in sorted(hashes.items()):
        print(f"File: {path}\n  SHA-256: {h}")
    for err in errors:
        print(f"[ERROR] {err}")
    print(f"\nScan finished: {len(hashes)} file(s) hashed, {len(errors)} error(s).")
    return 0


def cmd_save(directory, baseline_path):
    """save mode: scan the directory and store the baseline."""
    hashes, errors = scan_directory(directory)
    for err in errors:
        print(f"[ERROR] {err}")
    if not save_baseline(hashes, baseline_path):
        return 2
    print(f"Baseline saved to '{baseline_path}' ({len(hashes)} file(s)).")
    return 0


def cmd_check(directory, baseline_path):
    """check mode: compare the directory with the baseline."""
    baseline = load_baseline(baseline_path)
    if baseline is None:
        return 2

    current, errors = scan_directory(directory)
    for err in errors:
        print(f"[ERROR] {err}")

    modified, new, deleted = compare(baseline, current)

    for p in modified:
        print(f"[MODIFIED] {p}")
    for p in new:
        print(f"[NEW]      {p}")
    for p in deleted:
        print(f"[DELETED]  {p}")

    if not (modified or new or deleted):
        print("OK: no change detected, integrity verified.")
        return 0

    print(f"\nChanges detected: {len(modified)} modified, "
          f"{len(new)} new, {len(deleted)} deleted.")
    return 1


def main():
    """Parse command-line arguments and run the requested mode."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        usage()
        return 0

    mode = args[0]

    if mode not in ("scan", "save", "check"):
        print(f"[ERROR] Unknown mode '{mode}'.")
        usage()
        return 2

    # scan needs 1 argument, save/check need 2
    needed = 1 if mode == "scan" else 2
    if len(args) - 1 != needed:
        print(f"[ERROR] Wrong number of arguments for '{mode}'.")
        usage()
        return 2

    directory = args[1]
    if not os.path.isdir(directory):
        print(f"[ERROR] '{directory}' does not exist or is not a directory.")
        return 2

    if mode == "scan":
        return cmd_scan(directory)
    if mode == "save":
        return cmd_save(directory, args[2])
    return cmd_check(directory, args[2])


if __name__ == "__main__":
    sys.exit(main())
