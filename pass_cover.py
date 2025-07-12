#!/usr/bin/env python3

import os
import json
import hashlib
import subprocess
import sys
import readline
import signal
from pathlib import Path

INDEX_FILE = os.path.expanduser("~/.password-store/.index.gpg")
PASS_DIR = os.path.expanduser("~/.password-store")
GPG_ID_FILE = os.path.join(PASS_DIR, ".gpg-id")

# Handle Ctrl+Z gracefully
def signal_handler(sig, frame):
    print("\nUnexpected error occurred. Try again.")
    sys.exit(1)

signal.signal(signal.SIGTSTP, signal_handler)


def gpg_encrypt(data, recipients):
    process = subprocess.run(
        ["gpg", "--armor", "--encrypt"] + sum([["-r", r] for r in recipients.split(",")], []),
        input=data.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )
    return process.stdout


def gpg_decrypt(data):
    process = subprocess.run(
        ["gpg", "--decrypt"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )
    return process.stdout.decode()


def load_index():
    if not os.path.exists(INDEX_FILE):
        return {}
    with open(INDEX_FILE, 'rb') as f:
        encrypted = f.read()
    decrypted = gpg_decrypt(encrypted)
    return json.loads(decrypted)


def save_index(index, recipients):
    data = json.dumps(index, indent=2)
    encrypted = gpg_encrypt(data, recipients)
    with open(INDEX_FILE, 'wb') as f:
        f.write(encrypted)


def get_gpg_recipients():
    if not os.path.exists(GPG_ID_FILE):
        print(".gpg-id file not found. Please initialize pass with 'pass init <gpg-id>'")
        sys.exit(1)
    with open(GPG_ID_FILE) as f:
        return f.read().strip()


def hash_name(name):
    return hashlib.sha256(name.encode()).hexdigest()


def cmd_insert(name):
    index = load_index()
    hashed = hash_name(name)
    if hashed in index:
        print("Entry already exists.")
        return
    pw1 = input(f"Enter password for {name}: ")
    pw2 = input(f"Retype password for {name}: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return
    entry_path = os.path.join(PASS_DIR, f"{hashed}.gpg")
    subprocess.run(["gpg", "--armor", "--encrypt", "-r", get_gpg_recipients(), "-o", entry_path], input=pw1.encode())
    index[hashed] = name
    save_index(index, get_gpg_recipients())
    print("✔ Entry added.")


def cmd_show(name):
    index = load_index()
    hashed = hash_name(name)
    if hashed not in index:
        print("Entry not found.")
        return
    path = os.path.join(PASS_DIR, f"{hashed}.gpg")
    with open(path, 'rb') as f:
        decrypted = gpg_decrypt(f.read())
        print(decrypted)


def cmd_list():
    index = load_index()
    print("\nStored entries:\n")
    for i, (h, name) in enumerate(index.items(), 1):
        print(f"{i:02}. {name:<25} → {h[:8]}...")


def cmd_search(query):
    index = load_index()
    results = [(h, name) for h, name in index.items() if query.lower() in name.lower()]
    if results:
        print("Found entries:")
        for _, name in results:
            print(f"- {name}")
    else:
        print("No matching entries found.")


def cmd_remove(name):
    index = load_index()
    hashed = hash_name(name)
    if hashed not in index:
        print("Entry not found.")
        return
    try:
        os.remove(os.path.join(PASS_DIR, f"{hashed}.gpg"))
    except FileNotFoundError:
        pass
    del index[hashed]
    save_index(index, get_gpg_recipients())
    print("✔ Entry removed.")


def cmd_rename(old_name, new_name):
    index = load_index()
    old_hashed = hash_name(old_name)
    new_hashed = hash_name(new_name)
    if old_hashed not in index:
        print("Old entry not found.")
        return
    if new_hashed in index:
        print("New entry already exists.")
        return
    os.rename(os.path.join(PASS_DIR, f"{old_hashed}.gpg"), os.path.join(PASS_DIR, f"{new_hashed}.gpg"))
    index[new_hashed] = new_name
    del index[old_hashed]
    save_index(index, get_gpg_recipients())
    print("✔ Entry renamed.")


def main():
    try:
        if len(sys.argv) < 2:
            print("Usage: ./pass_cover.py [insert|show|list|search|remove|rename] <args>")
            return

        command = sys.argv[1]
        args = sys.argv[2:]

        if command == "insert" and len(args) == 1:
            cmd_insert(args[0])
        elif command == "show" and len(args) == 1:
            cmd_show(args[0])
        elif command == "list":
            cmd_list()
        elif command == "search" and len(args) == 1:
            cmd_search(args[0])
        elif command == "remove" and len(args) == 1:
            cmd_remove(args[0])
        elif command == "rename" and len(args) == 2:
            cmd_rename(args[0], args[1])
        else:
            print("Invalid command or arguments.")
    except Exception:
        print("\nUnexpected error occurred. Try again.")


if __name__ == "__main__":
    main()
