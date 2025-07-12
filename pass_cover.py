#!/usr/bin/env python3

import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import traceback

USE_GNUPG_LIB = False  # True to use python-gnupg

if USE_GNUPG_LIB:
    import gnupg
    gpg = gnupg.GPG()

INDEX_FILE = os.path.expanduser("~/.password-store/.index.gpg")
STORE_DIR = os.path.expanduser("~/.password-store")

def get_gpg_recipients() -> str:
    gpgid_file = os.path.join(STORE_DIR, ".gpg-id")
    if not os.path.exists(gpgid_file):
        raise RuntimeError("No GPG ID found in ~/.password-store/.gpg-id")
    with open(gpgid_file, "r") as f:
        return f.read().strip()

# Encrypt data
def gpg_encrypt(data: str, recipients: str) -> bytes:
    if USE_GNUPG_LIB:
        return gpg.encrypt(data, recipients.split(","), always_trust=True).data
    else:
        process = subprocess.run(
            ["gpg", "--encrypt"] + sum([["-r", r] for r in recipients.split(",")], []),
            input=data.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return process.stdout

# Decrypt data
def gpg_decrypt(data: bytes) -> str:
    if USE_GNUPG_LIB:
        return str(gpg.decrypt(data))
    else:
        process = subprocess.run(
            ["gpg", "--decrypt"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return process.stdout.decode()

# Load encrypted index
def load_index() -> dict:
    if not os.path.exists(INDEX_FILE):
        return {}
    with open(INDEX_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = gpg_decrypt(encrypted)
        return json.loads(decrypted)
    except Exception:
        return {}

# Save encrypted index
def save_index(index: dict, recipients: str):
    data = json.dumps(index, indent=2)
    encrypted = gpg_encrypt(data, recipients)
    with open(INDEX_FILE, "wb") as f:
        f.write(encrypted)

# Hash the readable path
def path_to_hash(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()

# Save password in ASCII-armored format
def store_password_ascii(hash_key: str, password: str, recipients: str):
    out_path = os.path.join(STORE_DIR, hash_key + ".gpg")
    process = subprocess.run(
        ["gpg", "--armor", "--encrypt", "-o", out_path] +
        sum([["-r", r] for r in recipients.split(",")], []),
        input=password.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )

# Command: insert
def cmd_insert(path: str):
    password = input(f"Enter password for {path_to_hash(path)}: ")
    confirm = input(f"Retype password for {path_to_hash(path)}: ")
    if password != confirm:
        print("Passwords do not match.")
        return
    index = load_index()
    hash_key = path_to_hash(path)
    index[hash_key] = path
    recipients = get_gpg_recipients()
    store_password_ascii(hash_key, password, recipients)
    save_index(index, recipients)
    print(f"Password for '{path}' saved.")

# Command: list
def cmd_list():
    index = load_index()
    if not index:
        print("No entries found.")
        return
    print("Stored entries:\n")
    for i, (hash_key, readable) in enumerate(sorted(index.items(), key=lambda x: x[1])):
        print(f"{i+1:02d}. {readable:<25} → {hash_key[:8]}...")

# Command: show
def cmd_show(path: str):
    hash_key = path_to_hash(path)
    file_path = os.path.join(STORE_DIR, hash_key + ".gpg")
    if not os.path.exists(file_path):
        print("Entry not found.")
        return
    with open(file_path, "rb") as f:
        decrypted = gpg_decrypt(f.read())
        print(f"{path}:\n{decrypted.strip()}")

# Handle command-line interface
def main():
    try:
        args = sys.argv[1:]
        if not args:
            print("Usage: insert <name>, show <name>, list")
            return
        cmd = args[0]
        if cmd == "insert" and len(args) == 2:
            cmd_insert(args[1])
        elif cmd == "show" and len(args) == 2:
            cmd_show(args[1])
        elif cmd == "list":
            cmd_list()
        else:
            print("Unknown command or wrong usage.")
    except KeyboardInterrupt:
        print("\nInterrupted. Try again.")
    except Exception:
        print("Unexpected error occurred. Try again.")
        traceback.print_exc()

if __name__ == "__main__":
    main()

