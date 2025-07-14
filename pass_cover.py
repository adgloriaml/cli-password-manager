#!/usr/bin/env python3

import os
import json
import hashlib
import subprocess
import sys
import readline
import signal
from pathlib import Path
import getpass
import random
import string

INDEX_FILE = os.path.expanduser("~/.password-store/.index.gpg")
PASS_DIR = os.path.expanduser("~/.password-store")
GPG_ID_FILE = os.path.join(PASS_DIR, ".gpg-id")


def signal_handler(sig, frame):
    print("\nUnexpected error occurred. Try again.")
    sys.exit(1)

signal.signal(signal.SIGTSTP, signal_handler)


def gpg_encrypt(data, recipients):
    process = subprocess.run(
        ["gpg", "--armor", "--encrypt"] + sum([["-r", r] for r in recipients.split(",")], []),
        input = data.encode(),
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        check = True
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


def name_to_hash(name):
    return hashlib.sha256(name.encode()).hexdigest()


def terminal_insert(name):
    index = load_index()
    hashed = name_to_hash(name)
    if hashed in index:
        print("Entry already exists.")
        return
    passwd1 = getpass.getpass(f"Enter password for {name}: ")
    passwd2 = getpass.getpass(f"Retype password for {name}: ")
    if passwd1 != passwd2:
        print("Passwords do not match.")
        return
    entry_path = os.path.join(PASS_DIR, f"{hashed}.gpg")
    subprocess.run(["gpg", "--armor", "--encrypt", "-r", get_gpg_recipients(), "-o", entry_path], input=passwd1.encode())
    index[hashed] = name
    save_index(index, get_gpg_recipients())
    print("Entry added.")


def terminal_show(name):
    index = load_index()
    hashed = name_to_hash(name)
    if hashed not in index:
        print("Entry not found.")
        return
    path = os.path.join(PASS_DIR, f"{hashed}.gpg")
    with open(path, 'rb') as f:
        decrypted = gpg_decrypt(f.read())
        print(decrypted)


def terminal_search(query):
    index = load_index()
    results = [(h, name) for h, name in index.items() if query.lower() in name.lower()]
    if results:
        print("Found entries:")
        for _, name in results:
            print(f"- {name}")
    else:
        print("No matching entries found.")


def terminal_remove(name):
    index = load_index()
    hashed = name_to_hash(name)
    if hashed not in index:
        print("Entry not found.")
        return
    try:
        os.remove(os.path.join(PASS_DIR, f"{hashed}.gpg"))
    except FileNotFoundError:
        pass
    del index[hashed]
    save_index(index, get_gpg_recipients())
    print("Entry removed.")


def terminal_rename(old_name, new_name):
    index = load_index()
    old_hashed = name_to_hash(old_name)
    new_hashed = name_to_hash(new_name)
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
    print("Entry renamed.")


def terminal_generate(name, length):
    db = load_index()
    hash_key = name_to_hash(name)
    if hash_key in db:
        print("Entry already exists.")
        return
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=length))
    enc_path = os.path.join(PASS_DIR, f"{hash_key}.gpg")
    subprocess.run(["gpg", "--armor", "--encrypt", "-r", get_gpg_recipients(), "-o", enc_path], input=password.encode())
    db[hash_key] = name
    save_index(db, get_gpg_recipients())
    print("Generated and saved password:")
    print(password)

def terminal_list():
    index = load_index()
    print("\nStored entries:\n")
    for i, (h, name) in enumerate(index.items(), 1):
        print(f"{i:02}. {name:<25} → {h[:8]}...")


def main():
    try:
        if len(sys.argv) < 2:
            print("Attention!")
            print("Usage: ./pass_cover.py [insert|show|list|search|remove|rename|generate] <args>")
            return

        command = sys.argv[1]
        args = sys.argv[2:]

        if command == "insert" and len(args) == 1:
            terminal_insert(args[0])
        elif command == "show" and len(args) == 1:
            terminal_show(args[0])
        elif command == "list":
            terminal_list()
        elif command == "search" and len(args) == 1:
            terminal_search(args[0])
        elif command == "remove" and len(args) == 1:
            terminal_remove(args[0])
        elif command == "rename" and len(args) == 2:
            terminal_rename(args[0], args[1])
        elif command == "generate" and len(args) == 2:
            try:
                length = int(args[1])
                terminal_generate(args[0], length)
            except ValueError:
                print("Password length must be a number.")
        else:
            print("Invalid command or arguments.")
    except Exception:
        print("\nUnexpected error occurred. Try again.")


if __name__ == "__main__":
    main()
