import os
import json
import hashlib
import subprocess
import sys
from typing import Dict

INDEX_FILE = os.path.expanduser("~/.password-store/.index.gpg")

# ---------------------------- GPG Utilities ----------------------------

def gpg_encrypt(data: str, recipients: str) -> bytes:
    """Encrypt data using GPG and given recipients (asymmetrically)."""
    process = subprocess.run(
        ["gpg", "--encrypt"] + sum([["-r", r] for r in recipients.split(",")], []),
        input=data.encode(),
        stdout=subprocess.PIPE,
        check=True
    )
    return process.stdout

def gpg_decrypt(ciphertext_path: str) -> str:
    """Decrypt data from a .gpg file using GPG."""
    process = subprocess.run(
        ["gpg", "--quiet", "--decrypt", ciphertext_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )
    return process.stdout.decode()

# ---------------------------- Index Management ----------------------------

def load_index() -> Dict[str, str]:
    """Load and decrypt the index file, returning the mapping."""
    if not os.path.exists(INDEX_FILE):
        return {}
    return json.loads(gpg_decrypt(INDEX_FILE))

def save_index(index: Dict[str, str], recipients: str):
    """Encrypt and save the index file with updated data."""
    data = json.dumps(index)
    encrypted = gpg_encrypt(data, recipients)
    with open(INDEX_FILE, "wb") as f:
        f.write(encrypted)

# ---------------------------- Utilities ----------------------------

def hash_name(name: str) -> str:
    """Generate a SHA-256 hash of the entry name."""
    return hashlib.sha256(name.encode()).hexdigest()

def get_gpg_recipients() -> str:
    """Get recipients from pass configuration."""
    result = subprocess.run(["pass", "init", "--clip"], capture_output=True, text=True)
    return result.stdout.strip()

# ---------------------------- Commands ----------------------------

def cmd_insert(name: str):
    """Insert a new entry."""
    index = load_index()
    if name in index:
        print(f"❗ Entry '{name}' already exists.")
        return
    hashed = hash_name(name)
    subprocess.run(["pass", "insert", hashed])
    index[name] = hashed
    save_index(index, get_gpg_recipients())
    print(f"✔ Inserted '{name}' (hash: {hashed})")

def cmd_show(name: str):
    """Show the contents of an entry."""
    index = load_index()
    hashed = index.get(name)
    if not hashed:
        print(f"❌ Entry '{name}' not found.")
        return
    subprocess.run(["pass", "show", hashed])

def cmd_search(pattern: str):
    """Search entries by readable names."""
    index = load_index()
    matches = [k for k in index if pattern.lower() in k.lower()]
    for m in matches:
        print(f"- {m}")

def cmd_remove(name: str):
    """Remove an entry."""
    index = load_index()
    hashed = index.pop(name, None)
    if not hashed:
        print(f"❌ Entry '{name}' not found.")
        return
    subprocess.run(["pass", "rm", "-rf", hashed])
    save_index(index, get_gpg_recipients())
    print(f"✔ Removed '{name}'")

def cmd_rename(old_name: str, new_name: str):
    """Rename an entry."""
    index = load_index()
    if old_name not in index:
        print(f"❌ Entry '{old_name}' not found.")
        return
    if new_name in index:
        print(f"❗ Entry '{new_name}' already exists.")
        return
    old_h = index.pop(old_name)
    new_h = hash_name(new_name)
    subprocess.run(["pass", "mv", old_h, new_h])
    index[new_name] = new_h
    save_index(index, get_gpg_recipients())
    print(f"✔ Renamed '{old_name}' → '{new_name}'")

# ---------------------------- CLI ----------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: pass-cover <command> [args]")
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    match cmd:
        case "insert" if len(args) == 1:
            cmd_insert(args[0])
        case "show" if len(args) == 1:
            cmd_show(args[0])
        case "search" if len(args) == 1:
            cmd_search(args[0])
        case "remove" if len(args) == 1:
            cmd_remove(args[0])
        case "rename" if len(args) == 2:
            cmd_rename(args[0], args[1])
        case _:
            print("Unknown or invalid command. Use: insert, show, search, remove, rename")

if __name__ == "__main__":
    main()

